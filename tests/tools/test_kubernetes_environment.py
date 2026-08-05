"""Unit tests for the Kubernetes session-pod execution backend.

Ported from upstream PR #37591 and re-specified for this fork's config surface:
every setting is a ``terminal.kubernetes.*`` config.yaml key bridged as ONE
internal JSON env var, and the pod's ``runAsUser``/``fsGroup`` are OMITTED by
default so OpenShift's restricted-v2 SCC can assign them.

No cluster required: the kubernetes client is stubbed into ``sys.modules`` and
manifest builders run with ``api=None``.
"""

import json
import sys
import types as _types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools.environments.kubernetes import (
    DEFAULT_KUBERNETES_CONFIG,
    DirectProvisioner,
    KubernetesEnvironment,
    PodRef,
    Resources,
    SandboxProvisioner,
    WorkspaceProvisioner,
    build_pod_template,
    merge_kubernetes_config,
    sanitize_name,
    validate_kubernetes_config,
)


@pytest.fixture(autouse=True)
def _stub_kubernetes(monkeypatch):
    """Stub the kubernetes client so the backend imports without a cluster."""
    if "kubernetes" in sys.modules:
        return
    k = _types.ModuleType("kubernetes")
    k.client = _types.ModuleType("kubernetes.client")
    k.config = _types.ModuleType("kubernetes.config")
    k.stream = _types.ModuleType("kubernetes.stream")
    ws_mod = _types.ModuleType("kubernetes.stream.ws_client")
    exc_mod = _types.ModuleType("kubernetes.client.exceptions")

    class ApiException(Exception):
        def __init__(self, status=0, reason=""):
            self.status = status
            self.reason = reason
            super().__init__(f"{status}: {reason}")

    exc_mod.ApiException = ApiException
    k.client.exceptions = exc_mod
    k.client.CoreV1Api = MagicMock
    k.client.CustomObjectsApi = MagicMock
    k.config.load_incluster_config = lambda: None
    k.config.load_kube_config = lambda **kw: None
    k.stream.stream = MagicMock()
    ws_mod.STDIN_CHANNEL = 0
    ws_mod.V5_CHANNEL_PROTOCOL = "v5.channel.k8s.io"
    k.stream.ws_client = ws_mod
    monkeypatch.setitem(sys.modules, "kubernetes", k)
    monkeypatch.setitem(sys.modules, "kubernetes.client", k.client)
    monkeypatch.setitem(sys.modules, "kubernetes.client.exceptions", exc_mod)
    monkeypatch.setitem(sys.modules, "kubernetes.config", k.config)
    monkeypatch.setitem(sys.modules, "kubernetes.stream", k.stream)
    monkeypatch.setitem(sys.modules, "kubernetes.stream.ws_client", ws_mod)


def _kcfg(**overrides):
    return merge_kubernetes_config(overrides)


OWNER_REF = {
    "apiVersion": "v1",
    "kind": "Pod",
    "name": "hermes-agent-0",
    "uid": "11111111-1111-1111-1111-111111111111",
    "controller": False,
    "blockOwnerDeletion": False,
}


# ---------------------------------------------------------------------------
# Value types / helpers
# ---------------------------------------------------------------------------


def test_podref_holds_coordinates():
    ref = PodRef(namespace="hermes", pod_name="hermes-ws-abc", container="workspace")
    assert ref.namespace == "hermes"
    assert ref.pod_name == "hermes-ws-abc"
    assert ref.container == "workspace"


def test_provisioner_is_abstract():
    with pytest.raises(TypeError):
        WorkspaceProvisioner()  # ABC — cannot instantiate


def test_sanitize_name_makes_rfc1123_safe_names():
    """RL/benchmark task ids carry uppercase, ``_`` and ``:``; the API server
    rejects those in a pod name with a confusing 422."""
    assert sanitize_name("default") == "default"
    slug = sanitize_name("Task_ID:With/Junk")
    assert slug.replace("-", "").isalnum()
    assert slug.islower()
    # Distinct inputs that share a prefix must not collide after truncation.
    a = sanitize_name("x" * 200 + "aaa")
    b = sanitize_name("x" * 200 + "bbb")
    assert a != b
    assert len(a) <= 40


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


def test_partial_config_still_yields_every_default():
    """cli.py and gateway/run.py bridge the RAW config without deep-merging
    DEFAULT_CONFIG, so a user who sets one key produces a partial payload."""
    merged = merge_kubernetes_config({"namespace": "hermes-agents"})
    assert merged["namespace"] == "hermes-agents"
    assert merged["provisioner"] == "direct"
    assert merged["security_context"]["seccomp_profile"] == "RuntimeDefault"
    assert merged["volume"]["access_modes"] == ["ReadWriteOnce"]
    assert merged["sandbox"]["api_group"] == "agents.x-k8s.io"


def test_partial_nested_config_merges_rather_than_replaces():
    merged = merge_kubernetes_config(
        {"security_context": {"run_as_user": 1000}, "resources": {"limits": {"cpu": "2"}}}
    )
    assert merged["security_context"]["run_as_user"] == 1000
    assert merged["security_context"]["drop_capabilities"] == ["ALL"]
    assert merged["resources"]["limits"]["cpu"] == "2"
    assert merged["resources"]["requests"] == {"cpu": "", "memory": ""}


def test_merge_does_not_mutate_defaults():
    merged = merge_kubernetes_config({"labels": {"a": "b"}})
    merged["labels"]["c"] = "d"
    merged["sandbox"]["template_ref"] = "x"
    assert DEFAULT_KUBERNETES_CONFIG["labels"] == {}
    assert DEFAULT_KUBERNETES_CONFIG["sandbox"]["template_ref"] == ""


def test_validation_rejects_bad_provisioner_and_quantities():
    problems = validate_kubernetes_config(_kcfg(provisioner="operator"))
    assert any("provisioner" in p for p in problems)

    problems = validate_kubernetes_config(
        _kcfg(resources={"requests": {"memory": "2 gigabytes"}})
    )
    assert any("quantity" in p for p in problems)


def test_validation_rejects_run_as_root_with_run_as_non_root():
    problems = validate_kubernetes_config(
        _kcfg(security_context={"run_as_non_root": True, "run_as_user": 0})
    )
    assert any("run_as_user=0" in p for p in problems)


def test_validation_requires_template_ref_for_claims():
    problems = validate_kubernetes_config(_kcfg(sandbox={"use_claim": True}))
    assert any("template_ref" in p for p in problems)


def test_default_config_is_valid():
    assert validate_kubernetes_config(merge_kubernetes_config({})) == []


# ---------------------------------------------------------------------------
# Pod template
# ---------------------------------------------------------------------------


def _provisioner(**overrides):
    return DirectProvisioner(
        _kcfg(**overrides), "hermes", api=None, owner_reference=OWNER_REF
    )


def test_ephemeral_pod_uses_emptydir_and_carries_ownerref():
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    vols = pod["spec"]["volumes"]
    assert vols[0]["name"] == "workspace"
    assert vols[0]["emptyDir"] == {}
    mount = pod["spec"]["containers"][0]["volumeMounts"][0]
    assert mount["mountPath"] == "/workspace"
    assert pod["metadata"]["ownerReferences"][0]["uid"] == OWNER_REF["uid"]


def test_persistent_pod_references_pvc_by_task_id():
    p = _provisioner()
    pod = p.pod_manifest("mytask", persistent=True, image="img:1", resources=Resources())
    vol = pod["spec"]["volumes"][0]
    assert vol["persistentVolumeClaim"]["claimName"] == "hermes-ws-mytask"


def test_pvc_manifest_has_no_ownerref():
    """A persistent PVC must outlive the agent pod, so it gets no ownerRef."""
    pvc = _provisioner().pvc_manifest("mytask", resources=Resources(disk_mib=10240))
    assert pvc["metadata"]["name"] == "hermes-ws-mytask"
    assert "ownerReferences" not in pvc["metadata"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "10240Mi"
    assert "storageClassName" not in pvc["spec"]


def test_pvc_honours_configured_storage_class_and_size():
    p = DirectProvisioner(
        _kcfg(volume={"size": "20Gi", "storage_class_name": "truenas-nvme",
                      "access_modes": ["ReadWriteMany"]}),
        "hermes", api=None, owner_reference=OWNER_REF,
    )
    pvc = p.pvc_manifest("mytask", resources=Resources())
    assert pvc["spec"]["resources"]["requests"]["storage"] == "20Gi"
    assert pvc["spec"]["storageClassName"] == "truenas-nvme"
    assert pvc["spec"]["accessModes"] == ["ReadWriteMany"]


def test_pod_manifest_omits_ownerref_when_owner_unknown():
    """K8s rejects an ownerReference with an empty name/uid with a 422."""
    p = DirectProvisioner(_kcfg(), "hermes", api=None, owner_reference=None)
    pod = p.pod_manifest("abc", persistent=False, image="img:1", resources=Resources())
    assert "ownerReferences" not in pod["metadata"]


def test_ephemeral_pod_has_active_deadline_persistent_does_not():
    p = DirectProvisioner(
        _kcfg(active_deadline_seconds=999), "hermes", api=None, owner_reference=OWNER_REF
    )
    ephemeral = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    persistent = p.pod_manifest("abc", persistent=True, image="i:1", resources=Resources())
    assert ephemeral["spec"]["activeDeadlineSeconds"] == 999
    assert "activeDeadlineSeconds" not in persistent["spec"]


def test_pod_security_context_is_hardened():
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    spec = pod["spec"]
    assert spec["automountServiceAccountToken"] is False
    assert spec["serviceAccountName"] == "hermes-session-noperms"
    assert spec["hostNetwork"] is False
    assert spec["hostPID"] is False
    assert spec["hostIPC"] is False
    assert spec["enableServiceLinks"] is False
    sc = spec["containers"][0]["securityContext"]
    assert sc["runAsNonRoot"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}


def test_run_as_user_omitted_by_default_for_openshift_scc():
    """restricted-v2 uses runAsUser: MustRunAsRange from the namespace's
    openshift.io/sa.scc.uid-range annotation, so a hardcoded 1000 is rejected
    outright. Omitting it lets SCC assign both runAsUser and fsGroup."""
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    assert "runAsUser" not in pod["spec"]["securityContext"]
    assert "fsGroup" not in pod["spec"]["securityContext"]
    assert "runAsUser" not in pod["spec"]["containers"][0]["securityContext"]


def test_run_as_user_present_when_explicitly_configured():
    """Vanilla Kubernetes needs a concrete UID for runAsNonRoot to schedule a
    root-default image, and an fsGroup so it can write the workspace volume."""
    p = _provisioner(security_context={"run_as_user": 1000, "fs_group": 1000})
    pod = p.pod_manifest("abc", persistent=False, image="img:1", resources=Resources())
    assert pod["spec"]["securityContext"]["runAsUser"] == 1000
    assert pod["spec"]["securityContext"]["fsGroup"] == 1000
    assert pod["spec"]["containers"][0]["securityContext"]["runAsUser"] == 1000


def test_runtime_class_omitted_when_empty_and_present_when_set():
    default_pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )
    assert "runtimeClassName" not in default_pod["spec"]

    kata_pod = _provisioner(runtime_class_name="kata").pod_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )
    assert kata_pod["spec"]["runtimeClassName"] == "kata"


def test_node_selector_tolerations_labels_and_env_reach_the_manifest():
    tolerations = [{"key": "kata", "operator": "Exists", "effect": "NoSchedule"}]
    p = _provisioner(
        node_selector={"node-role.kubernetes.io/worker": ""},
        tolerations=tolerations,
        labels={"team": "hermes"},
        annotations={"io.katacontainers.config.hypervisor.default_memory": "4096"},
        env={"HTTPS_PROXY": "http://proxy:3128"},
        image_pull_secrets=["regcred"],
        image_pull_policy="Always",
    )
    pod = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    assert pod["spec"]["nodeSelector"] == {"node-role.kubernetes.io/worker": ""}
    assert pod["spec"]["tolerations"] == tolerations
    assert pod["spec"]["imagePullSecrets"] == [{"name": "regcred"}]
    assert pod["metadata"]["labels"]["team"] == "hermes"
    assert pod["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "hermes-agent"
    assert pod["metadata"]["annotations"]
    container = pod["spec"]["containers"][0]
    assert container["imagePullPolicy"] == "Always"
    assert {"name": "HTTPS_PROXY", "value": "http://proxy:3128"} in container["env"]


def test_resources_fall_back_to_shared_container_keys_then_explicit_quantities():
    default_pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="i:1",
        resources=Resources(cpu=0.5, memory_mib=2048),
    )
    requests = default_pod["spec"]["containers"][0]["resources"]["requests"]
    assert requests == {"cpu": "500m", "memory": "2048Mi"}
    assert "limits" not in default_pod["spec"]["containers"][0]["resources"]

    explicit = _provisioner(
        resources={"requests": {"cpu": "250m", "memory": "1Gi"},
                   "limits": {"cpu": "2", "memory": "4Gi",
                              "ephemeral_storage": "8Gi"}}
    ).pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    res = explicit["spec"]["containers"][0]["resources"]
    assert res["requests"] == {"cpu": "250m", "memory": "1Gi"}
    assert res["limits"] == {"cpu": "2", "memory": "4Gi", "ephemeral-storage": "8Gi"}


def test_pod_template_overrides_are_applied_last():
    p = _provisioner(pod_template_overrides={"spec": {"priorityClassName": "high"}})
    pod = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    assert pod["spec"]["priorityClassName"] == "high"
    # Merge, not replace.
    assert pod["spec"]["restartPolicy"] == "Never"


def test_read_only_root_filesystem_gets_a_writable_tmp():
    """init_session() writes its env snapshot under /tmp; a read-only root with
    no writable /tmp silently breaks cwd/env tracking."""
    p = _provisioner(security_context={"read_only_root_filesystem": True})
    pod = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    mounts = {m["mountPath"] for m in pod["spec"]["containers"][0]["volumeMounts"]}
    assert "/tmp" in mounts
    assert any(v["name"] == "tmp" for v in pod["spec"]["volumes"])


def test_mount_path_is_configurable():
    p = _provisioner(mount_path="/home/agent")
    pod = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    container = pod["spec"]["containers"][0]
    assert container["workingDir"] == "/home/agent"
    assert container["volumeMounts"][0]["mountPath"] == "/home/agent"


def test_pod_name_is_instance_scoped():
    """_resolve_container_task_id collapses nearly everything to "default", so
    without a discriminator two agents in one namespace fight over the same pod
    name — the second 409s, "reuses" the first's workspace, and later deletes it."""
    a = DirectProvisioner(_kcfg(), "hermes", api=None, owner_reference=OWNER_REF)
    b = DirectProvisioner(
        _kcfg(), "hermes", api=None,
        owner_reference={**OWNER_REF, "uid": "22222222-2222-2222-2222-222222222222"},
    )
    assert a.workspace_name("default") != b.workspace_name("default")
    # The PVC is NOT instance-scoped — a persistent workspace must resume for
    # the same task after an agent restart.
    assert a.pvc_name("default") == b.pvc_name("default")


# ---------------------------------------------------------------------------
# DirectProvisioner against a mocked API
# ---------------------------------------------------------------------------


def _running_pod(labels=None, owners=None):
    cond = SimpleNamespace(type="Ready", status="True")
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name="hermes-ws", labels=labels or {}, owner_references=owners or []
        ),
        status=SimpleNamespace(
            phase="Running", conditions=[cond], container_statuses=[]
        ),
    )


def _provisioner_with_api(api, **overrides):
    return DirectProvisioner(
        _kcfg(**overrides), "hermes", api=api, owner_reference=OWNER_REF
    )


def test_ensure_ephemeral_creates_pod_only():
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    p = _provisioner_with_api(api)

    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())

    api.create_namespaced_pod.assert_called_once()
    api.create_namespaced_persistent_volume_claim.assert_not_called()
    assert ref.pod_name == p.workspace_name("abc")
    assert ref.container == "workspace"


def test_ensure_persistent_creates_pvc_then_pod():
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    api.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    p = _provisioner_with_api(api)

    p.ensure("mytask", persistent=True, image="img:1", resources=Resources())

    api.create_namespaced_persistent_volume_claim.assert_called_once()
    api.create_namespaced_pod.assert_called_once()


def test_ensure_persistent_skips_existing_pvc():
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    api.read_namespaced_persistent_volume_claim.return_value = SimpleNamespace()
    p = _provisioner_with_api(api)

    p.ensure("mytask", persistent=True, image="img:1", resources=Resources())

    api.create_namespaced_persistent_volume_claim.assert_not_called()


def test_ensure_reuses_our_own_pod_on_conflict():
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.create_namespaced_pod.side_effect = ApiException(status=409)
    api.read_namespaced_pod.return_value = _running_pod(
        labels={"app.kubernetes.io/managed-by": "hermes-agent"},
        owners=[SimpleNamespace(uid=OWNER_REF["uid"])],
    )
    p = _provisioner_with_api(api)

    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())
    assert ref.pod_name == p.workspace_name("abc")


def test_ensure_refuses_to_hijack_another_agents_pod():
    """A blanket 409-as-reuse leaks another agent's workspace (and later
    deletes it) on a shared cluster."""
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.create_namespaced_pod.side_effect = ApiException(status=409)
    api.read_namespaced_pod.return_value = _running_pod(
        labels={"app.kubernetes.io/managed-by": "someone-else"},
    )
    p = _provisioner_with_api(api)

    with pytest.raises(RuntimeError, match="not created by this Hermes instance"):
        p.ensure("abc", persistent=False, image="img:1", resources=Resources())


def test_wait_ready_surfaces_image_pull_failures_immediately():
    api = MagicMock()
    api.read_namespaced_pod.return_value = SimpleNamespace(
        metadata=SimpleNamespace(name="p", labels={}, owner_references=[]),
        status=SimpleNamespace(
            phase="Pending",
            conditions=[],
            container_statuses=[
                SimpleNamespace(
                    name="workspace",
                    state=SimpleNamespace(
                        waiting=SimpleNamespace(
                            reason="ImagePullBackOff", message="pull access denied"
                        ),
                        terminated=None,
                    ),
                )
            ],
        ),
    )
    p = _provisioner_with_api(api, ready_timeout_seconds=30)
    with pytest.raises(RuntimeError) as excinfo:
        p.ensure("abc", persistent=False, image="nope:1", resources=Resources())
    assert "ImagePullBackOff" in str(excinfo.value)
    assert "pull access denied" in str(excinfo.value)


def test_destroy_deletes_pod_and_keeps_pvc():
    api = MagicMock()
    p = _provisioner_with_api(api)
    p.destroy(PodRef("hermes", "hermes-ws-abc", "workspace"), persistent=True)
    api.delete_namespaced_pod.assert_called_once()
    kwargs = api.delete_namespaced_pod.call_args.kwargs
    assert kwargs["name"] == "hermes-ws-abc"
    assert kwargs["namespace"] == "hermes"
    # `sleep infinity` as PID 1 ignores SIGTERM; without grace 0 every teardown
    # waits the full 30s default, on the interrupt path.
    assert kwargs["grace_period_seconds"] == 0
    api.delete_namespaced_persistent_volume_claim.assert_not_called()


# ---------------------------------------------------------------------------
# SandboxProvisioner
# ---------------------------------------------------------------------------


def _sandbox_provisioner(api=None, custom=None, **sandbox_overrides):
    return SandboxProvisioner(
        _kcfg(provisioner="sandbox", sandbox=sandbox_overrides),
        "hermes", api=api, owner_reference=OWNER_REF, custom_api=custom,
    )


def test_sandbox_manifest_shape():
    manifest = _sandbox_provisioner().sandbox_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    assert manifest["apiVersion"] == "agents.x-k8s.io/v1beta1"
    assert manifest["kind"] == "Sandbox"
    assert manifest["metadata"]["namespace"] == "hermes"
    assert manifest["metadata"]["ownerReferences"][0]["uid"] == OWNER_REF["uid"]
    spec = manifest["spec"]["podTemplate"]["spec"]
    assert spec["containers"][0]["name"] == "workspace"
    assert spec["containers"][0]["image"] == "img:1"


def test_sandbox_pod_template_matches_direct_pod_spec():
    """Flipping provisioner must not silently change the workload shape."""
    kcfg = _kcfg(runtime_class_name="kata", labels={"team": "hermes"})
    direct = DirectProvisioner(kcfg, "hermes", api=None, owner_reference=OWNER_REF)
    sandbox = SandboxProvisioner(
        kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None
    )
    direct_spec = direct.pod_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )["spec"]
    sandbox_spec = sandbox.sandbox_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )["spec"]["podTemplate"]["spec"]
    assert direct_spec == sandbox_spec
    assert sandbox_spec["runtimeClassName"] == "kata"


def test_sandbox_manifest_uses_template_ref_instead_of_pod_template():
    manifest = _sandbox_provisioner(template_ref="agent-base").sandbox_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    assert manifest["spec"]["sandboxTemplateRef"] == {"name": "agent-base"}
    assert "podTemplate" not in manifest["spec"]


def test_sandbox_spec_overrides_and_ttl():
    manifest = _sandbox_provisioner(
        ttl_seconds=900, spec_overrides={"networkPolicy": {"egress": "deny"}}
    ).sandbox_manifest("abc", persistent=False, image="i:1", resources=Resources())
    assert manifest["spec"]["ttlSeconds"] == 900
    assert manifest["spec"]["networkPolicy"] == {"egress": "deny"}


def test_sandbox_ensure_creates_cr_and_waits_for_pod():
    custom = MagicMock()
    name_holder = {}

    def _get(**kwargs):
        name_holder["name"] = kwargs["name"]
        return {
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "podRef": {"name": "sandbox-pod-1"},
            }
        }

    custom.get_namespaced_custom_object.side_effect = _get
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()

    p = _sandbox_provisioner(api=api, custom=custom)
    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())

    custom.create_namespaced_custom_object.assert_called_once()
    call = custom.create_namespaced_custom_object.call_args.kwargs
    assert call["group"] == "agents.x-k8s.io"
    assert call["plural"] == "sandboxes"
    assert ref.pod_name == "sandbox-pod-1"
    # Exec targets the reconciled pod, not the CR.
    api.read_namespaced_pod.assert_called()


def test_sandbox_ensure_falls_back_to_label_lookup_for_pod_name():
    custom = MagicMock()
    custom.get_namespaced_custom_object.return_value = {
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}
    }
    api = MagicMock()
    api.list_namespaced_pod.return_value = SimpleNamespace(
        items=[SimpleNamespace(metadata=SimpleNamespace(name="labelled-pod"))]
    )
    api.read_namespaced_pod.return_value = _running_pod()

    p = _sandbox_provisioner(api=api, custom=custom)
    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())
    assert ref.pod_name == "labelled-pod"


def test_sandbox_ensure_reports_missing_crd_actionably():
    from kubernetes.client.exceptions import ApiException

    custom = MagicMock()
    custom.create_namespaced_custom_object.side_effect = ApiException(status=404)
    p = _sandbox_provisioner(api=MagicMock(), custom=custom)
    with pytest.raises(RuntimeError, match="agent-sandbox-operator"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())


def test_sandbox_destroy_deletes_the_custom_resource():
    custom = MagicMock()
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    custom.get_namespaced_custom_object.return_value = {
        "status": {"conditions": [{"type": "Ready", "status": "True"}],
                   "podRef": {"name": "sandbox-pod-1"}}
    }
    p = _sandbox_provisioner(api=api, custom=custom)
    ref = p.ensure("abc", persistent=False, image="i:1", resources=Resources())

    p.destroy(ref, persistent=False)
    kwargs = custom.delete_namespaced_custom_object.call_args.kwargs
    assert kwargs["plural"] == "sandboxes"
    # Deleting the CR is what tears the pod down; the pod name differs from it.
    assert kwargs["name"] == p.workspace_name("abc")
    api.delete_namespaced_pod.assert_not_called()


def test_sandbox_claim_requires_bound_sandbox_name():
    custom = MagicMock()
    custom.get_namespaced_custom_object.return_value = {
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}
    }
    p = _sandbox_provisioner(api=MagicMock(), custom=custom,
                             use_claim=True, template_ref="agent-base")
    with pytest.raises(RuntimeError, match="no bound Sandbox"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())


# ---------------------------------------------------------------------------
# KubernetesEnvironment
# ---------------------------------------------------------------------------


class _FakeWSClient:
    """Mimics kubernetes.stream WSClient for one exec call."""

    def __init__(self, stdout="", returncode=0, open_cycles=1, raise_on_update=None):
        self._stdout = stdout
        self._returncode = returncode
        self._cycles = open_cycles
        self._raise_on_update = raise_on_update
        self.closed = False
        self.subprotocol = "v4.channel.k8s.io"

    def is_open(self):
        if self.closed or self._cycles <= 0:
            return False
        self._cycles -= 1
        return True

    def update(self, timeout=None):
        if self._raise_on_update:
            raise self._raise_on_update

    def peek_stdout(self):
        return bool(self._stdout)

    def read_stdout(self):
        s, self._stdout = self._stdout, ""
        return s

    def peek_stderr(self):
        return False

    def read_stderr(self):
        return ""

    def close(self):
        self.closed = True

    @property
    def returncode(self):
        if isinstance(self._returncode, Exception):
            raise self._returncode
        return self._returncode


def _make_k8s_env(monkeypatch, exec_results, persistent=False):
    """exec_results: list of _FakeWSClient factories / tuples per exec call."""
    monkeypatch.setattr("tools.environments.base.is_interrupted", lambda: False)

    provisioner = MagicMock()
    provisioner.workspace_name.return_value = "hermes-ws-abc"
    provisioner.namespace = "hermes"
    provisioner.ensure.return_value = PodRef("hermes", "hermes-ws-abc", "workspace")

    calls = {"i": 0}

    def fake_stream(*args, **kwargs):
        idx = min(calls["i"], len(exec_results) - 1)
        calls["i"] += 1
        spec = exec_results[idx]
        if isinstance(spec, _FakeWSClient):
            return spec
        out, rc = spec
        return _FakeWSClient(stdout=out, returncode=rc)

    monkeypatch.setattr("kubernetes.stream.stream", fake_stream)

    env = KubernetesEnvironment(
        provisioner=provisioner,
        task_id="abc",
        persistent=persistent,
        image="img:1",
        cwd="/workspace",
        timeout=30,
        sync_files=False,  # file sync is exercised separately
    )
    env._exec_calls = calls
    return env


def test_basic_command(monkeypatch):
    # exec calls: (1) init_session bootstrap, (2) the actual command
    env = _make_k8s_env(monkeypatch, [("", 0), ("hello\n", 0)])
    result = env.execute("echo hello")
    assert "hello" in result["output"]
    assert result["returncode"] == 0


def test_nonzero_exit_code(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0), ("nope\n", 127)])
    result = env.execute("bad_cmd")
    assert result["returncode"] == 127


def test_exec_keeps_partial_output_when_returncode_raises(monkeypatch):
    """WSClient.returncode does yaml.safe_load(err)['status'] on the error
    channel; an abnormal disconnect leaves it empty and the property raises
    TypeError. Unguarded, _ThreadedProcessHandle discards every byte."""
    client = _FakeWSClient(stdout="partial output\n",
                           returncode=TypeError("NoneType not subscriptable"))
    env = _make_k8s_env(monkeypatch, [("", 0), client])
    result = env.execute("something")
    assert "partial output" in result["output"]


def test_exec_stream_error_returns_message_not_silence(monkeypatch):
    client = _FakeWSClient(raise_on_update=RuntimeError("connection reset"))
    env = _make_k8s_env(monkeypatch, [("", 0), client])
    result = env.execute("something")
    assert "connection reset" in result["output"]
    assert result["returncode"] != 0


def test_cleanup_calls_provisioner_destroy(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    env.cleanup()
    env._provisioner.destroy.assert_called_once()
    args, _kwargs = env._provisioner.destroy.call_args
    assert args[1] is False  # persistent flag


def test_cleanup_is_idempotent(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    env.cleanup()
    env.cleanup()
    assert env._provisioner.destroy.call_count == 1


def test_ephemeral_cancel_deletes_pod_and_clears_ref(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0), ("", 0)])
    handle = env._run_bash("sleep 1")
    handle.kill()
    env._provisioner.destroy.assert_called()
    assert env._pod_ref is None


def test_persistent_cancel_closes_stream_without_deleting_pod(monkeypatch):
    """The PR left cancel() a no-op for persistent sessions, leaking the exec
    thread, its websocket and a pipe fd for the full command duration."""
    client = _FakeWSClient(open_cycles=10_000)
    env = _make_k8s_env(monkeypatch, [("", 0), client], persistent=True)
    handle = env._run_bash("sleep 3600")
    handle.kill()
    assert client.closed is True
    env._provisioner.destroy.assert_not_called()
    assert env._pod_ref is not None


def test_session_recovers_after_interrupt(monkeypatch):
    """A single timeout used to brick the session: cancel() deleted the pod but
    nothing could re-provision, so every later command 404'd with empty output
    until the idle reaper evicted the environment."""
    env = _make_k8s_env(monkeypatch, [("", 0), ("", 0), ("", 0), ("back\n", 0)])
    handle = env._run_bash("sleep 1")
    handle.kill()
    assert env._pod_ref is None

    env._provisioner.ensure.reset_mock()
    result = env.execute("echo back")
    env._provisioner.ensure.assert_called_once()
    assert env._pod_ref is not None
    assert "back" in result["output"]


def test_failed_ensure_does_not_orphan_a_pod(monkeypatch):
    monkeypatch.setattr("tools.environments.base.is_interrupted", lambda: False)
    provisioner = MagicMock()
    provisioner.namespace = "hermes"
    provisioner.workspace_name.return_value = "hermes-ws-abc"
    provisioner.ensure.side_effect = TimeoutError("not Ready after 120s")

    with pytest.raises(TimeoutError):
        KubernetesEnvironment(
            provisioner=provisioner, task_id="abc", persistent=False,
            image="img:1", cwd="/workspace", timeout=30, sync_files=False,
        )
    provisioner.destroy.assert_called_once()


def test_agent_visible_cache_base_is_stable_across_cd(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    base = env.agent_visible_cache_base()
    env.cwd = "/somewhere/else"
    assert env.agent_visible_cache_base() == base == "/workspace/.hermes"


# ---------------------------------------------------------------------------
# terminal_tool integration
# ---------------------------------------------------------------------------


def _install_fake_backend(monkeypatch):
    captured = {}

    class _FakeEnv:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import tools.environments.kubernetes as k8s_mod

    monkeypatch.setattr(k8s_mod, "KubernetesEnvironment", _FakeEnv)
    monkeypatch.setattr(
        k8s_mod, "DirectProvisioner", lambda *a, **kw: MagicMock(name="direct")
    )
    monkeypatch.setattr(
        k8s_mod, "SandboxProvisioner", lambda *a, **kw: MagicMock(name="sandbox")
    )
    monkeypatch.setattr(
        k8s_mod, "load_kubernetes_apis", lambda kcfg: (MagicMock(), MagicMock())
    )
    monkeypatch.setattr(k8s_mod, "resolve_owner_reference", lambda *a, **kw: None)
    return captured, _FakeEnv


def test_factory_builds_kubernetes_env(monkeypatch):
    import tools.terminal_tool as tt

    captured, fake_cls = _install_fake_backend(monkeypatch)
    env = tt._create_environment(
        env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
        container_config={"container_persistent": False,
                          "kubernetes": {"namespace": "hermes"}},
        task_id="abc",
    )
    assert isinstance(env, fake_cls)
    assert captured["task_id"] == "abc"
    assert captured["persistent"] is False


def test_factory_k8s_defaults_ephemeral_even_when_container_persistent_true(monkeypatch):
    import tools.terminal_tool as tt

    captured, _ = _install_fake_backend(monkeypatch)
    tt._create_environment(
        env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
        container_config={"container_persistent": True,
                          "kubernetes": {"namespace": "hermes"}},
        task_id="abc",
    )
    assert captured["persistent"] is False


def test_factory_k8s_persistent_opt_in(monkeypatch):
    import tools.terminal_tool as tt

    captured, _ = _install_fake_backend(monkeypatch)
    tt._create_environment(
        env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
        container_config={"kubernetes": {"namespace": "hermes", "persistent": True}},
        task_id="abc",
    )
    assert captured["persistent"] is True


def test_factory_selects_sandbox_provisioner(monkeypatch):
    import tools.terminal_tool as tt
    import tools.environments.kubernetes as k8s_mod

    _install_fake_backend(monkeypatch)
    seen = {}
    monkeypatch.setattr(
        k8s_mod, "SandboxProvisioner",
        lambda *a, **kw: seen.setdefault("sandbox", MagicMock()),
    )
    tt._create_environment(
        env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
        container_config={"kubernetes": {"namespace": "hermes",
                                         "provisioner": "sandbox"}},
        task_id="abc",
    )
    assert "sandbox" in seen


def test_factory_rejects_invalid_config(monkeypatch):
    import tools.terminal_tool as tt

    _install_fake_backend(monkeypatch)
    with pytest.raises(ValueError, match="provisioner"):
        tt._create_environment(
            env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
            container_config={"kubernetes": {"namespace": "hermes",
                                             "provisioner": "operator"}},
            task_id="abc",
        )


def test_check_requirements_kubernetes_missing_client(monkeypatch):
    import tools.terminal_tool as tt

    monkeypatch.setattr(tt, "_get_env_config", lambda: {"env_type": "kubernetes"})
    import importlib.util as _ilu

    real_find_spec = _ilu.find_spec

    def fake_find_spec(name, *a, **k):
        if name == "kubernetes":
            return None
        return real_find_spec(name, *a, **k)

    monkeypatch.setattr(tt.importlib.util, "find_spec", fake_find_spec)
    assert tt.check_terminal_requirements() is False


def test_check_requirements_kubernetes_present(monkeypatch):
    import tools.terminal_tool as tt

    monkeypatch.setattr(
        tt, "_get_env_config",
        lambda: {"env_type": "kubernetes", "kubernetes": {"namespace": "hermes"}},
    )
    monkeypatch.setattr(tt.importlib.util, "find_spec", lambda name, *a, **k: object())
    assert tt.check_terminal_requirements() is True


def test_check_requirements_rejects_invalid_config(monkeypatch):
    import tools.terminal_tool as tt

    monkeypatch.setattr(
        tt, "_get_env_config",
        lambda: {"env_type": "kubernetes", "kubernetes": {"provisioner": "nope"}},
    )
    monkeypatch.setattr(tt.importlib.util, "find_spec", lambda name, *a, **k: object())
    assert tt.check_terminal_requirements() is False


def test_live_terminal_tool_kubernetes_image_and_container_config(monkeypatch):
    """Regression pin for the two spots the upstream PR missed at first: the
    image-selection ladder and the container_config builder in terminal_tool().

    Drives the real terminal_tool() entry path with _create_environment stubbed,
    so no cluster is needed.
    """
    import uuid

    import tools.terminal_tool as tt

    unique_task_id = f"k8s-regression-{uuid.uuid4().hex}"
    with tt._env_lock:
        tt._active_environments.pop(unique_task_id, None)
        # _resolve_container_task_id collapses non-isolation task ids back to
        # "default", so a cached env another test left there would be reused and
        # _create_environment never called.
        tt._active_environments.pop("default", None)

    captured = {}

    def _fake_create_environment(**kwargs):
        captured.update(kwargs)
        mock_env = MagicMock()
        mock_env.execute.return_value = {"output": "", "returncode": 0}
        return mock_env

    monkeypatch.setattr(tt, "_create_environment", _fake_create_environment)
    monkeypatch.setattr(tt, "_check_all_guards", lambda *a, **kw: {"approved": True})
    monkeypatch.setattr(tt, "_start_cleanup_thread", lambda: None)

    monkeypatch.setenv("TERMINAL_ENV", "kubernetes")
    # The ONLY kubernetes env var: the internal JSON bridge payload. There is
    # deliberately no TERMINAL_KUBERNETES_POD_SA / _IMAGE / _NAMESPACE.
    monkeypatch.setenv(
        "TERMINAL_KUBERNETES",
        json.dumps({"namespace": "hermes", "service_account": "custom-sa",
                    "image": "quay.io/hermes/session:1"}),
    )

    # An isolation-keyed override keeps _resolve_container_task_id from
    # collapsing this session onto the shared "default" container.
    tt._task_env_overrides[unique_task_id] = {"env_type": "kubernetes"}
    try:
        tt.terminal_tool(command="echo hi", task_id=unique_task_id, force=True)
    finally:
        with tt._env_lock:
            tt._active_environments.pop(unique_task_id, None)
        tt._task_env_overrides.pop(unique_task_id, None)

    assert captured, "_create_environment was never called"
    assert captured["image"] == "quay.io/hermes/session:1"
    cc = captured.get("container_config")
    assert cc is not None, "container_config was None — kubernetes missing from the builder"
    assert cc["kubernetes"]["service_account"] == "custom-sa"
    assert cc["kubernetes"]["namespace"] == "hermes"
    # Defaults survive a partial payload.
    assert cc["kubernetes"]["provisioner"] == "direct"


def test_kubernetes_backend_default_cwd_is_the_mount_path(monkeypatch):
    import tools.terminal_tool as tt

    monkeypatch.setattr(tt, "_ensure_terminal_env_bridged", lambda: None)
    monkeypatch.setenv("TERMINAL_ENV", "kubernetes")
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    monkeypatch.setenv("TERMINAL_KUBERNETES", json.dumps({"mount_path": "/home/agent"}))
    cfg = tt._get_env_config()
    assert cfg["cwd"] == "/home/agent"
    assert cfg["kubernetes"]["mount_path"] == "/home/agent"


def test_stale_kubernetes_payload_does_not_break_other_backends(monkeypatch):
    """Bridged container-only env vars must not be parsed when another backend
    is selected — a malformed value would otherwise kill the local terminal."""
    import tools.terminal_tool as tt

    monkeypatch.setattr(tt, "_ensure_terminal_env_bridged", lambda: None)
    monkeypatch.setenv("TERMINAL_ENV", "local")
    monkeypatch.setenv("TERMINAL_KUBERNETES", "{not json")
    cfg = tt._get_env_config()
    assert cfg["env_type"] == "local"
    assert cfg["kubernetes"] == {}


def test_kubernetes_is_a_container_backend():
    """Membership drives cwd sanitization, container_config assembly and the
    file-tool path translation."""
    import tools.terminal_tool as tt

    assert "kubernetes" in tt._CONTAINER_BACKENDS
