"""Unit tests for the Kubernetes session-pod execution backend.

Ported from upstream PR #37591 and re-specified for this fork's config surface:
every setting is a ``terminal.kubernetes.*`` config.yaml key bridged as ONE
internal JSON env var, and the pod shape is ONE ``pod_template``
PodTemplateSpec merged over a DEFAULT base with RFC 7386 semantics. Nothing in
that base is reserved: validating and constraining the pod is the cluster's
job (``fieldValidation=Strict``, SCC / PSA / admission policy), so these tests
pin the MERGE, the managed-by stamp and the exec loop — not a local judge.

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

# merge_pod_template and the sandbox provisioner are imported inside the tests
# that use them, so this module still imports against a build that lacks them.


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


def test_validation_rejects_an_unknown_provisioner():
    """`provisioner` selects which Kubernetes API this backend calls, so an
    unknown value has no request to be rejected by — it is one of the two
    things the API server cannot check for us."""
    problems = validate_kubernetes_config(_kcfg(provisioner="operator"))
    assert any("provisioner" in p for p in problems)


def test_validation_leaves_pod_content_to_the_api_server():
    """A bogus quantity, a bad RFC-1123 name and a /tmp mount collision are all
    things the API server rejects with the exact JSON path under
    fieldValidation=Strict. Hermes deliberately says nothing about them: an
    in-process approximation would be redundant where it agreed and wrong where
    it did not."""
    assert validate_kubernetes_config(_kcfg(volume={"size": "2 gigabytes"})) == []
    assert validate_kubernetes_config(_kcfg(container_name="Not Valid")) == []
    assert validate_kubernetes_config(_kcfg(mount_path="/tmp")) == []
    assert validate_kubernetes_config(_kcfg(pod_template={"spec": {
        "securityContext": {"runAsUser": 0, "runAsNonRoot": False},
    }})) == []


def test_validation_reports_the_types_it_needs_to_build_a_request():
    """The other half of what the API server cannot do for us: a scalar where a
    mapping belongs is a TypeError inside a manifest builder, never an HTTP
    response."""
    assert any("pod_template" in p
               for p in validate_kubernetes_config(_kcfg(pod_template=["a"])))
    assert any("sandbox.spec" in p for p in validate_kubernetes_config(
        _kcfg(sandbox={"api_group": "g", "api_version": "v", "spec": "nope"})))
    assert any("terminal.kubernetes must be a mapping"
               in p for p in validate_kubernetes_config("nope"))


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
    shim: the schema is the 15 top-level keys the backend reasons about
    (20 leaves counting volume.* and sandbox.*)."""
    # Named, not counted: a bare `== 14` fails for any legitimate new key and
    # names no offender. This fails for the same input and says which key.
    assert set(DEFAULT_KUBERNETES_CONFIG) == {
        "provisioner", "namespace", "kubeconfig", "context", "image",
        "container_name", "mount_path", "pod_template", "trusted_sandbox",
        "persistent", "volume", "active_deadline_seconds",
        "ready_timeout_seconds", "owner_reference", "sandbox",
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


def test_the_default_base_is_a_sane_starting_point():
    """What pod_template merges OVER. These are DEFAULTS, not constraints —
    every one of them is overridable (see the override tests below). They exist
    so the out-of-box config produces a pod that starts, stays up, can be
    exec'd into, and satisfies OpenShift restricted-v2 without extra RBAC."""
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
    """The user layer: anything that is merely PodSpec goes here."""
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
    """init_session() writes its env snapshot under /tmp, so the DEFAULT base
    always mounts an emptyDir there. Overridable like everything else — a
    pod_template that replaces spec.volumes drops it, and the session's env
    tracking then fails visibly on the first command."""
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
    # The provisioner enum: it picks which Kubernetes API is called, so an
    # unknown value never becomes a request the server could reject.
    ({"provisioner": "operator"}, "provisioner"),
    # The types needed to BUILD a request. A scalar here is a TypeError inside
    # a manifest builder, never an HTTP response.
    ({"pod_template": "not-a-mapping"}, "pod_template"),
    ({"provisioner": "sandbox", "sandbox": {"spec": 7}}, "sandbox.spec"),
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
    """The old code silently exec'd into names[0]. `container_name` is the exec
    target SELECTOR, so a pod that lacks it is either not the pod this backend
    rendered or a pod whose container a `pod_template` renamed — and the very
    next thing that happens is a credential-file upload into whatever we
    exec'd into."""
    p = _provisioner_with_api(MagicMock())
    pod = _running_pod(containers=("istio-proxy", "somebody-elses-shell"))
    with pytest.raises(RuntimeError, match="did not render"):
        p.exec_container(pod)


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
# Approval trust: DECLARED by the operator, never inferred from the pod
# ---------------------------------------------------------------------------


def _has_host_access(**overrides):
    from tools.terminal_tool import _kubernetes_has_host_access

    return _kubernetes_has_host_access({"kubernetes": _kcfg(**overrides)})


def test_the_approval_skip_is_off_by_default():
    """Guards ON unless the operator opts out. `trusted_sandbox` defaults to
    false, and "has host access" is its negation."""
    assert DEFAULT_KUBERNETES_CONFIG["trusted_sandbox"] is False
    assert _has_host_access() is True


def test_trusted_sandbox_is_the_only_input_to_the_approval_skip():
    """DECLARED, not inferred. Hermes used to grade the rendered pod —
    securityContext, volume types, host namespaces, the ServiceAccount — and
    six review rounds each found another way to fool that grader. Whether a pod
    is contained is decided by SCC / Pod Security Admission /
    ValidatingAdmissionPolicy / NetworkPolicy, which Hermes cannot see, so the
    operator states the answer and nothing about the pod is read."""
    assert _has_host_access(trusted_sandbox=True) is False

    # Every one of these used to flip the verdict on its own. Now none of them
    # does: the declaration is the whole input.
    for hostile in (
        {"persistent": True},
        {"pod_template": {"spec": {"hostPID": True, "hostNetwork": True}}},
        {"pod_template": {"spec": {"automountServiceAccountToken": True,
                                   "serviceAccountName": "cluster-admin-sa"}}},
        {"pod_template": {"spec": {"containers": [
            {"name": "workspace",
             "securityContext": {"privileged": True, "runAsUser": 0}}]}}},
        {"pod_template": {"spec": {"volumes": [
            {"name": "host", "hostPath": {"path": "/"}}]}}},
    ):
        assert _has_host_access(trusted_sandbox=True, **hostile) is False, hostile
        assert _has_host_access(**hostile) is True, hostile


def test_the_approval_skip_never_renders_or_inspects_a_pod(monkeypatch):
    """The function must not touch the renderer at all — an evaluation that
    renders is an evaluation that can raise, and one that reads the pod is the
    in-process admission control this design removed."""
    import tools.environments.kubernetes as k8s_mod

    def _boom(*a, **kw):
        raise AssertionError("the approval skip rendered a pod template")

    monkeypatch.setattr(k8s_mod, "render_pod_template", _boom)
    assert _has_host_access(trusted_sandbox=True) is False
    assert _has_host_access() is True


def test_a_malformed_kubernetes_block_keeps_the_guards_on():
    from tools.terminal_tool import _kubernetes_has_host_access

    assert _kubernetes_has_host_access({"kubernetes": None}) is True
    assert _kubernetes_has_host_access({"kubernetes": "nonsense"}) is True
    assert _kubernetes_has_host_access({}) is True


def test_approval_layer_keeps_guards_when_host_access_is_true():
    from tools.approval import _should_skip_container_guards

    assert _should_skip_container_guards("kubernetes", has_host_access=True) is False
    assert _should_skip_container_guards("kubernetes", has_host_access=False) is True


def test_docker_host_access_dispatches_to_the_kubernetes_evaluator():
    from tools.terminal_tool import _docker_has_host_access

    assert _docker_has_host_access(
        {"env_type": "kubernetes", "kubernetes": _kcfg()}
    ) is True
    assert _docker_has_host_access(
        {"env_type": "kubernetes", "kubernetes": _kcfg(trusted_sandbox=True)}
    ) is False


# ---------------------------------------------------------------------------
# Nothing is reserved: a pod_template may override anything
# ---------------------------------------------------------------------------


MANAGED_BY = "app.kubernetes.io/managed-by"


@pytest.mark.parametrize("pod_template, check", [
    # The exec container's process. It used to be pinned and any attempt to set
    # it was a config error; a pod that exits immediately is now the operator's
    # error to see, at the first command.
    ({"spec": {"containers": [{"name": "workspace",
                               "command": ["/bin/dash"], "args": ["-l"]}]}},
     lambda s: (s["containers"][0]["command"] == ["/bin/dash"]
                and s["containers"][0]["args"] == ["-l"])),
    # A restart used to be able to swap the workspace out mid-session.
    ({"spec": {"restartPolicy": "Always"}},
     lambda s: s["restartPolicy"] == "Always"),
    # The workspace mount and the volume behind it.
    ({"spec": {"containers": [{"name": "workspace", "volumeMounts": [
        {"name": "elsewhere", "mountPath": "/workspace"}]}]}},
     lambda s: s["containers"][0]["volumeMounts"] == [
         {"name": "elsewhere", "mountPath": "/workspace"}]),
    ({"spec": {"volumes": [{"name": "workspace",
                            "hostPath": {"path": "/srv"}}]}},
     lambda s: s["volumes"] == [{"name": "workspace",
                                 "hostPath": {"path": "/srv"}}]),
    # The securityContext floor.
    ({"spec": {"securityContext": {"runAsNonRoot": False, "runAsUser": 0}}},
     lambda s: s["securityContext"] == {"runAsNonRoot": False, "runAsUser": 0,
                                        "seccompProfile":
                                            {"type": "RuntimeDefault"}}),
    ({"spec": {"containers": [{"name": "workspace", "securityContext": {
        "privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}}]}},
     lambda s: s["containers"][0]["securityContext"]["privileged"] is True),
    # The no-perms ServiceAccount and its unmounted token.
    ({"spec": {"serviceAccountName": "builder",
               "automountServiceAccountToken": True}},
     lambda s: (s["serviceAccountName"] == "builder"
                and s["automountServiceAccountToken"] is True)),
    # Host namespaces.
    ({"spec": {"hostNetwork": True, "hostPID": True, "hostIPC": True}},
     lambda s: s["hostNetwork"] and s["hostPID"] and s["hostIPC"]),
    # RFC 7386: null DELETES a base default outright.
    ({"spec": {"automountServiceAccountToken": None}},
     lambda s: "automountServiceAccountToken" not in s),
])
def test_a_pod_template_can_override_anything_in_the_base(pod_template, check):
    """The onus is on the cluster administrator. Hermes' base is defaults, and
    every one of these used to be a hard config error naming a dotted path.
    What a session pod is ALLOWED to be is decided by SCC / Pod Security
    Admission / ValidatingAdmissionPolicy / RBAC, and whether it is well-formed
    is decided by the API server under fieldValidation=Strict."""
    kcfg = _kcfg(pod_template=pod_template)
    assert validate_kubernetes_config(kcfg) == []
    template = render_pod_template(
        kcfg, persistent=False, image="i:1", resources=Resources(),
        pvc_name="hermes-ws",
    )
    assert check(template["spec"]), template["spec"]


def test_the_sandbox_cr_spec_is_submitted_verbatim():
    """`sandboxTemplateRef` and every other CR field used to be rejected or to
    cost the approval skip. The CRD's own schema validates them now, under
    fieldValidation=Strict, and what the operator does with them is the
    cluster's business."""
    cr_spec = {"sandboxTemplateRef": {"name": "privileged"},
               "ttlSeconds": 900, "whateverTheCrdAdded": {"x": 1}}
    kcfg = _kcfg(provisioner="sandbox",
                 sandbox={"api_group": "agents.x-k8s.io",
                          "api_version": "v1beta1", "spec": cr_spec})
    assert validate_kubernetes_config(kcfg) == []

    manifest = _sandbox_provisioner(spec=cr_spec).sandbox_manifest(
        "abc", persistent=False, image="i:1", resources=Resources()
    )
    assert manifest["spec"]["sandboxTemplateRef"] == {"name": "privileged"}
    assert manifest["spec"]["whateverTheCrdAdded"] == {"x": 1}


def test_the_injected_pod_template_wins_over_one_written_in_sandbox_spec():
    """`spec.podTemplate` is ASSIGNED, not merged: the same rendered dict feeds
    both provisioners. A podTemplate written in config is overwritten rather
    than rejected — there is nothing to reject, and one source is still one
    source."""
    manifest = _sandbox_provisioner(
        spec={"podTemplate": {"spec": {"hostPID": True}}}
    ).sandbox_manifest("abc", persistent=False, image="i:1",
                       resources=Resources())
    pod_spec = manifest["spec"]["podTemplate"]["spec"]
    assert pod_spec["hostPID"] is False, "the config-written podTemplate won"
    assert pod_spec["containers"][0]["name"] == "workspace"


# ---------------------------------------------------------------------------
# The managed-by label survives the merge (adoption + the admin's NetworkPolicy)
# ---------------------------------------------------------------------------


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


def test_the_label_survives_any_attempt_to_change_or_delete_it():
    """Stamped AFTER the merge, so the stamp wins — including against RFC 7386
    null-deletion of the whole metadata node. Not a security control: it is how
    Hermes finds and adopts its own session pods, and what the admin's
    NetworkPolicy and ValidatingAdmissionPolicy select on. A template that
    dropped it would break adoption and fall out of the admin's policy
    silently, which is the one outcome nobody asked for."""
    for overlay in ({"metadata": {"labels": {MANAGED_BY: "Helm"}}},
                    {"metadata": None},
                    {"metadata": {"labels": None}},
                    {"metadata": {"labels": 7}}):
        kcfg = _kcfg(pod_template=overlay)
        assert validate_kubernetes_config(kcfg) == [], overlay
        template = render_pod_template(
            kcfg, persistent=False, image="i:1", resources=Resources(),
            pvc_name="hermes-ws",
        )
        assert template["metadata"]["labels"][MANAGED_BY] == "hermes-agent", overlay


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
# The pod_template merge rule: RFC 7386 + the containers-by-name exception
# ---------------------------------------------------------------------------


def test_maps_merge_recursively():
    """Case 1 of the rule. The overlay names one key inside spec; every other
    key the base set is still there."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"spec": {"restartPolicy": "Never", "nodeSelector": {"a": "1"},
                  "securityContext": {"runAsNonRoot": True,
                                      "seccompProfile": {"type": "RuntimeDefault"}}}},
        {"spec": {"nodeSelector": {"b": "2"},
                  "securityContext": {"runAsUser": 1000}}},
    )
    assert merged["spec"]["restartPolicy"] == "Never"
    assert merged["spec"]["nodeSelector"] == {"a": "1", "b": "2"}
    assert merged["spec"]["securityContext"] == {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
        "runAsUser": 1000,
    }


def test_lists_replace_wholesale():
    """Case 2 of the rule, and the change from the old bespoke merge: EVERY
    list replaces — volumes, volumeMounts, env, tolerations, imagePullSecrets,
    ports. Replacement is loud (you lose what you did not restate), which is
    the point: there is no index for an alias to slip past, and no
    patchMergeKey table for all of PodSpec to carry and version."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"spec": {
            "volumes": [{"name": "workspace", "emptyDir": {}},
                        {"name": "tmp", "emptyDir": {}}],
            "tolerations": [{"key": "a"}],
            "imagePullSecrets": [{"name": "old"}],
            "containers": [{"name": "workspace",
                            "env": [{"name": "A", "value": "1"}],
                            "ports": [{"containerPort": 80}],
                            "volumeMounts": [
                                {"name": "workspace", "mountPath": "/workspace"},
                                {"name": "tmp", "mountPath": "/tmp"}]}]}},
        {"spec": {
            "volumes": [{"name": "scratch", "emptyDir": {}}],
            "tolerations": [{"key": "b"}],
            "imagePullSecrets": [{"name": "new"}],
            "containers": [{"name": "workspace",
                            "env": [{"name": "B", "value": "2"}],
                            "ports": [{"containerPort": 443}],
                            "volumeMounts": [
                                {"name": "scratch", "mountPath": "/scratch"}]}]}},
    )
    spec = merged["spec"]
    assert spec["volumes"] == [{"name": "scratch", "emptyDir": {}}]
    assert spec["tolerations"] == [{"key": "b"}]
    assert spec["imagePullSecrets"] == [{"name": "new"}]
    container = spec["containers"][0]
    assert container["env"] == [{"name": "B", "value": "2"}]
    assert container["ports"] == [{"containerPort": 443}]
    assert container["volumeMounts"] == [{"name": "scratch",
                                          "mountPath": "/scratch"}]


def test_containers_merge_element_wise_by_name():
    """Case 3: the ONE exception. Without it the most common override there is
    — setting `resources` on the workspace container — would force the user to
    restate image, command, volumeMounts and securityContext verbatim, and a
    drifting restatement is exactly what a merge rule exists to avoid."""
    template = render_pod_template(
        _kcfg(pod_template={"spec": {"containers": [
            {"name": "workspace", "resources": {"limits": {"cpu": "2"}}},
            {"name": "sidecar", "image": "proxy:1"},
        ], "initContainers": [{"name": "prep", "image": "busybox"}]}}),
        persistent=False, image="img:1", resources=Resources(), pvc_name="pvc",
    )
    workspace, sidecar = template["spec"]["containers"]
    # Merged by name: the base container's own fields survive...
    assert workspace["name"] == "workspace"
    assert workspace["image"] == "img:1"
    assert workspace["command"] == ["sleep", "infinity"]
    assert workspace["volumeMounts"]
    assert workspace["securityContext"]["allowPrivilegeEscalation"] is False
    assert workspace["resources"]["limits"] == {"cpu": "2"}
    # ...and a container the base does not declare is APPENDED, not dropped.
    assert sidecar == {"name": "sidecar", "image": "proxy:1"}
    # initContainers get the same treatment (the base declares none).
    assert template["spec"]["initContainers"] == [{"name": "prep",
                                                   "image": "busybox"}]


def test_null_removes_a_base_default():
    """RFC 7386's defining rule, and what makes "every field is overridable"
    complete: without it a base default could be changed but never dropped."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"spec": {"restartPolicy": "Never", "securityContext": {"a": 1},
                  "containers": [{"name": "workspace", "workingDir": "/w"}]}},
        {"spec": {"securityContext": None,
                  "containers": [{"name": "workspace", "workingDir": None}]}},
    )
    assert "securityContext" not in merged["spec"]
    assert merged["spec"]["restartPolicy"] == "Never"
    assert "workingDir" not in merged["spec"]["containers"][0]


def test_the_containers_exception_is_path_anchored():
    """`spec.containers` and `spec.initContainers`, nothing else. A list that
    merely happens to be called `containers` somewhere else is a plain list and
    replaces, and so does `ephemeralContainers`."""
    from tools.environments.kubernetes import merge_pod_template

    merged = merge_pod_template(
        {"metadata": {"containers": [{"name": "a"}]},
         "spec": {"ephemeralContainers": [{"name": "a", "image": "keep:1"}]}},
        {"metadata": {"containers": [{"name": "b"}]},
         "spec": {"ephemeralContainers": [{"name": "a"}]}},
    )
    assert merged["metadata"]["containers"] == [{"name": "b"}]
    assert merged["spec"]["ephemeralContainers"] == [{"name": "a"}]


def test_the_merge_does_not_mutate_the_base_or_the_overlay():
    from tools.environments.kubernetes import merge_pod_template

    base = {"spec": {"containers": [{"name": "workspace", "env": [{"name": "A"}]}]}}
    overlay = {"spec": {"containers": [{"name": "workspace",
                                        "env": [{"name": "B"}]}]}}
    merged = merge_pod_template(base, overlay)
    merged["spec"]["containers"][0]["env"].append({"name": "C"})
    assert base["spec"]["containers"][0]["env"] == [{"name": "A"}]
    assert overlay["spec"]["containers"][0]["env"] == [{"name": "B"}]


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
# The shipped cluster manifests say what they actually do
#
# The controls live in k8s/*.yaml now, so an overclaim in their headers is the
# failure mode with real consequences: an operator who believes Hermes is
# enforcing something stops enforcing it themselves.
# ---------------------------------------------------------------------------

K8S_DIR = __import__("pathlib").Path(__file__).resolve().parents[2] / "k8s"


def test_validatingadmissionpolicy_does_not_claim_the_label_is_unconfigurable():
    """A false security claim in shipped docs is worse than the bug: an earlier
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
    # It selects on the managed-by label, and says why config cannot strip it:
    # the stamp is applied AFTER the merge, so it is the last write.
    assert "app.kubernetes.io/managed-by" in text
    assert "AFTER the user's" in text
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


def test_doctor_reports_the_api_servers_rejection_as_a_failure():
    """The API server IS the validator, so its 400 is what doctor reports —
    with the server's own message, which names the exact JSON path. A transient
    error (403, connection refused) is only a warning: it says nothing about
    the template."""
    from hermes_cli import doctor
    from kubernetes.client.exceptions import ApiException

    core = MagicMock()
    core.create_namespaced_pod.side_effect = ApiException(status=400, reason="Bad")
    issues: list[str] = []
    doctor._dry_run_pod_template(_kcfg(), "hermes", core, False, issues)
    assert any("pod_template" in issue for issue in issues), issues

    core = MagicMock()
    core.create_namespaced_pod.side_effect = ApiException(status=403, reason="No")
    issues = []
    doctor._dry_run_pod_template(_kcfg(), "hermes", core, False, issues)
    assert issues == []


# ---------------------------------------------------------------------------
# What a pod_template CAN break, and what stays working
# ---------------------------------------------------------------------------
#
# Six review rounds each found a new way past the in-process "reserved core"
# check that used to live here, which is the argument against having one. The
# contract is now the opposite one: a pod_template that reaches those fields
# reaches them, and a pod that cannot serve exec fails at the first command.
# What these pin is that the ORDINARY overrides still work — the exception
# nobody would forgive is a merge rule that quietly drops what you wrote.


#: Templates that must keep working. Each one is a thing an operator actually
#: does, and each is a case the merge rule has to get right.
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


@pytest.mark.parametrize("pod_template", _CLEAN_PROBES)
def test_ordinary_overrides_still_produce_an_exec_able_pod(pod_template):
    """Both provisioners submit the SAME rendered template, the exec container
    is still there under the configured name, and the managed-by stamp
    survived."""
    kcfg = _kcfg(pod_template=pod_template)
    assert validate_kubernetes_config(kcfg) == []

    pod = PodProvisioner(
        kcfg, "hermes", api=None, owner_reference=OWNER_REF,
    ).pod_manifest("abc", persistent=False, image="i:1", resources=Resources())
    sandbox = _sandbox_cls()(
        dict(kcfg, provisioner="sandbox"), "hermes", api=None,
        owner_reference=OWNER_REF, custom_api=None,
    ).sandbox_manifest("abc", persistent=False, image="i:1",
                       resources=Resources())
    assert pod["spec"] == sandbox["spec"]["podTemplate"]["spec"]

    for template in ({"metadata": pod["metadata"], "spec": pod["spec"]},
                     sandbox["spec"]["podTemplate"]):
        spec = template["spec"]
        workspace = [c for c in spec["containers"] if c["name"] == "workspace"]
        assert len(workspace) == 1, spec["containers"]
        assert workspace[0]["command"] == ["sleep", "infinity"]
        assert template["metadata"]["labels"][MANAGED_BY] == "hermes-agent"


@pytest.mark.parametrize("overrides, expected", [
    ({"sandbox": "oops"}, "terminal.kubernetes.sandbox must be a mapping"),
    ({"provisioner": "sandbox", "sandbox": {"spec": "oops"}},
     "terminal.kubernetes.sandbox.spec must be a mapping"),
    ({"pod_template": "oops"},
     "terminal.kubernetes.pod_template must be a mapping"),
])
def test_a_non_mapping_block_is_a_message_not_a_crash(overrides, expected):
    """The types the validator still checks, and the only reason it checks
    them: a scalar here is a TypeError or an AttributeError inside a manifest
    builder, never an HTTP response the API server could name a path in."""
    kcfg = _kcfg(**overrides)
    problems = validate_kubernetes_config(kcfg)
    assert any(expected in p for p in problems), problems


def test_a_non_mapping_volume_block_is_left_to_the_api_server():
    """`volume` is different: `_mapping()` already tolerates a scalar there and
    the resulting PVC is a request the API server rejects by name. Nothing for
    Hermes to add."""
    assert validate_kubernetes_config(_kcfg(volume="oops")) == []
    pvc = _provisioner(volume="oops").pvc_manifest("t", resources=Resources())
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]


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

