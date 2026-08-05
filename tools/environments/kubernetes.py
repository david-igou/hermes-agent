"""Kubernetes session-pod execution environment.

Runs each agent command by exec-ing into a per-session pod in a Kubernetes
cluster.  Provisioning sits behind :class:`WorkspaceProvisioner` so the raw-API
:class:`DirectProvisioner` can be swapped for the operator-CR
:class:`SandboxProvisioner` (``agents.x-k8s.io/v1beta1`` ``Sandbox``, reconciled
by agent-sandbox-operator) without touching the exec loop.

Configuration policy
--------------------
Every user-facing setting for this backend lives in ``config.yaml`` under
``terminal.kubernetes.*`` (see :data:`DEFAULT_KUBERNETES_CONFIG`).  There are no
``TERMINAL_KUBERNETES_*`` env vars: the existing terminal config bridge
serialises the whole block into ONE internal env var (``TERMINAL_KUBERNETES``)
that only ``tools.terminal_tool`` reads.  ``.env`` is for secrets, and this
backend has no credential surface at all — in-cluster auth is the projected
ServiceAccount token the kubelet mounts, which Hermes never reads or stores.

Auth resolution order: in-cluster ServiceAccount →
``terminal.kubernetes.kubeconfig`` → ambient ``KUBECONFIG`` / ``~/.kube/config``.

All ``kubernetes`` SDK imports are function-local so this module imports
cleanly (and its manifest builders stay unit-testable) without the client
installed.
"""

import base64
import hashlib
import io
import logging
import os
import posixpath
import re
import socket
import tarfile
import threading
import time
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Optional

from tools.environments.base import BaseEnvironment, _ThreadedProcessHandle
from tools.environments.file_sync import (
    FileSyncManager,
    iter_sync_files,
    quoted_mkdir_command,
    quoted_rm_command,
    unique_parent_dirs,
)

logger = logging.getLogger(__name__)

# Namespace the kubelet projects into every pod.
_SA_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
_SA_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"

WORKSPACE_CONTAINER_NAME = "workspace"
# Grace added to the caller's timeout before the exec loop gives up on its
# own; _wait_for_process is expected to act first.
_EXEC_GRACE_SECONDS = 15
# Terminator for the stdin file-sync payload (see _stdin_upload).
_SYNC_SENTINEL = "__HERMES_TAR_EOF__"
_STDIN_CHUNK_BYTES = 64 * 1024
MANAGED_BY_LABEL = {"app.kubernetes.io/managed-by": "hermes-agent"}


# ---------------------------------------------------------------------------
# Configuration schema
# ---------------------------------------------------------------------------
#
# Mirrored verbatim in hermes_cli/config_defaults.py -> DEFAULT_CONFIG
# ["terminal"]["kubernetes"] (a literal is required there so `hermes config
# set` key validation and the desktop schema can walk it).  The two are pinned
# together by tests/tools/test_kubernetes_config_schema.py.
DEFAULT_KUBERNETES_CONFIG: dict[str, Any] = {
    # --- selection / connection ---------------------------------------
    "provisioner": "direct",          # direct | sandbox
    "namespace": "",                  # "" -> the projected SA namespace file
    "kubeconfig": "",                 # out-of-cluster dev only (a path, not a secret)
    "context": "",                    # kubeconfig context; ignored in-cluster
    # --- workload shape (both provisioners) ---------------------------
    "image": "nikolaik/python-nodejs:python3.11-nodejs20",
    "image_pull_policy": "IfNotPresent",
    "image_pull_secrets": [],
    # Container this backend builds AND execs into.  With sandbox.template_ref
    # / sandbox.use_claim the pod is built by the operator, so when the
    # reconciled pod has no container with this name the first one is used
    # instead (see _BaseProvisioner.pick_container).
    "container_name": "workspace",
    "service_account": "hermes-session-noperms",
    "automount_service_account_token": False,
    "runtime_class_name": "",         # e.g. "kata" for OpenShift sandboxed containers
    "node_selector": {},
    "tolerations": [],
    "labels": {},
    "annotations": {},
    # Literal NON-SECRET env vars inside the session container. config.yaml is
    # the non-secret half of the config split, so never put an API key here.
    #
    # The session pod is credential-free BY DESIGN. You *can* reference a
    # Secret by name through pod_template_overrides (envFrom / secretKeyRef),
    # but know the two consequences: k8s/validatingadmissionpolicy.yaml DENIES
    # secret-backed env and secret volumes alike (a pod that can name any
    # Secret in the namespace can exfiltrate it), and unhardened_reasons()
    # counts such a pod as not-a-throwaway-sandbox, so the dangerous-command
    # approval prompts stay on.
    "env": {},
    "mount_path": "/workspace",
    # Strategic-merge patch applied last onto the built pod template. Lists of
    # named objects (containers, volumes, volumeMounts, env, ...) merge by
    # `name`; every other list replaces wholesale.
    "pod_template_overrides": {},
    # --- workspace lifetime -------------------------------------------
    "persistent": False,
    "volume": {
        "size": "10Gi",               # "" -> {container_disk}Mi (50Gi by default)
        "storage_class_name": "",     # "" -> omit (cluster default StorageClass)
        "access_modes": ["ReadWriteOnce"],
        # "" -> hermes-ws-<task>, which every Hermes instance in the namespace
        # running that task id SHARES. Set an explicit name when several
        # agents share a namespace and must not share a workspace.
        "claim_name": "",
    },
    "active_deadline_seconds": 14400,  # ephemeral pods only; 0 -> omit
    "ready_timeout_seconds": 120,
    "owner_reference": "auto",        # auto | off
    # --- security context ---------------------------------------------
    "security_context": {
        "run_as_non_root": True,
        # null/0 -> omit runAsUser so OpenShift's restricted-v2 SCC assigns a
        # UID from the namespace range.  Set an int on vanilla Kubernetes,
        # where runAsNonRoot without a concrete UID rejects root-default images.
        "run_as_user": None,
        "fs_group": None,
        "seccomp_profile": "RuntimeDefault",   # "" -> omit
        "allow_privilege_escalation": False,
        "drop_capabilities": ["ALL"],
        "read_only_root_filesystem": False,
    },
    # --- resources (k8s quantity strings; "" -> derive from terminal.container_*)
    "resources": {
        "requests": {"cpu": "", "memory": ""},
        "limits": {"cpu": "", "memory": "", "ephemeral_storage": ""},
    },
    # --- sandbox provisioner only -------------------------------------
    "sandbox": {
        "api_group": "agents.x-k8s.io",
        "api_version": "v1beta1",
        "template_ref": "",
        "use_claim": False,
        "ttl_seconds": None,
        "ready_condition": "Ready",
        "spec_overrides": {},
    },
}

VALID_PROVISIONERS = ("direct", "sandbox")


def _deep_merge(base: dict, overlay: Any) -> dict:
    """Recursively merge *overlay* onto a copy of *base* (lists replace)."""
    out = deepcopy(base)
    if not isinstance(overlay, dict):
        return out
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = deepcopy(value)
    return out


def _is_named_object_list(value: Any) -> bool:
    """True for a Kubernetes ``name``-keyed list (containers, volumes, env...)."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, dict) and item.get("name") for item in value)
    )


def strategic_merge(base: dict, overlay: Any) -> dict:
    """Merge *overlay* onto *base* the way a strategic-merge patch does.

    ``pod_template_overrides`` is documented as a strategic-merge patch, and
    the natural thing to write is::

        pod_template_overrides:
          spec:
            containers:
              - name: workspace
                env: [...]

    A plain deep merge replaces the whole ``containers`` list, silently
    dropping ``image``/``command``/``volumeMounts``/``securityContext`` and
    leaving a pod that never becomes Ready.  So lists whose elements are all
    dicts with a ``name`` merge element-wise on that key.  Every other list
    (tolerations, capabilities.drop, command, args) replaces wholesale, as it
    does upstream.

    Fidelity caveat — ``name`` is used for EVERY such list, which is not what
    the API server does for all of them:

    * MATCHES upstream for ``containers``, ``initContainers``, ``volumes``,
      ``env`` and ``imagePullSecrets``, whose ``patchMergeKey`` really is
      ``name`` (``tolerations`` has no merge key upstream and replaces here
      too, which also matches);
    * DIVERGES for ``volumeMounts`` (upstream ``patchMergeKey: mountPath``) and
      ``ports`` (upstream ``containerPort``).  An override that adds a
      volumeMount with a NEW name but an EXISTING mountPath appends here and
      would replace under a real ``kubectl patch``, giving a duplicate-mountPath
      pod the kubelet rejects.

    The divergence is deliberate (one keying rule is predictable and needs no
    per-field table) but it is a divergence, so ``pod_template_overrides`` is
    "strategic-merge shaped", not byte-for-byte strategic merge.
    """
    out = deepcopy(base)
    if not isinstance(overlay, dict):
        return out
    for key, value in overlay.items():
        current = out.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = strategic_merge(current, value)
        elif _is_named_object_list(value) and _is_named_object_list(current):
            merged = [deepcopy(item) for item in current]
            index = {item["name"]: pos for pos, item in enumerate(merged)}
            for item in value:
                name = item["name"]
                if name in index:
                    merged[index[name]] = strategic_merge(merged[index[name]], item)
                else:
                    merged.append(deepcopy(item))
            out[key] = merged
        else:
            out[key] = deepcopy(value)
    return out


def _dig_dict(obj: Any, *path: str) -> dict:
    """Walk *path* through nested mappings, returning ``{}`` when absent."""
    for key in path:
        if not isinstance(obj, dict):
            return {}
        obj = obj.get(key)
    return obj if isinstance(obj, dict) else {}


def _lookup(obj: Any, path: "tuple[str, ...]") -> "tuple[bool, Any]":
    """Return ``(present, value)`` for *path* — distinguishing absent from null."""
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return False, None
        obj = obj[key]
    return True, obj


def _pod_template_override_layers(kcfg: dict) -> "list[tuple[str, dict]]":
    """EVERY override layer applied to the pod template, in application order.

    THE single source of truth for "what can still change the pod after the
    builder has run".  :func:`build_pod_template` applies exactly these layers
    and :func:`unhardened_reasons` judges the result, so a new layer added here
    is automatically both rendered and judged — and one added anywhere else is
    caught by ``SandboxProvisioner.sandbox_manifest``, which re-asserts the
    rendered template over its own merge output rather than producing a second
    one, and by
    ``test_the_judged_pod_template_is_the_submitted_pod_template``.

    Round 2 shipped ``sandbox.spec_overrides`` as a SECOND override layer that
    only the sandbox manifest builder applied: every security control that
    inspected or stamped the builder's output (the hardening judge, the
    managed-by re-stamp, the reserved-key validation) was bypassable by moving
    the same YAML from ``pod_template_overrides`` into
    ``sandbox.spec_overrides.podTemplate``.
    """
    layers: list[tuple[str, dict]] = []
    overrides = kcfg.get("pod_template_overrides")
    if isinstance(overrides, dict) and overrides:
        layers.append(("pod_template_overrides", overrides))
    if str(kcfg.get("provisioner") or "").strip().lower() == "sandbox":
        spec_overrides = (kcfg.get("sandbox") or {}).get("spec_overrides")
        if isinstance(spec_overrides, dict) and "podTemplate" in spec_overrides:
            layers.append(
                ("sandbox.spec_overrides.podTemplate",
                 spec_overrides["podTemplate"]),
            )
    return layers


def _is_rfc1123_name(value: str) -> bool:
    """RFC-1123 label check INCLUDING the 63-character bound.

    The bound is not cosmetic: without it the validator (and ``hermes doctor``)
    passed a 70-character container_name that the API server then rejected at
    create time, with an error the operator had to decode themselves.
    """
    return bool(value) and len(value) <= 63 and bool(_RFC1123_RE.match(value))


def merge_kubernetes_config(user_config: Any) -> dict:
    """Merge a (possibly partial) ``terminal.kubernetes`` block over defaults.

    Two of the three config→env bridges (``cli.py`` and ``gateway/run.py``) do
    NOT deep-merge ``DEFAULT_CONFIG`` before bridging, so a user who sets only
    ``terminal.kubernetes.namespace`` produces ``{"namespace": "..."}`` here.
    Every consumer must therefore go through this function rather than indexing
    the parsed payload directly.
    """
    return _deep_merge(DEFAULT_KUBERNETES_CONFIG, user_config)


def validate_kubernetes_config(kcfg: dict) -> list[str]:
    """Return a list of human-readable config problems (empty when valid).

    Cheap, offline checks only — used by ``hermes doctor`` and by the backend
    itself before it ever talks to a cluster.
    """
    problems: list[str] = []
    provisioner = str(kcfg.get("provisioner") or "").strip().lower()
    if provisioner not in VALID_PROVISIONERS:
        problems.append(
            f"terminal.kubernetes.provisioner must be one of "
            f"{', '.join(VALID_PROVISIONERS)} (got {provisioner!r})"
        )

    pull_policy = str(kcfg.get("image_pull_policy") or "")
    if pull_policy and pull_policy not in {"Always", "IfNotPresent", "Never"}:
        problems.append(
            "terminal.kubernetes.image_pull_policy must be Always, IfNotPresent "
            f"or Never (got {pull_policy!r})"
        )

    sc = kcfg.get("security_context") or {}
    if sc.get("run_as_non_root") and sc.get("run_as_user") == 0:
        problems.append(
            "terminal.kubernetes.security_context: run_as_non_root=true is "
            "incompatible with run_as_user=0 (the kubelet rejects the pod)"
        )

    for section in ("requests", "limits"):
        for field, value in (kcfg.get("resources", {}).get(section) or {}).items():
            if value and not _QUANTITY_RE.match(str(value)):
                problems.append(
                    f"terminal.kubernetes.resources.{section}.{field}={value!r} "
                    "is not a valid Kubernetes quantity (e.g. 500m, 2Gi)"
                )
    vol_size = (kcfg.get("volume") or {}).get("size")
    if vol_size and not _QUANTITY_RE.match(str(vol_size)):
        problems.append(
            f"terminal.kubernetes.volume.size={vol_size!r} is not a valid "
            "Kubernetes quantity (e.g. 50Gi)"
        )

    for field in ("namespace", "service_account", "runtime_class_name",
                  "container_name"):
        value = str(kcfg.get(field) or "")
        if value and not _is_rfc1123_name(value):
            problems.append(
                f"terminal.kubernetes.{field}={value!r} is not a valid "
                "RFC-1123 name (lowercase alphanumeric, '-', max 63 chars)"
            )
    claim_name = str((kcfg.get("volume") or {}).get("claim_name") or "")
    if claim_name and not _is_rfc1123_name(claim_name):
        problems.append(
            f"terminal.kubernetes.volume.claim_name={claim_name!r} is not a "
            "valid RFC-1123 name (lowercase alphanumeric, '-', max 63 chars)"
        )

    # The managed-by label is the selector for the shipped NetworkPolicy and
    # ValidatingAdmissionPolicy and for session-pod adoption. Overriding it
    # silently drops the pod out of all three, so it is reserved on EVERY
    # override layer (see pod_template_override_layers).
    managed_by_key = next(iter(MANAGED_BY_LABEL))
    if managed_by_key in (kcfg.get("labels") or {}):
        problems.append(
            f"terminal.kubernetes.labels: {managed_by_key!r} is reserved "
            "(k8s/networkpolicy.yaml, k8s/validatingadmissionpolicy.yaml and "
            "session-pod adoption all select on it); remove it"
        )
    for layer_name, overlay in _pod_template_override_layers(kcfg):
        if managed_by_key in _dig_dict(overlay, "metadata", "labels"):
            problems.append(
                f"terminal.kubernetes.{layer_name}.metadata.labels: "
                f"{managed_by_key!r} is reserved and cannot be overridden"
            )
        # A scalar/null where the renderer expects a mapping used to surface as
        # a raw AttributeError out of manifest construction while this
        # validator — which exists to catch exactly that — reported no problem.
        for path in (("metadata",), ("metadata", "labels"), ("spec",)):
            present, node = _lookup(overlay, path)
            if present and not isinstance(node, dict):
                problems.append(
                    f"terminal.kubernetes.{layer_name}.{'.'.join(path)} must be "
                    f"a mapping (got {'null' if node is None else type(node).__name__})"
                )

    sb = kcfg.get("sandbox") or {}
    if sb.get("use_claim") and not str(sb.get("template_ref") or "").strip():
        problems.append(
            "terminal.kubernetes.sandbox.use_claim requires "
            "terminal.kubernetes.sandbox.template_ref (a claim with no "
            "SandboxTemplate has nothing to bind)"
        )
    return problems


_QUANTITY_RE = re.compile(r"^\d+(\.\d+)?(m|[KMGTPE]i?)?$")
_RFC1123_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


# ---------------------------------------------------------------------------
# Small value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PodRef:
    """Coordinates for exec-ing into a session pod."""

    namespace: str
    pod_name: str
    container: str


@dataclass(frozen=True)
class Resources:
    """Fallback sizing derived from the shared ``terminal.container_*`` keys.

    ``cpu`` is whole cores (fractional allowed — 0.5 renders as ``500m``),
    ``memory_mib`` / ``disk_mib`` are MiB.  Explicit
    ``terminal.kubernetes.resources.*`` quantity strings win over these.
    """

    cpu: float = 1
    memory_mib: int = 5120
    disk_mib: int = 51200


def _cpu_quantity(cpu: float) -> str:
    """Render a core count as a Kubernetes CPU quantity."""
    try:
        value = float(cpu)
    except (TypeError, ValueError):
        return "1"
    if value <= 0:
        return "1"
    if value == int(value):
        return str(int(value))
    return f"{int(round(value * 1000))}m"


def sanitize_name(raw: str, *, max_len: int = 40) -> str:
    """Slugify *raw* into a safe DNS-1123 label fragment.

    Task ids from RL/benchmark harnesses and gateway sessions can contain
    uppercase, ``_`` and ``:``, which the API server rejects with a confusing
    422.  Truncated values get a short hash suffix so two long ids that share a
    prefix cannot collide.
    """
    slug = re.sub(r"[^a-z0-9-]+", "-", str(raw or "default").lower()).strip("-")
    if not slug:
        slug = "default"
    # Compared against the RAW input, not a lowercased copy: comparing against
    # `raw.lower()` skipped the hash for case-only normalisation, so "Default"
    # and "default" (two distinct RL/benchmark task ids) landed on the same pod
    # AND the same PVC and silently shared one credential-file sync.
    if len(slug) > max_len or slug != str(raw or ""):
        digest = hashlib.sha1(str(raw or "default").encode("utf-8")).hexdigest()[:6]
        slug = f"{slug[: max_len - 7].strip('-') or 'task'}-{digest}"
    return slug


def _instance_discriminator(owner_pod_uid: str = "") -> str:
    """Stable per-agent-instance suffix, so two agents never share a pod name.

    ``_resolve_container_task_id`` collapses almost every session to
    ``"default"``, so without a discriminator two Hermes pods in one namespace
    both target ``hermes-ws-default``: the second create 409s, gets silently
    "reused", and each agent then execs into (and later deletes) the other's
    workspace.  Derived from the agent pod's UID in-cluster and from the
    hostname otherwise, so it is stable across restarts and persistent
    workspaces still resume.
    """
    seed = owner_pod_uid or socket.gethostname() or "hermes"
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Client / namespace resolution
# ---------------------------------------------------------------------------


def _ensure_sdk() -> None:
    """Lazily install the kubernetes client, mirroring the Daytona pattern."""
    try:
        from tools.lazy_deps import ensure as _lazy_ensure

        _lazy_ensure("terminal.kubernetes", prompt=False)
    except ImportError:
        pass
    except Exception as exc:  # FeatureUnavailable etc.
        # terminal_tool catches ImportError from _create_environment and
        # returns a clean "Terminal tool disabled" payload instead of a
        # traceback, so convert.
        raise ImportError(str(exc))


def in_cluster() -> bool:
    """True when the projected ServiceAccount token is present."""
    return os.path.exists(_SA_TOKEN_FILE) and os.path.exists(_SA_NAMESPACE_FILE)


def load_kubernetes_apis(kcfg: dict):
    """Return ``(CoreV1Api, CustomObjectsApi)`` for the configured cluster.

    In-cluster ServiceAccount first (the deployment topology this backend is
    built for), then an explicit ``terminal.kubernetes.kubeconfig`` path, then
    the ambient ``KUBECONFIG``/``~/.kube/config`` for out-of-cluster dev.
    """
    _ensure_sdk()
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config

    kubeconfig = str(kcfg.get("kubeconfig") or "").strip()
    context = str(kcfg.get("context") or "").strip() or None

    loaded = False
    if not kubeconfig:
        try:
            k8s_config.load_incluster_config()
            loaded = True
        except Exception:
            loaded = False
    if not loaded:
        try:
            k8s_config.load_kube_config(
                config_file=os.path.expanduser(kubeconfig) or None,
                context=context,
            )
        except Exception as exc:
            raise RuntimeError(
                "kubernetes backend: could not authenticate to a cluster. "
                "Tried the in-cluster ServiceAccount, then "
                f"terminal.kubernetes.kubeconfig={kubeconfig or '(unset)'}, then "
                f"KUBECONFIG/~/.kube/config. Underlying error: {exc}"
            ) from exc

    return k8s_client.CoreV1Api(), k8s_client.CustomObjectsApi()


def resolve_namespace(kcfg: dict) -> str:
    """Resolve the namespace session pods are created in.

    ``terminal.kubernetes.namespace`` → the projected ServiceAccount namespace
    file.  There is deliberately no env-var branch: in-cluster the kubelet
    already projects the namespace, and out-of-cluster the config key covers
    it, so a third source would only add a way to disagree.
    """
    namespace = str(kcfg.get("namespace") or "").strip()
    if namespace:
        return namespace
    try:
        with open(_SA_NAMESPACE_FILE, encoding="utf-8") as handle:
            namespace = handle.read().strip()
    except OSError:
        namespace = ""
    if not namespace:
        raise ValueError(
            "kubernetes backend: could not resolve a namespace. Set "
            "terminal.kubernetes.namespace in config.yaml, or run Hermes "
            "in-cluster so the ServiceAccount namespace is projected."
        )
    return namespace


def resolve_owner_reference(core_api, namespace: str, kcfg: dict) -> Optional[dict]:
    """Build the ownerReference that GCs session pods when the agent pod dies.

    Only emitted when the agent's own pod identity is resolvable — Kubernetes
    rejects an ownerReference with an empty name/uid, and out-of-cluster dev
    runs have no agent pod to GC against.  Identity comes from the downward API
    when the Deployment injects it, otherwise from a self-lookup on the pod's
    hostname (which is the pod name in-cluster).
    """
    if str(kcfg.get("owner_reference") or "auto").strip().lower() == "off":
        return None

    name = (os.getenv("HERMES_POD_NAME") or "").strip()
    uid = (os.getenv("HERMES_POD_UID") or "").strip()
    if not (name and uid):
        if not in_cluster() or core_api is None:
            return None
        try:
            pod = core_api.read_namespaced_pod(
                name=socket.gethostname(), namespace=namespace
            )
            name = getattr(pod.metadata, "name", "") or ""
            uid = getattr(pod.metadata, "uid", "") or ""
        except Exception as exc:
            # Not cosmetic: with no ownerReference the session pod loses its
            # only garbage-collection path, so say so out loud.
            logger.warning(
                "k8s: could not resolve the agent pod identity (%s: %s); session "
                "pods will carry no ownerReference and will NOT be garbage "
                "collected when this agent dies. Set HERMES_POD_NAME/"
                "HERMES_POD_UID from the downward API, or grant 'get pods'.",
                type(exc).__name__, exc,
            )
            return None
    if not (name and uid):
        logger.warning(
            "k8s: agent pod identity incomplete (name=%r uid=%r); session pods "
            "will carry no ownerReference.", name, uid,
        )
        return None
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "name": name,
        "uid": uid,
        # Not controller-owned, and blocking deletion of the AGENT pod on a
        # session pod would be a foot-gun.
        "controller": False,
        "blockOwnerDeletion": False,
    }


# ---------------------------------------------------------------------------
# Pod template construction (shared by both provisioners)
# ---------------------------------------------------------------------------


def container_name(kcfg: dict) -> str:
    """Name of the container this backend builds and prefers to exec into."""
    return str(kcfg.get("container_name") or "").strip() or WORKSPACE_CONTAINER_NAME


def build_pod_template(
    kcfg: dict,
    *,
    persistent: bool,
    image: str,
    resources: Resources,
    pvc_name: str,
    labels: Optional[dict] = None,
    owned: bool = True,
) -> dict:
    """Render THE final pod template — the artifact that reaches the API server.

    This is the ONE function that produces a pod template.  ``DirectProvisioner``
    posts it as a ``Pod``; ``SandboxProvisioner`` posts it as
    ``Sandbox.spec.podTemplate``.  Every override layer
    (:func:`_pod_template_override_layers`) is applied HERE, so what
    :func:`unhardened_reasons` judges is byte-for-byte what gets submitted —
    there is no later layer for a security control to miss.

    *owned* is False when no ownerReference could be resolved — the one case
    where a persistent pod also needs the activeDeadlineSeconds backstop,
    because nothing else would ever reap it.
    """
    mount_path = str(kcfg.get("mount_path") or "/workspace")
    sc = kcfg.get("security_context") or {}

    pod_security: dict[str, Any] = {}
    if sc.get("run_as_non_root", True):
        pod_security["runAsNonRoot"] = True
    # runAsUser/fsGroup are OMITTED by default: OpenShift's restricted-v2 SCC
    # assigns both from the namespace's uid/supplemental-group range, and a
    # hardcoded 1000 is outside that range (the pod is rejected outright).
    # On vanilla Kubernetes set security_context.run_as_user so runAsNonRoot
    # can schedule a root-default image, and fs_group so the non-root uid can
    # write the emptyDir/PVC (they mount root:root 0755 otherwise).
    # `is not None`, not truthiness: 0 is a legitimate (if unwise) value and
    # must reach the manifest rather than being silently dropped.
    if sc.get("run_as_user") is not None:
        pod_security["runAsUser"] = int(sc["run_as_user"])
    if sc.get("fs_group") is not None:
        pod_security["fsGroup"] = int(sc["fs_group"])
    seccomp = str(sc.get("seccomp_profile") or "").strip()
    if seccomp:
        pod_security["seccompProfile"] = {"type": seccomp}

    container_security: dict[str, Any] = {
        "allowPrivilegeEscalation": bool(sc.get("allow_privilege_escalation", False)),
        "capabilities": {"drop": list(sc.get("drop_capabilities") or ["ALL"])},
    }
    if sc.get("run_as_non_root", True):
        container_security["runAsNonRoot"] = True
    if sc.get("run_as_user") is not None:
        container_security["runAsUser"] = int(sc["run_as_user"])
    if sc.get("read_only_root_filesystem"):
        container_security["readOnlyRootFilesystem"] = True

    res_cfg = kcfg.get("resources") or {}
    requests = {
        "cpu": str((res_cfg.get("requests") or {}).get("cpu") or "")
        or _cpu_quantity(resources.cpu),
        "memory": str((res_cfg.get("requests") or {}).get("memory") or "")
        or f"{resources.memory_mib}Mi",
    }
    limits: dict[str, str] = {}
    for key, field in (("cpu", "cpu"), ("memory", "memory"),
                       ("ephemeral-storage", "ephemeral_storage")):
        value = str((res_cfg.get("limits") or {}).get(field) or "").strip()
        if value:
            limits[key] = value
    container_resources: dict[str, Any] = {"requests": requests}
    if limits:
        container_resources["limits"] = limits

    container: dict[str, Any] = {
        "name": container_name(kcfg),
        "image": image,
        # Keep the pod alive so we can exec into it repeatedly.
        "command": ["sleep", "infinity"],
        "workingDir": mount_path,
        "volumeMounts": [{"name": "workspace", "mountPath": mount_path}],
        "securityContext": container_security,
        "resources": container_resources,
    }
    pull_policy = str(kcfg.get("image_pull_policy") or "").strip()
    if pull_policy:
        container["imagePullPolicy"] = pull_policy
    env_pairs = kcfg.get("env") or {}
    if env_pairs:
        container["env"] = [
            {"name": str(k), "value": str(v)} for k, v in sorted(env_pairs.items())
        ]
    if sc.get("read_only_root_filesystem"):
        # init_session() writes its env snapshot under /tmp; a read-only root
        # without a writable /tmp silently breaks cwd/env tracking.
        container["volumeMounts"].append({"name": "tmp", "mountPath": "/tmp"})

    if persistent:
        workspace_volume = {
            "name": "workspace",
            "persistentVolumeClaim": {"claimName": pvc_name},
        }
    else:
        workspace_volume = {"name": "workspace", "emptyDir": {}}
    volumes = [workspace_volume]
    if sc.get("read_only_root_filesystem"):
        volumes.append({"name": "tmp", "emptyDir": {}})

    spec: dict[str, Any] = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": bool(
            kcfg.get("automount_service_account_token", False)
        ),
        "serviceAccountName": str(kcfg.get("service_account") or "default"),
        "enableServiceLinks": False,
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        # `sleep infinity` as PID 1 ignores SIGTERM, so the default 30s grace
        # would stall every teardown (which is on the interrupt path).
        "terminationGracePeriodSeconds": 1,
        "securityContext": pod_security,
        "containers": [container],
        "volumes": volumes,
    }

    pull_secrets = [
        {"name": str(n)} for n in (kcfg.get("image_pull_secrets") or []) if n
    ]
    if pull_secrets:
        spec["imagePullSecrets"] = pull_secrets
    runtime_class = str(kcfg.get("runtime_class_name") or "").strip()
    if runtime_class:
        spec["runtimeClassName"] = runtime_class
    if kcfg.get("node_selector"):
        spec["nodeSelector"] = dict(kcfg["node_selector"])
    if kcfg.get("tolerations"):
        spec["tolerations"] = deepcopy(kcfg["tolerations"])
    deadline = int(kcfg.get("active_deadline_seconds") or 0)
    if deadline > 0 and (not persistent or not owned):
        # Hard lifetime ceiling (leak backstop). Normally ephemeral-only — a
        # persistent workspace is meant to be long-lived — but a persistent pod
        # with no ownerReference has no reaper at all, and its PVC (the durable
        # half) outlives the pod either way.
        spec["activeDeadlineSeconds"] = deadline

    metadata: dict[str, Any] = {
        # MANAGED_BY_LABEL goes LAST: the shipped NetworkPolicy, the
        # ValidatingAdmissionPolicy and pod adoption all select on it, so user
        # labels must not be able to strip the pod out of them.
        "labels": {**(kcfg.get("labels") or {}), **(labels or {}), **MANAGED_BY_LABEL},
    }
    if kcfg.get("annotations"):
        metadata["annotations"] = dict(kcfg["annotations"])

    template = {"metadata": metadata, "spec": spec}
    for _layer_name, overlay in _pod_template_override_layers(kcfg):
        template = strategic_merge(template, overlay)
    # Re-stamp after the LAST override layer, for the same reason, and
    # tolerating a layer that replaced metadata/labels with a scalar or null.
    return _stamp_managed_by(template)


def _stamp_managed_by(template: Any) -> dict:
    """Force ``MANAGED_BY_LABEL`` onto *template*'s metadata.labels.

    Runs after the last override layer.  Written defensively because
    ``strategic_merge`` faithfully replaces a dict with whatever the overlay
    supplies: ``metadata: null`` or ``labels: 7`` used to raise a bare
    ``AttributeError`` out of manifest construction.  The label is not
    negotiable — it is the selector for k8s/networkpolicy.yaml and for the
    ValidatingAdmissionPolicy matchCondition — so a malformed layer loses its
    metadata, it does not lose the label.
    """
    if not isinstance(template, dict):
        template = {}
    metadata = template.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        template["metadata"] = metadata
    labels = metadata.get("labels")
    if not isinstance(labels, dict):
        labels = {}
        metadata["labels"] = labels
    labels.update(MANAGED_BY_LABEL)
    return template


# ---------------------------------------------------------------------------
# Trust evaluation (feeds the approval layer)
# ---------------------------------------------------------------------------

# Volume types a throwaway session pod may use. Anything else (hostPath,
# secret, projected, csi, nfs, persistentVolumeClaim, ...) either reaches host
# state or injects credentials, so the pod stops being a throwaway sandbox.
_SANDBOX_VOLUME_TYPES = frozenset({"emptyDir"})


def _container_pulls_in_a_secret(container: dict) -> bool:
    """True when a container reads a Secret through env rather than a volume."""
    for source in (container.get("envFrom") or []):
        if isinstance(source, dict) and source.get("secretRef"):
            return True
    for entry in (container.get("env") or []):
        if not isinstance(entry, dict):
            continue
        if _dig_dict(entry, "valueFrom").get("secretKeyRef"):
            return True
    return False


def unhardened_reasons(kcfg: dict) -> list[str]:
    """Why the pod this config SUBMITS is not a throwaway sandbox (empty = it is).

    ``tools.approval`` skips the dangerous-command guards for backends whose
    workload cannot touch anything durable.  The justification for putting
    ``kubernetes`` on that path is an ephemeral, non-root, drop-ALL,
    token-less, secret-free, emptyDir pod.

    This is the ONE judge, and it judges the FINAL rendered pod template — the
    exact artifact :func:`build_pod_template` hands to whichever provisioner is
    selected, after every override layer in
    :func:`_pod_template_override_layers`.  Judging the builder's output while a
    provisioner applied a further layer is what let ``provisioner: sandbox``
    keep the approval skip with ``hostPID``, ``hostNetwork``, a hostPath ``/``
    volume and a privileged container, purely by writing them under
    ``sandbox.spec_overrides.podTemplate`` instead of
    ``pod_template_overrides``.

    When the pod shape is NOT authored here at all (``sandbox.template_ref`` /
    ``sandbox.use_claim``: agent-sandbox-operator builds the pod from a
    SandboxTemplate that Hermes never reads) there is nothing to judge, and
    "cannot be evaluated" must never read as "hardened".

    Any exception fails closed — see ``_kubernetes_has_host_access``, which
    also treats a raise as untrusted.
    """
    reasons: list[str] = []
    if kcfg.get("persistent"):
        # `rm -rf /workspace` would destroy a PVC the user asked to keep.
        reasons.append("persistent: true (durable PVC workspace)")

    if str(kcfg.get("provisioner") or "").strip().lower() == "sandbox":
        sb = kcfg.get("sandbox") or {}
        if str(sb.get("template_ref") or "").strip() or sb.get("use_claim"):
            # Unconditional: the operator's SandboxTemplate supplies the whole
            # pod shape and Hermes never reads it, so no property below can be
            # established. Unknown is not hardened.
            reasons.append(
                "sandbox.template_ref/use_claim: the pod shape comes from a "
                "SandboxTemplate this backend never reads and cannot evaluate"
            )
            return reasons

    try:
        template = build_pod_template(
            kcfg,
            persistent=bool(kcfg.get("persistent")),
            image=str(kcfg.get("image") or ""),
            resources=Resources(),
            pvc_name="hermes-ws",
        )
    except Exception as exc:  # unrenderable config -> assume untrusted
        return reasons + [f"pod template could not be rendered ({exc})"]

    spec = template.get("spec")
    if not isinstance(spec, dict):
        return reasons + ["pod template has no spec mapping"]
    if (spec.get("securityContext") or {}).get("runAsNonRoot") is not True:
        reasons.append("pod securityContext.runAsNonRoot is not true")
    if spec.get("automountServiceAccountToken") is not False:
        reasons.append("automountServiceAccountToken is not false")
    expected_sa = str(kcfg.get("service_account") or "default")
    if str(spec.get("serviceAccountName") or "") != expected_sa:
        reasons.append(
            f"serviceAccountName {spec.get('serviceAccountName')!r} is not the "
            f"configured {expected_sa!r}"
        )
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(key):
            reasons.append(f"{key} is enabled")

    containers: list[Any] = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        containers.extend(spec.get(field) or [])
    if not containers:
        reasons.append("pod template declares no containers")
    for entry in containers:
        if not isinstance(entry, dict):
            reasons.append("a container entry is not a mapping")
            continue
        name = entry.get("name", "?")
        csc = entry.get("securityContext") or {}
        if csc.get("privileged"):
            reasons.append(f"container {name} is privileged")
        if csc.get("allowPrivilegeEscalation") is not False:
            reasons.append(f"container {name} allows privilege escalation")
        if csc.get("runAsNonRoot") is False or csc.get("runAsUser") == 0:
            reasons.append(f"container {name} may run as root")
        capabilities = csc.get("capabilities") or {}
        drops = [str(c).upper() for c in (capabilities.get("drop") or [])]
        if "ALL" not in drops:
            reasons.append(f"container {name} does not drop ALL capabilities")
        if capabilities.get("add"):
            reasons.append(
                f"container {name} adds capabilities {list(capabilities['add'])}"
            )
        # Secret VOLUMES are flagged below; env is the same exfiltration
        # surface with none of the visibility, and it is the shape the config
        # docs suggest for provider keys. A pod holding namespace credentials
        # is not a throwaway sandbox, whichever door they came through.
        if _container_pulls_in_a_secret(entry):
            reasons.append(
                f"container {name} pulls a Secret into its environment "
                "(envFrom.secretRef / env[].valueFrom.secretKeyRef)"
            )

    for volume in (spec.get("volumes") or []):
        if not isinstance(volume, dict):
            reasons.append("a volume entry is not a mapping")
            continue
        kinds = [k for k in volume if k != "name"]
        extra = [k for k in kinds if k not in _SANDBOX_VOLUME_TYPES]
        if extra or not kinds:
            reasons.append(
                f"volume {volume.get('name', '?')} is "
                f"{', '.join(extra) or 'untyped'}, not an emptyDir"
            )
    return reasons


# ---------------------------------------------------------------------------
# Provisioners
# ---------------------------------------------------------------------------


class WorkspaceProvisioner(ABC):
    """Creates and destroys the session pod (and its PVC, when persistent)."""

    @abstractmethod
    def ensure(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> PodRef:
        """Create (or resume) the session workspace; return a Ready PodRef."""
        ...

    @abstractmethod
    def destroy(self, pod_ref: PodRef, persistent: bool) -> None:
        """Tear down the session workspace. Keep the PVC iff persistent."""
        ...


class _BaseProvisioner(WorkspaceProvisioner):
    """Shared naming, PVC handling and readiness polling."""

    def __init__(self, kcfg: dict, namespace: str, api=None, owner_reference=None):
        self.kcfg = kcfg
        self.namespace = namespace
        self._api = api  # kubernetes.client.CoreV1Api (None in manifest tests)
        self._owner_reference = owner_reference
        self._instance = _instance_discriminator(
            (owner_reference or {}).get("uid", "")
        )
        self.ready_timeout = int(kcfg.get("ready_timeout_seconds") or 120)

    # -- naming ---------------------------------------------------------
    def workspace_name(self, task_id: str) -> str:
        return f"hermes-ws-{self._instance}-{sanitize_name(task_id)}"

    def pvc_name(self, task_id: str) -> str:
        # Deliberately NOT instance-scoped: a persistent workspace must resume
        # for the same task across agent restarts, and the instance
        # discriminator is derived from the agent pod UID, which changes on
        # every restart.  The consequence is that two Hermes instances in one
        # namespace running the same task id share this claim (ReadWriteOnce:
        # the second pod stays Pending) — set
        # terminal.kubernetes.volume.claim_name to give an instance its own.
        configured = str(
            (self.kcfg.get("volume") or {}).get("claim_name") or ""
        ).strip()
        return configured or f"hermes-ws-{sanitize_name(task_id)}"

    def container_name(self) -> str:
        return container_name(self.kcfg)

    def pick_container(self, pod: Any) -> str:
        """Choose which container of the RECONCILED pod to exec into.

        The configured name is a preference, not a guarantee: with
        ``sandbox.template_ref`` / ``sandbox.use_claim`` the operator builds
        the pod from a SandboxTemplate, and ``pod_template_overrides`` can
        replace ``spec.containers`` outright.  Hardcoding "workspace" makes
        every exec in those modes fail with ``container workspace is not valid
        for pod ...``.
        """
        preferred = self.container_name()
        names: list[str] = []
        for entry in (getattr(getattr(pod, "spec", None), "containers", None) or []):
            name = getattr(entry, "name", None)
            if name is None and isinstance(entry, dict):
                name = entry.get("name")
            if name:
                names.append(str(name))
        if not names or preferred in names:
            return preferred
        logger.info(
            "k8s: pod has no container %r (found %s); exec-ing into %r instead",
            preferred, ", ".join(names), names[0],
        )
        return names[0]

    # -- PVC ------------------------------------------------------------
    def pvc_manifest(self, task_id: str, resources: Resources) -> dict:
        vol = self.kcfg.get("volume") or {}
        size = str(vol.get("size") or "").strip() or f"{resources.disk_mib}Mi"
        spec: dict[str, Any] = {
            "accessModes": list(vol.get("access_modes") or ["ReadWriteOnce"]),
            "resources": {"requests": {"storage": size}},
        }
        storage_class = str(vol.get("storage_class_name") or "").strip()
        if storage_class:
            spec["storageClassName"] = storage_class
        # No ownerRef: a persistent PVC must outlive the agent pod.  The task
        # label is what a reaper (see k8s/README.md) selects on, since nothing
        # in this backend ever deletes these claims.
        return {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": self.pvc_name(task_id),
                "namespace": self.namespace,
                "labels": {
                    **MANAGED_BY_LABEL,
                    "app.kubernetes.io/component": "hermes-workspace",
                    "hermes.nousresearch.com/task": sanitize_name(task_id),
                },
            },
            "spec": spec,
        }

    def _assert_pvc_is_ours(self, pvc, name: str) -> None:
        """Refuse to adopt a PVC this backend did not create.

        Adoption is not free: the claim is mounted at ``mount_path``, which is
        the agent's cwd, and ``KubernetesEnvironment`` immediately syncs its
        credential files into ``<cwd>/.hermes`` — i.e. into this claim, at
        rest, on a volume Hermes never deletes.  Pod adoption was hardened in
        round 2 (``DirectProvisioner._is_ours``); this path had no check at
        all, so a claim someone else created under the conventional name was
        adopted silently.

        The check is the managed-by label, NOT an ownerReference: the claim
        deliberately carries none (it must outlive the agent pod) and is
        deliberately task-scoped rather than instance-scoped, so sharing it
        between Hermes instances running the same task id is the DESIGNED
        behaviour — see ``pvc_name`` and k8s/README.md.  What we can and do
        refuse is a claim that is not a Hermes workspace at all.
        """
        labels = getattr(getattr(pvc, "metadata", None), "labels", None)
        if labels is None and isinstance(pvc, dict):
            labels = _dig_dict(pvc, "metadata").get("labels")
        labels = labels or {}
        managed_by_key, managed_by_value = next(iter(MANAGED_BY_LABEL.items()))
        if labels.get(managed_by_key) != managed_by_value:
            raise RuntimeError(
                f"persistentvolumeclaim {name} already exists and is not a "
                f"Hermes workspace ({managed_by_key}="
                f"{labels.get(managed_by_key)!r}); refusing to mount it. The "
                "agent's credential files are synced into this claim. Set "
                "terminal.kubernetes.volume.claim_name to a name of your own."
            )

    def _ensure_pvc(self, task_id: str, resources: Resources) -> None:
        from kubernetes.client.exceptions import ApiException

        name = self.pvc_name(task_id)
        try:
            existing = self._api.read_namespaced_persistent_volume_claim(
                name=name, namespace=self.namespace
            )
            self._assert_pvc_is_ours(existing, name)
            return
        except ApiException as exc:
            if exc.status != 404:
                raise
        try:
            self._api.create_namespaced_persistent_volume_claim(
                namespace=self.namespace, body=self.pvc_manifest(task_id, resources)
            )
        except ApiException as exc:
            # Lost a create race — the PVC exists, which is what we wanted, but
            # the winner still has to be a Hermes workspace.
            if exc.status != 409:
                raise
            try:
                raced = self._api.read_namespaced_persistent_volume_claim(
                    name=name, namespace=self.namespace
                )
            except Exception as read_exc:
                raise RuntimeError(
                    f"persistentvolumeclaim {name} already exists but could not "
                    f"be read ({read_exc}); refusing to mount it."
                ) from read_exc
            self._assert_pvc_is_ours(raced, name)

    # -- readiness ------------------------------------------------------
    def _pod_failure_detail(self, pod) -> str:
        """Surface *why* a pod isn't Ready instead of a bare timeout."""
        details: list[str] = []
        for status in (getattr(pod.status, "container_statuses", None) or []):
            state = getattr(status, "state", None)
            waiting = getattr(state, "waiting", None) if state else None
            if waiting is not None and getattr(waiting, "reason", None):
                details.append(
                    f"{status.name}: {waiting.reason}"
                    f"{': ' + waiting.message if getattr(waiting, 'message', None) else ''}"
                )
            terminated = getattr(state, "terminated", None) if state else None
            if terminated is not None and getattr(terminated, "reason", None):
                details.append(f"{status.name}: {terminated.reason}")
        for cond in (getattr(pod.status, "conditions", None) or []):
            if cond.status != "True" and getattr(cond, "message", None):
                details.append(f"{cond.type}: {cond.message}")
        return "; ".join(details)

    _FATAL_WAITING_REASONS = frozenset({
        "ImagePullBackOff", "ErrImagePull", "InvalidImageName",
        "CreateContainerConfigError", "CreateContainerError",
    })

    def wait_pod_ready(self, pod_name: str):
        """Block until the pod is Ready, then return it (for container pick)."""
        from kubernetes.client.exceptions import ApiException

        deadline = time.monotonic() + self.ready_timeout
        last_detail = ""
        while time.monotonic() < deadline:
            try:
                pod = self._api.read_namespaced_pod(
                    name=pod_name, namespace=self.namespace
                )
            except ApiException as exc:
                if exc.status != 404:
                    raise
                time.sleep(0.5)
                continue
            conditions = getattr(pod.status, "conditions", None) or []
            ready = any(
                c.type == "Ready" and c.status == "True" for c in conditions
            )
            if pod.status.phase == "Running" and ready:
                return pod
            if pod.status.phase in ("Failed", "Succeeded"):
                raise RuntimeError(
                    f"session pod {pod_name} entered phase {pod.status.phase}. "
                    f"{self._pod_failure_detail(pod)}"
                )
            last_detail = self._pod_failure_detail(pod)
            for status in (getattr(pod.status, "container_statuses", None) or []):
                waiting = getattr(getattr(status, "state", None), "waiting", None)
                reason = getattr(waiting, "reason", None) if waiting else None
                if reason in self._FATAL_WAITING_REASONS:
                    # Fail fast: these never resolve on their own, and burning
                    # the full ready timeout hides the real cause.
                    raise RuntimeError(
                        f"session pod {pod_name} cannot start ({reason}). {last_detail}"
                    )
            time.sleep(0.5)
        raise TimeoutError(
            f"session pod {pod_name} not Ready after {self.ready_timeout}s. "
            f"{last_detail or 'No pod conditions reported.'} "
            "Raise terminal.kubernetes.ready_timeout_seconds if this is a slow "
            "image pull or a kata/sandboxed runtime."
        )

    def _delete_pod(self, namespace: str, pod_name: str) -> None:
        from kubernetes.client.exceptions import ApiException

        try:
            self._api.delete_namespaced_pod(
                name=pod_name, namespace=namespace, grace_period_seconds=0
            )
        except TypeError:
            # Older/mocked clients without the kwarg.
            try:
                self._api.delete_namespaced_pod(name=pod_name, namespace=namespace)
            except ApiException as exc:
                if exc.status != 404:
                    logger.warning("k8s: failed to delete pod %s: %s", pod_name, exc)
        except ApiException as exc:
            if exc.status != 404:
                logger.warning("k8s: failed to delete pod %s: %s", pod_name, exc)


class DirectProvisioner(_BaseProvisioner):
    """Creates session pods/PVCs directly via the Kubernetes core API.

    The pod shape is deliberately constrained: no host namespaces, a no-perms
    ServiceAccount with its token unmounted, ``runAsNonRoot``, drop-ALL
    capabilities, no privilege escalation, ``seccompProfile: RuntimeDefault``.
    The session pod carries an ownerReference to the agent's own pod so it is
    garbage-collected if the agent crashes.
    """

    def pod_manifest(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> dict:
        template = build_pod_template(
            self.kcfg,
            persistent=persistent,
            image=image,
            resources=resources,
            pvc_name=self.pvc_name(task_id),
            owned=self._owner_reference is not None,
        )
        metadata = dict(template["metadata"])
        metadata["name"] = self.workspace_name(task_id)
        metadata["namespace"] = self.namespace
        if self._owner_reference is not None:
            # GC the session pod when the agent pod dies.
            metadata["ownerReferences"] = [dict(self._owner_reference)]
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": metadata,
            "spec": template["spec"],
        }

    def _is_ours(self, pod_name: str) -> bool:
        """True when an existing pod was created by THIS agent instance.

        A 409 on create is only safe to treat as "resume" when the pod is ours;
        otherwise we would silently exec into (and later delete) another
        agent's live workspace.
        """
        from kubernetes.client.exceptions import ApiException

        try:
            pod = self._api.read_namespaced_pod(
                name=pod_name, namespace=self.namespace
            )
        except ApiException:
            return False
        labels = getattr(pod.metadata, "labels", None) or {}
        if labels.get("app.kubernetes.io/managed-by") != "hermes-agent":
            return False
        if self._owner_reference is None:
            # No agent identity to compare against (out-of-cluster dev); the
            # instance discriminator in the name is the only guard we have and
            # it already matched.
            return True
        owners = getattr(pod.metadata, "owner_references", None) or []
        our_uid = self._owner_reference.get("uid")
        # No `or not owners` fallback: an unowned pod carrying our label is
        # exactly what another agent's workspace looks like, and adopting it
        # means uploading our credential files into it and later deleting it.
        # Ownership has to be proved, not assumed.
        return any(getattr(o, "uid", None) == our_uid for o in owners)

    def ensure(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> PodRef:
        from kubernetes.client.exceptions import ApiException

        if persistent:
            self._ensure_pvc(task_id, resources)

        pod_name = self.workspace_name(task_id)
        try:
            self._api.create_namespaced_pod(
                namespace=self.namespace,
                body=self.pod_manifest(task_id, persistent, image, resources),
            )
        except ApiException as exc:
            if exc.status != 409:
                raise
            # 409 = the pod already exists (persistent resume after a soft
            # stop, or a racing session in this same agent).
            if not self._is_ours(pod_name):
                raise RuntimeError(
                    f"session pod {pod_name} already exists and was not created "
                    "by this Hermes instance; refusing to reuse it."
                )

        pod = self.wait_pod_ready(pod_name)
        return PodRef(self.namespace, pod_name, self.pick_container(pod))

    def destroy(self, pod_ref: PodRef, persistent: bool) -> None:
        self._delete_pod(pod_ref.namespace, pod_ref.pod_name)
        # Persistent: keep the PVC so the next session resumes the filesystem.
        # There is deliberately no automatic PVC deletion — see
        # `hermes` docs / k8s/README.md for the reaper story.


class SandboxProvisioner(_BaseProvisioner):
    """Provisions session workspaces as ``Sandbox`` custom resources.

    Creates ``agents.x-k8s.io/v1beta1`` ``Sandbox`` objects (optionally a
    ``SandboxClaim`` against a ``SandboxTemplate``/``SandboxWarmPool``) and lets
    agent-sandbox-operator reconcile the pod.  Exec still happens by exec-ing
    into the resulting pod, so the exec loop is identical to the direct path.

    Security upside: the agent's ServiceAccount needs ``sandboxes`` create/
    delete but does NOT need bare ``pods`` create/delete.
    """

    CLAIM_GROUP = "extensions.agents.x-k8s.io"

    def __init__(self, kcfg: dict, namespace: str, api=None, owner_reference=None,
                 custom_api=None):
        super().__init__(kcfg, namespace, api=api, owner_reference=owner_reference)
        self._custom = custom_api
        sb = kcfg.get("sandbox") or {}
        self.group = str(sb.get("api_group") or "agents.x-k8s.io")
        self.version = str(sb.get("api_version") or "v1beta1")
        self.template_ref = str(sb.get("template_ref") or "").strip()
        self.use_claim = bool(sb.get("use_claim"))
        self.ttl_seconds = sb.get("ttl_seconds")
        self.ready_condition = str(sb.get("ready_condition") or "Ready")
        self.spec_overrides = sb.get("spec_overrides") or {}
        # CR names this provisioner created, so destroy() deletes the right
        # object even when the reconciled pod has a different name.
        self._created_names: set[str] = set()

    # -- manifests ------------------------------------------------------
    def sandbox_manifest(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> dict:
        spec: dict[str, Any] = {}
        pod_template: Optional[dict] = None
        if self.template_ref:
            # The operator's template supplies the pod shape; the shared
            # terminal.kubernetes.* pod keys are intentionally not sent.
            spec["sandboxTemplateRef"] = {"name": self.template_ref}
        else:
            # build_pod_template already applied
            # sandbox.spec_overrides.podTemplate (it is a declared override
            # layer), so this IS the final, judged template.
            pod_template = build_pod_template(
                self.kcfg,
                persistent=persistent,
                image=image,
                resources=resources,
                pvc_name=self.pvc_name(task_id),
                owned=self._owner_reference is not None,
            )
            spec["podTemplate"] = pod_template
        if self.ttl_seconds:
            spec["ttlSeconds"] = int(self.ttl_seconds)
        if self.spec_overrides:
            spec = strategic_merge(spec, self.spec_overrides)
            # Re-assert the rendered template over the merge result. Without
            # this, spec_overrides is a SECOND pod-template layer that the
            # hardening judge and the managed-by re-stamp never see — the root
            # cause of the sandbox-mode bypass. Re-assertion is a no-op for a
            # well-formed config (the layer was already applied above) and
            # makes it structurally impossible for this merge to emit a pod
            # template nothing judged.
            if pod_template is not None:
                spec["podTemplate"] = pod_template
            elif isinstance(spec.get("podTemplate"), dict):
                # template_ref mode: we author no template, so an overlay one
                # is stamped but NOT trusted — unhardened_reasons returns an
                # unconditional reason for template_ref/use_claim.
                spec["podTemplate"] = _stamp_managed_by(spec["podTemplate"])

        metadata: dict[str, Any] = {
            "name": self.workspace_name(task_id),
            "namespace": self.namespace,
            # MANAGED_BY_LABEL last: user labels must not be able to strip it.
            "labels": {**(self.kcfg.get("labels") or {}), **MANAGED_BY_LABEL},
        }
        if self._owner_reference is not None:
            metadata["ownerReferences"] = [dict(self._owner_reference)]
        return {
            "apiVersion": f"{self.group}/{self.version}",
            "kind": "Sandbox",
            "metadata": metadata,
            "spec": spec,
        }

    def claim_manifest(self, task_id: str) -> dict:
        spec: dict[str, Any] = {"sandboxTemplateRef": {"name": self.template_ref}}
        if self.spec_overrides:
            spec = strategic_merge(spec, self.spec_overrides)
        metadata: dict[str, Any] = {
            "name": self.workspace_name(task_id),
            "namespace": self.namespace,
            "labels": dict(MANAGED_BY_LABEL),
        }
        if self._owner_reference is not None:
            metadata["ownerReferences"] = [dict(self._owner_reference)]
        return {
            "apiVersion": f"{self.CLAIM_GROUP}/{self.version}",
            "kind": "SandboxClaim",
            "metadata": metadata,
            "spec": spec,
        }

    # -- helpers --------------------------------------------------------
    def _get_object(self, group: str, plural: str, name: str) -> dict:
        return self._custom.get_namespaced_custom_object(
            group=group, version=self.version, namespace=self.namespace,
            plural=plural, name=name,
        )

    def _create_object(self, group: str, plural: str, body: dict) -> bool:
        """Create the CR. Returns True when it already existed (409)."""
        from kubernetes.client.exceptions import ApiException

        try:
            self._custom.create_namespaced_custom_object(
                group=group, version=self.version, namespace=self.namespace,
                plural=plural, body=body,
            )
        except ApiException as exc:
            if exc.status == 404:
                raise RuntimeError(
                    f"kubernetes backend: {plural}.{group}/{self.version} is not "
                    "served by this cluster. Install agent-sandbox-operator "
                    "(v0.9.0+) or set terminal.kubernetes.provisioner: direct."
                ) from exc
            if exc.status != 409:
                raise
            # Already exists — the caller must prove it is ours before reuse.
            return True
        return False

    def _assert_ours(self, group: str, plural: str, name: str) -> None:
        """Refuse to adopt a pre-existing CR this agent did not create.

        Adoption is not free: ``KubernetesEnvironment.__init__`` immediately
        uploads the agent's credential files into whatever pod the CR points
        at, and ``destroy()`` later deletes it.
        """
        if self._owner_reference is None:
            # Out-of-cluster dev: no agent identity to compare against, so the
            # instance discriminator in the name is the only guard there is.
            return
        try:
            existing = self._get_object(group, plural, name)
        except Exception as exc:
            raise RuntimeError(
                f"{plural[:-1]} {name} already exists but could not be read "
                f"({exc}); refusing to reuse it."
            ) from exc
        owners = _dig_dict(existing, "metadata").get("ownerReferences") or []
        our_uid = self._owner_reference.get("uid")
        if not any(
            isinstance(o, dict) and o.get("uid") == our_uid for o in owners
        ):
            raise RuntimeError(
                f"{plural[:-1]} {name} already exists and was not created by "
                "this Hermes instance; refusing to reuse it."
            )

    @staticmethod
    def _dig(obj: Any, *path: str) -> Any:
        for key in path:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(key)
        return obj

    def _pod_name_from_status(self, sandbox: dict) -> Optional[str]:
        """Read the reconciled pod name straight out of the CR status.

        Pure dict digs, no API calls: this runs on every poll iteration of
        ``_wait_sandbox``.
        """
        status = sandbox.get("status") or {}
        for path in (("podRef", "name"), ("podName",), ("pod", "name"),
                     ("workloadRef", "name")):
            value = self._dig(status, *path)
            if isinstance(value, str) and value:
                return value
        return None

    def _resolve_pod_name(self, sandbox: dict, sandbox_name: str) -> "tuple[str, bool]":
        """Find the pod agent-sandbox-operator reconciled for this Sandbox.

        Status field names differ across operator releases, so probe the known
        shapes, then fall back to a label lookup, then to the convention that
        the pod is named after the Sandbox.  Called ONCE, after readiness: the
        label fallback issues three LISTs, and running it on every 0.5s poll
        meant up to 720 LISTs per session provisioning.

        Returns ``(pod_name, proven)``.  ``proven`` is False for the pure
        name-convention fallback, where nothing tied the pod to our Sandbox —
        the name is guessable by anything that can list pods in the namespace,
        and the next thing that happens is a credential-file upload into it.
        """
        from_status = self._pod_name_from_status(sandbox)
        if from_status:
            return from_status, True

        if self._api is not None:
            for selector in (
                f"{self.group}/sandbox={sandbox_name}",
                f"{self.group}/sandbox-name={sandbox_name}",
                f"sandbox.{self.group}/name={sandbox_name}",
            ):
                try:
                    pods = self._api.list_namespaced_pod(
                        namespace=self.namespace, label_selector=selector
                    )
                except Exception:
                    continue
                items = getattr(pods, "items", None) or []
                if items:
                    return items[0].metadata.name, True
        return sandbox_name, False

    def _wait_sandbox(self, plural: str, name: str, group: str) -> dict:
        """Poll a Sandbox/SandboxClaim until it reports Ready (or times out)."""
        deadline = time.monotonic() + self.ready_timeout
        last = {}
        while time.monotonic() < deadline:
            last = self._get_object(group, plural, name)
            conditions = (last.get("status") or {}).get("conditions") or []
            for cond in conditions:
                if cond.get("type") == self.ready_condition:
                    if str(cond.get("status")) == "True":
                        return last
                    if str(cond.get("reason") or "").endswith("Failed"):
                        raise RuntimeError(
                            f"{plural[:-1]} {name} failed: "
                            f"{cond.get('message') or cond.get('reason')}"
                        )
            # Some operator versions surface the pod before the condition
            # flips; that's good enough because we still gate on pod Ready.
            # Status-only (no LIST): this runs every 0.5s.
            if plural == "sandboxes" and self._pod_name_from_status(last):
                return last
            time.sleep(0.5)
        raise TimeoutError(
            f"{plural[:-1]} {name} did not report {self.ready_condition}=True "
            f"within {self.ready_timeout}s. Last status: {last.get('status')}"
        )

    # -- WorkspaceProvisioner ------------------------------------------
    def ensure(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> PodRef:
        name = self.workspace_name(task_id)
        if persistent and not self.template_ref:
            self._ensure_pvc(task_id, resources)

        if self.use_claim:
            existed = self._create_object(self.CLAIM_GROUP, "sandboxclaims",
                                          self.claim_manifest(task_id))
            if existed:
                self._assert_ours(self.CLAIM_GROUP, "sandboxclaims", name)
            self._created_names.add(name)
            claim = self._wait_sandbox("sandboxclaims", name, self.CLAIM_GROUP)
            sandbox_name = (
                self._dig(claim.get("status") or {}, "sandboxRef", "name")
                or self._dig(claim.get("status") or {}, "sandboxName")
            )
            if not sandbox_name:
                raise RuntimeError(
                    f"SandboxClaim {name} is Ready but reports no bound Sandbox "
                    "(looked at status.sandboxRef.name and status.sandboxName). "
                    "Set terminal.kubernetes.sandbox.use_claim: false, or file "
                    "the operator's actual status shape."
                )
        else:
            existed = self._create_object(
                self.group, "sandboxes",
                self.sandbox_manifest(task_id, persistent, image, resources),
            )
            if existed:
                self._assert_ours(self.group, "sandboxes", name)
            self._created_names.add(name)
            sandbox_name = name

        sandbox = self._wait_sandbox("sandboxes", sandbox_name, self.group)
        pod_name, proven = self._resolve_pod_name(sandbox, sandbox_name)
        pod = self.wait_pod_ready(pod_name)
        self._assert_pod_belongs(pod, pod_name, sandbox, sandbox_name,
                                 proven=proven)
        # The pod was built by the operator (SandboxTemplate/warm pool) or by
        # us (podTemplate), so the container name must come from the pod.
        return PodRef(self.namespace, pod_name, self.pick_container(pod))

    def _assert_pod_belongs(self, pod, pod_name: str, sandbox: dict,
                            sandbox_name: str, *, proven: bool = True) -> None:
        """Refuse to exec into a pod that something else owns.

        Only ``status.podRef`` (and the operator's own labels) tie a pod to our
        Sandbox; the bare name convention is a guess.  If the pod declares
        owners and none of them is our Sandbox we resolved the wrong pod — and
        the very next thing that happens is a credential-file upload into it.

        *proven* is False on the name-convention path, where ownership must be
        POSITIVELY established: an unowned pod under a guessable name is
        exactly what a co-tenant's workload looks like, so "declares no
        owners" stops being a free pass there.
        """
        sandbox_uid = _dig_dict(sandbox, "metadata").get("uid")
        owners = getattr(
            getattr(pod, "metadata", None), "owner_references", None
        ) or []
        if sandbox_uid and any(
            getattr(o, "uid", None) == sandbox_uid for o in owners
        ):
            return
        if not proven:
            raise RuntimeError(
                f"pod {pod_name} was resolved only by name convention from "
                f"sandbox {sandbox_name} and does not carry an ownerReference "
                "to it; refusing to exec into it. The operator's status shape "
                "is unrecognised — file it, or use provisioner: direct."
            )
        if not sandbox_uid or not owners:
            return
        raise RuntimeError(
            f"pod {pod_name} is not owned by sandbox {sandbox_name} "
            f"(uid {sandbox_uid}); refusing to exec into it."
        )

    def destroy(self, pod_ref: PodRef, persistent: bool) -> None:
        from kubernetes.client.exceptions import ApiException

        # Deleting the CR is what tears the pod down — the operator owns it.
        plural, group = (
            ("sandboxclaims", self.CLAIM_GROUP) if self.use_claim
            else ("sandboxes", self.group)
        )
        # The reconciled pod may be named after the CR or resolved via labels,
        # so delete by the CR names we actually created.
        names = list(self._created_names) or [pod_ref.pod_name]
        for name in names:
            try:
                self._custom.delete_namespaced_custom_object(
                    group=group, version=self.version, namespace=self.namespace,
                    plural=plural, name=name,
                )
            except ApiException as exc:
                if exc.status != 404:
                    logger.warning("k8s: failed to delete %s %s: %s", plural, name, exc)
            except Exception as exc:
                logger.warning("k8s: failed to delete %s %s: %s", plural, name, exc)
        self._created_names.clear()


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


class _ExecState:
    """Cancellation state for ONE exec — never for the environment.

    Why per-exec rather than a per-environment execution lock:

    ``BaseEnvironment.execute()`` deliberately has no serialising lock, and the
    handle it hands back is the caller's to ``kill()`` at any time.  Crucially
    ``_wait_for_process`` calls ``_kill_process()`` on an ORDINARY TIMEOUT, not
    only on a user interrupt — so with a single-slot ``_active_stream`` /
    ``_cancelled`` per environment, command A timing out closed whatever stream
    happened to be registered, which under the concurrency this backend already
    documents as routine (gateway/TUI/desktop collapse the terminal to one
    "default" environment; ACP runs each session in its own thread) was command
    B's.  B returned rc=130 "interrupted" with truncated output while A ran on.

    Serialising execs on the environment would fix the race but change the
    contract every other backend implements: local/docker run overlapping
    commands, ``cleanup()`` is called from the idle-reaper thread while an exec
    may be in flight, and a lock held for the full duration of a long command
    would block that teardown (and any concurrent session) for minutes.  Binding
    the state to the exec keeps the contract and makes kill() address exactly
    the command whose handle was killed.

    The environment lock still guards these two fields: the worker thread
    publishes ``stream`` while the caller's thread may be reading it in
    ``cancel()``.
    """

    __slots__ = ("stream", "cancelled")

    def __init__(self) -> None:
        self.stream = None
        self.cancelled = False


class KubernetesEnvironment(BaseEnvironment):
    """Exec-into-session-pod backend. Lifecycle delegated to a provisioner."""

    _stdin_mode = "heredoc"  # no real stdin pipe over the exec channel
    _snapshot_timeout = 60  # pod cold-start can be slow

    def __init__(
        self,
        provisioner: WorkspaceProvisioner,
        task_id: str,
        persistent: bool,
        image: str,
        cwd: str = "/workspace",
        timeout: int = 60,
        resources: "Resources | None" = None,
        api=None,
        sync_files: bool = True,
    ):
        super().__init__(cwd=cwd, timeout=timeout)
        self._provisioner = provisioner
        self._persistent = persistent
        self._task_id = task_id
        self._image = image
        self._resources = resources or Resources()
        self._exec_api = api  # configured CoreV1Api; falls back to a fresh one
        self._lock = threading.Lock()
        self._sync_manager = None
        # Captured once: the agent may `cd` away, but the synced ~/.hermes tree
        # must stay where the first sync put it.
        self._hermes_base = posixpath.join(cwd or "/workspace", ".hermes")

        try:
            self._pod_ref = provisioner.ensure(
                task_id=task_id,
                persistent=persistent,
                image=image,
                resources=self._resources,
            )
        except BaseException:
            # A pod created but never Ready (image pull, quota, SCC denial)
            # would otherwise linger until activeDeadlineSeconds.
            self._pod_ref = None
            self._best_effort_destroy(task_id)
            raise

        if sync_files:
            # Session pods are not bind-mounted, so skills, ~/.hermes
            # credential files and the agent cache have to be pushed in.
            self._sync_manager = FileSyncManager(
                get_files_fn=lambda: iter_sync_files(self._hermes_base),
                upload_fn=self._upload_file,
                delete_fn=self._delete_files,
                bulk_upload_fn=self._bulk_upload,
            )
            try:
                self._sync_manager.sync(force=True)
            except Exception as exc:
                logger.warning("k8s: initial file sync failed: %s", exc)

        self.init_session()

    # -- provisioning ---------------------------------------------------
    def _best_effort_destroy(self, task_id: str) -> None:
        try:
            ref = PodRef(
                getattr(self._provisioner, "namespace", ""),
                self._provisioner.workspace_name(task_id)  # type: ignore[attr-defined]
                if hasattr(self._provisioner, "workspace_name")
                else f"hermes-ws-{task_id}",
                WORKSPACE_CONTAINER_NAME,
            )
            self._provisioner.destroy(ref, self._persistent)
        except Exception:
            pass

    def _ensure_pod(self) -> PodRef:
        """Re-provision after the session pod went away.

        ``cancel()`` no longer destroys the pod, so this is now reached only
        when the pod genuinely disappeared (activeDeadlineSeconds, an operator
        TTL, an eviction).  Without it a single vanished pod bricks the
        session: every later exec 404s and the agent sees empty output with
        rc=1 until the idle reaper evicts the environment.
        """
        with self._lock:
            if self._pod_ref is not None:
                return self._pod_ref
        logger.warning(
            "k8s: session pod for task %s is gone; provisioning a new one — "
            "an ephemeral workspace starts empty again.", self._task_id,
        )
        pod_ref = self._provisioner.ensure(
            task_id=self._task_id,
            persistent=self._persistent,
            image=self._image,
            resources=self._resources,
        )
        with self._lock:
            self._pod_ref = pod_ref
        # A fresh pod has none of the synced files or the env snapshot.
        if self._sync_manager is not None:
            try:
                self._sync_manager.sync(force=True)
            except Exception as exc:
                logger.warning("k8s: file re-sync failed: %s", exc)
        self._snapshot_ready = False
        try:
            self.init_session()
        except Exception as exc:
            logger.debug("k8s: init_session after re-provision failed: %s", exc)
        return pod_ref

    def _before_execute(self) -> None:
        self._ensure_pod()
        if self._sync_manager is not None:
            try:
                self._sync_manager.sync()
            except Exception as exc:
                logger.debug("k8s: file sync skipped: %s", exc)

    # -- raw exec -------------------------------------------------------
    def _exec_client(self):
        """Build a CoreV1Api on a PRIVATE ApiClient, for exactly one exec.

        ``kubernetes.stream.stream()`` does not wrap the client: it
        MONKEYPATCHES ``api_client.request`` with a websocket implementation
        and restores it in a ``finally``.  That is not reentrant.  Two
        overlapping execs on one ApiClient interleave the save/restore and the
        second restore installs the websocket partial *permanently* — after
        which every REST call the provisioner makes (create/read/delete pod)
        tries to open a websocket against a plain HTTPS URL.

        Concurrency is the normal case here: the gateway, TUI and desktop all
        collapse the terminal to one "default" environment, ACP runs each
        session in its own thread, and the idle reaper calls ``cleanup()``
        from a background thread while an exec may be in flight.  So exec
        never touches the shared client — it gets its own, whose only job is
        to build the request.

        Deliberately NOT cached per environment: one cached exec client would
        be shared by exactly the overlapping execs this exists to separate,
        reintroducing the interleaved save/restore.  ``ApiClient.__init__``
        also builds a ``RESTClientObject``/``PoolManager`` that is never used
        here and that ``close()`` does not tear down, so each exec leaves one
        for the GC — no sockets are opened, and correctness beats the churn.
        """
        from kubernetes.client import ApiClient, CoreV1Api

        configuration = getattr(
            getattr(self._exec_api, "api_client", None), "configuration", None
        )
        try:
            api_client = (
                ApiClient(configuration) if configuration is not None else ApiClient()
            )
        except Exception:
            # Never fall back to the SHARED client: that is the bug.
            api_client = ApiClient()
        return CoreV1Api(api_client), api_client

    def _open_stream(self, command: list[str], *, stdin: bool = False):
        from kubernetes.stream import stream as k8s_stream

        ref = self._pod_ref
        if ref is None:
            raise RuntimeError("kubernetes session pod is not provisioned")
        api, api_client = self._exec_client()
        try:
            return k8s_stream(
                api.connect_get_namespaced_pod_exec,
                ref.pod_name,
                ref.namespace,
                container=ref.container,
                command=command,
                stderr=True,
                stdin=stdin,
                stdout=True,
                tty=False,
                _preload_content=False,
            )
        finally:
            # The returned WSClient owns its own websocket; the ApiClient was
            # only needed to build the request, so it can go immediately.
            try:
                api_client.close()
            except Exception:
                pass

    @staticmethod
    def _drain(resp, chunks: list[str]) -> None:
        if resp.peek_stdout():
            chunks.append(resp.read_stdout())
        if resp.peek_stderr():
            chunks.append(resp.read_stderr())

    @staticmethod
    def _safe_returncode(resp) -> "int | None":
        """Read ``WSClient.returncode``, or None when it is UNKNOWN.

        ``returncode`` parses the exec error channel with ``yaml.safe_load``
        and subscripts the result.  On an abnormal disconnect that channel is
        empty, ``safe_load("")`` returns None and the property raises
        ``TypeError``; while the stream is still open it returns None by
        design.  Both mean "we do not know", which is NOT the same as success
        — every caller must treat None as a failure, or a timed-out upload
        gets recorded as a completed one.
        """
        try:
            rc = resp.returncode
        except Exception:
            return None
        return rc if isinstance(rc, int) else None

    def _exec_capture(
        self, command: list[str], *, timeout: int = 60
    ) -> "tuple[str, int | None]":
        """Blocking exec helper used by the file-sync transport.

        Returns ``(output, returncode)`` where a returncode of ``None`` means
        the exit status could not be determined.  Raises ``TimeoutError`` when
        the deadline expires with the stream still open, rather than reading a
        returncode that is None-because-still-running and calling it success.
        """
        resp = self._open_stream(command)
        chunks: list[str] = []
        deadline = time.monotonic() + max(1, timeout)
        timed_out = False
        try:
            while True:
                if not resp.is_open():
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                resp.update(timeout=1)
                self._drain(resp, chunks)
            self._drain(resp, chunks)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        if timed_out:
            raise TimeoutError(
                f"kubernetes exec did not finish within {timeout}s: "
                f"{' '.join(command[:2])}"
            )
        return "".join(chunks), self._safe_returncode(resp)

    def _forget_pod_if_gone(self, exc: Exception) -> None:
        """Drop the pod ref when the API server says the pod is gone.

        activeDeadlineSeconds, an operator TTL or a node eviction can delete
        the session pod underneath us; clearing the ref makes the next command
        re-provision instead of 404-ing forever.
        """
        if getattr(exc, "status", None) != 404 and "not found" not in str(exc).lower():
            return
        with self._lock:
            self._pod_ref = None
        self._snapshot_ready = False

    def _run_bash(
        self, cmd_string: str, *, login: bool = False, timeout: int = 120,
        stdin_data: str | None = None,
    ):
        shell = "bash -l -c" if login else "bash -c"
        command = [*shell.split(), cmd_string]
        # stdin_data is always None here: _stdin_mode = "heredoc" makes the
        # base class fold it into cmd_string before calling us.  The deadline
        # is a backstop under _wait_for_process's own timeout, so a wedged
        # websocket cannot pin the worker thread forever.
        deadline = time.monotonic() + max(1, int(timeout or 0)) + _EXEC_GRACE_SECONDS
        # Cancellation state belongs to THIS exec, not to the environment.
        # Created before the worker thread starts: setting it inside exec_fn
        # (after _open_stream returned) erased a kill() that landed while the
        # stream was still opening.
        state = _ExecState()

        def exec_fn() -> tuple[str, int]:
            chunks: list[str] = []
            resp = None
            timed_out = False
            try:
                resp = self._open_stream(command)
                with self._lock:
                    state.stream = resp
                    already_cancelled = state.cancelled
                if already_cancelled:
                    # kill() landed while the stream was opening.
                    return "", 130
                while resp.is_open():
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    resp.update(timeout=1)
                    self._drain(resp, chunks)
                # Drain any tail buffered by the final update().
                self._drain(resp, chunks)
            except Exception as exc:
                # Return whatever the command produced instead of losing it —
                # _ThreadedProcessHandle only writes to the output pipe on the
                # success path.
                with self._lock:
                    cancelled = state.cancelled
                if not cancelled:
                    logger.warning("k8s: exec stream error: %s", exc)
                    chunks.append(f"\n[kubernetes exec error: {exc}]")
                    self._forget_pod_if_gone(exc)
                return "".join(chunks), (130 if cancelled else 1)
            finally:
                with self._lock:
                    state.stream = None
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass
            with self._lock:
                cancelled = state.cancelled
            if cancelled:
                return "".join(chunks), 130
            if timed_out:
                chunks.append(f"\n[kubernetes: exec exceeded {timeout}s]")
                return "".join(chunks), 124
            rc = self._safe_returncode(resp)
            if rc is None:
                # Unknown != success. Reporting 0 here told the model a failed
                # or half-killed command had succeeded.
                chunks.append("\n[kubernetes: exec status unavailable]")
                return "".join(chunks), 1
            return "".join(chunks), rc

        def cancel() -> None:
            with self._lock:
                state.cancelled = True
                stream = state.stream
            # Closing the websocket is the whole interrupt: the kubelet
            # terminates the exec'd process when the stream goes away.
            #
            # The pod is deliberately NOT destroyed here. _wait_for_process
            # calls _kill_process() on an ORDINARY TIMEOUT as well as on a
            # user interrupt (base.py), so tearing the pod down wiped
            # /workspace — every file the agent had just written — whenever a
            # command ran past its timeout, with no notice to the agent.
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

        return _ThreadedProcessHandle(exec_fn, cancel_fn=cancel)

    # -- file sync transport --------------------------------------------
    def agent_visible_cache_base(self) -> str:
        """Where the agent sees ~/.hermes inside the pod (extension hook used
        by tools/image_generation_tool.py to surface generated artifacts)."""
        return self._hermes_base

    def _bulk_upload(self, files: list[tuple[str, str]]) -> None:
        """Push many files into the pod in one shot.

        The payload travels over the exec STDIN channel, never over argv —
        see :meth:`_stdin_upload`.
        """
        if not files:
            return
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for host_path, remote_path in files:
                try:
                    tar.add(host_path, arcname=remote_path.lstrip("/"))
                except OSError as exc:
                    logger.debug("k8s: skipping %s: %s", host_path, exc)
        payload = buf.getvalue()
        if not payload:
            return

        dirs = unique_parent_dirs(files)
        if dirs:
            out, rc = self._exec_capture(["sh", "-c", quoted_mkdir_command(dirs)])
            if rc != 0:
                raise RuntimeError(
                    "kubernetes file sync: could not create target directories "
                    f"(exit {rc if rc is not None else 'unknown'}): {out.strip()}"
                )

        # encodebytes() wraps at 76 columns, which keeps the remote `sed`
        # working on short lines instead of one multi-MB line.
        self._stdin_upload(base64.encodebytes(payload).decode("ascii"))

    def _stdin_upload(self, encoded: str, *, timeout: int = 120) -> None:
        """Stream a base64 tar into the pod over the exec STDIN channel.

        NEVER over argv.  ``kubernetes/stream/ws_client.py`` appends every
        ``command`` element to the exec request URL as a repeated ``?command=``
        parameter, and kube-apiserver records ``requestURI`` in the audit log
        at Metadata level and above (OpenShift's default policy included).
        ``iter_sync_files()`` starts with ``get_credential_file_mounts()``, so
        an argv transport writes the agent's credential files into the cluster
        audit log and everything downstream of it.  The previous chunked-argv
        fallback did exactly that; it is gone, and a sync that cannot use
        stdin now fails loudly instead of silently downgrading.

        The remote reader terminates on a sentinel line rather than on EOF, so
        this works on clusters that negotiate a pre-v5 subprotocol (no stdin
        half-close).  When ``v5.channel.k8s.io`` IS available the channel is
        half-closed as well, so a remote without ``sed`` still sees EOF.
        """
        from kubernetes.stream.ws_client import STDIN_CHANNEL, V5_CHANNEL_PROTOCOL

        remote = (
            f"sed -n '/^{_SYNC_SENTINEL}$/q;p' | base64 -d | tar xf - -C /"
        )
        resp = self._open_stream(["sh", "-c", remote], stdin=True)
        chunks: list[str] = []
        timed_out = False
        try:
            if not encoded.endswith("\n"):
                encoded += "\n"
            for offset in range(0, len(encoded), _STDIN_CHUNK_BYTES):
                resp.write_stdin(encoded[offset:offset + _STDIN_CHUNK_BYTES])
            resp.write_stdin(f"{_SYNC_SENTINEL}\n")
            if getattr(resp, "subprotocol", None) == V5_CHANNEL_PROTOCOL:
                try:
                    resp.close_channel(STDIN_CHANNEL)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("k8s: stdin half-close unavailable: %s", exc)

            deadline = time.monotonic() + max(1, timeout)
            while True:
                if not resp.is_open():
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                resp.update(timeout=1)
                self._drain(resp, chunks)
            self._drain(resp, chunks)
        finally:
            try:
                resp.close()
            except Exception:
                pass

        if timed_out:
            raise TimeoutError(
                f"kubernetes file sync: tar extract did not finish within "
                f"{timeout}s ({''.join(chunks).strip()})"
            )
        rc = self._safe_returncode(resp)
        if rc != 0:
            # rc None (unknown) lands here too, on purpose: FileSyncManager
            # commits its synced-file state whenever this returns without
            # raising, so "we do not know" must never look like success.
            raise RuntimeError(
                "kubernetes file sync: tar extract failed (exit "
                f"{rc if rc is not None else 'unknown'}): {''.join(chunks).strip()}"
            )

    def _upload_file(self, host_path: str, remote_path: str) -> None:
        self._bulk_upload([(host_path, remote_path)])

    def _delete_files(self, remote_paths: list[str]) -> None:
        if not remote_paths:
            return
        out, rc = self._exec_capture(["sh", "-c", quoted_rm_command(remote_paths)])
        if rc != 0:
            raise RuntimeError(
                "kubernetes file sync: delete failed (exit "
                f"{rc if rc is not None else 'unknown'}): {out.strip()}"
            )

    # -- teardown -------------------------------------------------------
    def cleanup(self):
        with self._lock:
            ref = getattr(self, "_pod_ref", None)
            self._pod_ref = None
        if ref is None:
            return
        try:
            self._provisioner.destroy(ref, self._persistent)
        except Exception as exc:
            logger.warning("k8s: cleanup failed: %s", exc)


__all__ = [
    "DEFAULT_KUBERNETES_CONFIG",
    "VALID_PROVISIONERS",
    "PodRef",
    "Resources",
    "WorkspaceProvisioner",
    "DirectProvisioner",
    "SandboxProvisioner",
    "KubernetesEnvironment",
    "build_pod_template",
    "container_name",
    "strategic_merge",
    "unhardened_reasons",
    "merge_kubernetes_config",
    "validate_kubernetes_config",
    "load_kubernetes_apis",
    "resolve_namespace",
    "resolve_owner_reference",
    "sanitize_name",
    "in_cluster",
]
