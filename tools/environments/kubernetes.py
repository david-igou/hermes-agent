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
import shlex
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
    "namespace": "",                  # "" -> downward API -> SA namespace file
    "kubeconfig": "",                 # out-of-cluster dev only (a path, not a secret)
    "context": "",                    # kubeconfig context; ignored in-cluster
    # --- workload shape (both provisioners) ---------------------------
    "image": "nikolaik/python-nodejs:python3.11-nodejs20",
    "image_pull_policy": "IfNotPresent",
    "image_pull_secrets": [],
    "service_account": "hermes-session-noperms",
    "automount_service_account_token": False,
    "runtime_class_name": "",         # e.g. "kata" for OpenShift sandboxed containers
    "node_selector": {},
    "tolerations": [],
    "labels": {},
    "annotations": {},
    "env": {},                        # literal env vars inside the session container
    "mount_path": "/workspace",
    "pod_template_overrides": {},     # strategic-merge patch, applied last
    # --- workspace lifetime -------------------------------------------
    "persistent": False,
    "volume": {
        "size": "",                   # "" -> {container_disk}Mi
        "storage_class_name": "",     # "" -> omit (cluster default StorageClass)
        "access_modes": ["ReadWriteOnce"],
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

    for field in ("namespace", "service_account", "runtime_class_name"):
        value = str(kcfg.get(field) or "")
        if value and not _RFC1123_RE.match(value):
            problems.append(
                f"terminal.kubernetes.{field}={value!r} is not a valid "
                "RFC-1123 name (lowercase alphanumeric, '-', max 63 chars)"
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
    if len(slug) > max_len or slug != str(raw or "").lower():
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

    ``terminal.kubernetes.namespace`` → ``HERMES_POD_NAMESPACE`` (downward API,
    injected by the Deployment — runtime identity, not user config) → the
    projected ServiceAccount namespace file.
    """
    namespace = str(kcfg.get("namespace") or "").strip()
    if namespace:
        return namespace
    namespace = (os.getenv("HERMES_POD_NAMESPACE") or "").strip()
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
            logger.debug("k8s: could not resolve agent pod identity: %s", exc)
            return None
    if not (name and uid):
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


def build_pod_template(
    kcfg: dict,
    *,
    persistent: bool,
    image: str,
    resources: Resources,
    pvc_name: str,
    labels: Optional[dict] = None,
) -> dict:
    """Build the ``{"metadata": ..., "spec": ...}`` shared by both provisioners.

    ``DirectProvisioner`` posts this as a ``Pod``; ``SandboxProvisioner`` posts
    it as ``Sandbox.spec.podTemplate``.  Keeping one builder is what makes
    flipping ``terminal.kubernetes.provisioner`` a one-line change.
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
    if sc.get("run_as_user"):
        pod_security["runAsUser"] = int(sc["run_as_user"])
    if sc.get("fs_group"):
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
    if sc.get("run_as_user"):
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
        "name": WORKSPACE_CONTAINER_NAME,
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
    if not persistent and deadline > 0:
        # Hard lifetime ceiling for ephemeral pods (leak backstop). Never set
        # for persistent pods — their workspace is meant to be long-lived.
        spec["activeDeadlineSeconds"] = deadline

    metadata: dict[str, Any] = {
        "labels": {**MANAGED_BY_LABEL, **(kcfg.get("labels") or {}), **(labels or {})},
    }
    if kcfg.get("annotations"):
        metadata["annotations"] = dict(kcfg["annotations"])

    template = {"metadata": metadata, "spec": spec}
    overrides = kcfg.get("pod_template_overrides") or {}
    if overrides:
        template = _deep_merge(template, overrides)
    return template


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
        # for the same task across agent restarts.
        return f"hermes-ws-{sanitize_name(task_id)}"

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
        # No ownerRef: a persistent PVC must outlive the agent pod.
        return {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": self.pvc_name(task_id),
                "namespace": self.namespace,
                "labels": dict(MANAGED_BY_LABEL),
            },
            "spec": spec,
        }

    def _ensure_pvc(self, task_id: str, resources: Resources) -> None:
        from kubernetes.client.exceptions import ApiException

        try:
            self._api.read_namespaced_persistent_volume_claim(
                name=self.pvc_name(task_id), namespace=self.namespace
            )
            return
        except ApiException as exc:
            if exc.status != 404:
                raise
        try:
            self._api.create_namespaced_persistent_volume_claim(
                namespace=self.namespace, body=self.pvc_manifest(task_id, resources)
            )
        except ApiException as exc:
            # Lost a create race with a concurrent session — the PVC exists,
            # which is exactly what we wanted.
            if exc.status != 409:
                raise

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

    def wait_pod_ready(self, pod_name: str) -> None:
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
                return
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
        return any(getattr(o, "uid", None) == our_uid for o in owners) or not owners

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

        self.wait_pod_ready(pod_name)
        return PodRef(self.namespace, pod_name, WORKSPACE_CONTAINER_NAME)

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
        if self.template_ref:
            # The operator's template supplies the pod shape; the shared
            # terminal.kubernetes.* pod keys are intentionally not sent.
            spec["sandboxTemplateRef"] = {"name": self.template_ref}
        else:
            spec["podTemplate"] = build_pod_template(
                self.kcfg,
                persistent=persistent,
                image=image,
                resources=resources,
                pvc_name=self.pvc_name(task_id),
            )
        if self.ttl_seconds:
            spec["ttlSeconds"] = int(self.ttl_seconds)
        if self.spec_overrides:
            spec = _deep_merge(spec, self.spec_overrides)

        metadata: dict[str, Any] = {
            "name": self.workspace_name(task_id),
            "namespace": self.namespace,
            "labels": {**MANAGED_BY_LABEL, **(self.kcfg.get("labels") or {})},
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
            spec = _deep_merge(spec, self.spec_overrides)
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

    def _create_object(self, group: str, plural: str, body: dict) -> None:
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
            # Already exists — resume it.

    @staticmethod
    def _dig(obj: Any, *path: str) -> Any:
        for key in path:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(key)
        return obj

    def _resolve_pod_name(self, sandbox: dict, sandbox_name: str) -> Optional[str]:
        """Find the pod agent-sandbox-operator reconciled for this Sandbox.

        Status field names differ across operator releases, so probe the known
        shapes, then fall back to a label lookup, then to the convention that
        the pod is named after the Sandbox.
        """
        status = sandbox.get("status") or {}
        for path in (("podRef", "name"), ("podName",), ("pod", "name"),
                     ("workloadRef", "name")):
            value = self._dig(status, *path)
            if isinstance(value, str) and value:
                return value

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
                    return items[0].metadata.name
        return sandbox_name

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
            if plural == "sandboxes" and self._resolve_pod_name(last, name) != name:
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
            self._create_object(self.CLAIM_GROUP, "sandboxclaims",
                                self.claim_manifest(task_id))
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
            self._create_object(
                self.group, "sandboxes",
                self.sandbox_manifest(task_id, persistent, image, resources),
            )
            self._created_names.add(name)
            sandbox_name = name

        sandbox = self._wait_sandbox("sandboxes", sandbox_name, self.group)
        pod_name = self._resolve_pod_name(sandbox, sandbox_name)
        self.wait_pod_ready(pod_name)
        return PodRef(self.namespace, pod_name, WORKSPACE_CONTAINER_NAME)

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
        self._active_stream = None
        self._cancelled = False
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
        """Re-provision after an interrupt tore the ephemeral pod down.

        Without this a single timeout bricks the session: ``cancel()`` deletes
        the pod, every later exec 404s, and the agent sees empty output with
        rc=1 until the idle reaper evicts the environment.
        """
        with self._lock:
            if self._pod_ref is not None:
                return self._pod_ref
        pod_ref = self._provisioner.ensure(
            task_id=self._task_id,
            persistent=self._persistent,
            image=self._image,
            resources=self._resources,
        )
        with self._lock:
            self._pod_ref = pod_ref
            self._cancelled = False
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
    def _open_stream(self, command: list[str], *, stdin: bool = False):
        from kubernetes.client import CoreV1Api
        from kubernetes.stream import stream as k8s_stream

        ref = self._pod_ref
        if ref is None:
            raise RuntimeError("kubernetes session pod is not provisioned")
        api = self._exec_api or CoreV1Api()
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

    @staticmethod
    def _drain(resp, chunks: list[str]) -> None:
        if resp.peek_stdout():
            chunks.append(resp.read_stdout())
        if resp.peek_stderr():
            chunks.append(resp.read_stderr())

    @staticmethod
    def _safe_returncode(resp) -> "int | None":
        """Read ``WSClient.returncode`` without letting it explode.

        ``returncode`` parses the exec error channel with ``yaml.safe_load``
        and then subscripts the result. On an abnormal disconnect (the pod
        being deleted mid-exec — i.e. our own cancel path) that channel is
        empty, ``safe_load("")`` returns None, and the property raises
        ``TypeError``. Left unguarded that discards every byte of output the
        command already produced.
        """
        try:
            return resp.returncode
        except Exception:
            return None

    def _exec_capture(self, command: list[str], *, timeout: int = 60) -> tuple[str, int]:
        """Blocking exec helper used by the file-sync transport."""
        resp = self._open_stream(command)
        chunks: list[str] = []
        deadline = time.monotonic() + max(1, timeout)
        try:
            while resp.is_open() and time.monotonic() < deadline:
                resp.update(timeout=1)
                self._drain(resp, chunks)
            self._drain(resp, chunks)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        rc = self._safe_returncode(resp)
        return "".join(chunks), (rc if rc is not None else 0)

    def _run_bash(
        self, cmd_string: str, *, login: bool = False, timeout: int = 120,
        stdin_data: str | None = None,
    ):
        shell = "bash -l -c" if login else "bash -c"
        command = [*shell.split(), cmd_string]

        def exec_fn() -> tuple[str, int]:
            chunks: list[str] = []
            resp = None
            try:
                resp = self._open_stream(command)
                with self._lock:
                    self._active_stream = resp
                    self._cancelled = False
                while resp.is_open():
                    resp.update(timeout=1)
                    self._drain(resp, chunks)
                # Drain any tail buffered by the final update().
                self._drain(resp, chunks)
            except Exception as exc:
                # Return whatever the command produced instead of losing it —
                # _ThreadedProcessHandle only writes to the output pipe on the
                # success path.
                with self._lock:
                    cancelled = self._cancelled
                if not cancelled:
                    logger.warning("k8s: exec stream error: %s", exc)
                    chunks.append(f"\n[kubernetes exec error: {exc}]")
                return "".join(chunks), (130 if cancelled else 1)
            finally:
                with self._lock:
                    self._active_stream = None
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass
            with self._lock:
                cancelled = self._cancelled
            if cancelled:
                return "".join(chunks), 130
            rc = self._safe_returncode(resp)
            return "".join(chunks), (rc if rc is not None else 0)

        def cancel() -> None:
            with self._lock:
                self._cancelled = True
                stream = self._active_stream
            # Close the websocket first so the exec'd process is signalled and
            # the worker thread can exit. The PR left persistent sessions with
            # a no-op cancel, leaking a thread + websocket + pipe fd for the
            # full duration of the runaway command.
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
            if not self._persistent:
                # Ephemeral: tearing the pod down is the cleanest interrupt.
                # _ensure_pod() re-provisions on the next command.
                ref = self._pod_ref
                if ref is not None:
                    try:
                        self._provisioner.destroy(ref, persistent=False)
                    except Exception:
                        pass
                with self._lock:
                    self._pod_ref = None
                self._snapshot_ready = False

        return _ThreadedProcessHandle(exec_fn, cancel_fn=cancel)

    # -- file sync transport --------------------------------------------
    def agent_visible_cache_base(self) -> str:
        """Where the agent sees ~/.hermes inside the pod (extension hook used
        by tools/image_generation_tool.py to surface generated artifacts)."""
        return self._hermes_base

    def _bulk_upload(self, files: list[tuple[str, str]]) -> None:
        """Push many files into the pod in one shot.

        Preferred path streams a base64 tar over the exec stdin channel and
        half-closes it (``v5.channel.k8s.io``) so the remote ``tar`` sees EOF.
        Clusters that negotiate an older subprotocol have no half-close, so we
        fall back to appending bounded base64 chunks with ordinary execs.
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
            self._exec_capture(["sh", "-c", quoted_mkdir_command(dirs)])

        encoded = base64.b64encode(payload).decode("ascii")
        if self._stdin_upload(encoded):
            return
        self._upload_tar_base64(encoded)

    def _stdin_upload(self, encoded: str) -> bool:
        """Try the stdin half-close path. Returns False when unavailable."""
        try:
            from kubernetes.stream.ws_client import (
                STDIN_CHANNEL,
                V5_CHANNEL_PROTOCOL,
            )
        except Exception:
            return False

        resp = None
        try:
            resp = self._open_stream(
                ["sh", "-c", "base64 -d | tar xf - -C /"], stdin=True
            )
            if getattr(resp, "subprotocol", None) != V5_CHANNEL_PROTOCOL:
                # No half-close: `tar` would block on stdin forever.
                return False
            for offset in range(0, len(encoded), 64 * 1024):
                resp.write_stdin(encoded[offset:offset + 64 * 1024])
            resp.close_channel(STDIN_CHANNEL)
            deadline = time.monotonic() + 120
            chunks: list[str] = []
            while resp.is_open() and time.monotonic() < deadline:
                resp.update(timeout=1)
                self._drain(resp, chunks)
            self._drain(resp, chunks)
            rc = self._safe_returncode(resp)
            if rc not in (0, None):
                raise RuntimeError(
                    f"kubernetes file sync: tar extract failed: {''.join(chunks).strip()}"
                )
            return True
        except RuntimeError:
            raise
        except Exception as exc:
            logger.debug("k8s: stdin file upload unavailable (%s)", exc)
            return False
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

    def _upload_tar_base64(self, encoded: str) -> None:
        """Ship a base64 tar to the pod in bounded chunks, then extract."""
        remote_tmp = f"/tmp/.hermes-sync.{os.getpid()}.b64"
        self._exec_capture(["sh", "-c", f"rm -f {shlex.quote(remote_tmp)}"])
        chunk = 48 * 1024  # keeps each exec URL well under API-server limits
        for offset in range(0, len(encoded), chunk):
            piece = encoded[offset:offset + chunk]
            _, rc = self._exec_capture(
                ["sh", "-c", f"printf %s {shlex.quote(piece)} >> {shlex.quote(remote_tmp)}"],
                timeout=60,
            )
            if rc != 0:
                raise RuntimeError("kubernetes file sync: chunk upload failed")
        out, rc = self._exec_capture(
            ["sh", "-c",
             f"base64 -d {shlex.quote(remote_tmp)} | tar xf - -C / && "
             f"rm -f {shlex.quote(remote_tmp)}"],
            timeout=120,
        )
        if rc != 0:
            raise RuntimeError(f"kubernetes file sync: extract failed: {out.strip()}")

    def _upload_file(self, host_path: str, remote_path: str) -> None:
        self._bulk_upload([(host_path, remote_path)])

    def _delete_files(self, remote_paths: list[str]) -> None:
        if not remote_paths:
            return
        self._exec_capture(["sh", "-c", quoted_rm_command(remote_paths)])

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
    "merge_kubernetes_config",
    "validate_kubernetes_config",
    "load_kubernetes_apis",
    "resolve_namespace",
    "resolve_owner_reference",
    "sanitize_name",
    "in_cluster",
]
