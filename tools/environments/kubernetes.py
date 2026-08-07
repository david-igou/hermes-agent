"""Kubernetes session-pod execution environment.

Runs each agent command by exec-ing into a per-session pod in a Kubernetes
cluster.  Provisioning sits behind :class:`WorkspaceProvisioner` so the raw-API
:class:`PodProvisioner` (``provisioner: pod``) can be swapped for the
operator-CR ``SandboxProvisioner`` in :mod:`tools.environments.kubernetes_sandbox`
(``agents.x-k8s.io/v1beta1`` ``Sandbox``, reconciled by agent-sandbox-operator)
without touching the exec loop.

Configuration policy
--------------------
Every user-facing setting for this backend lives in ``config.yaml`` under
``terminal.kubernetes.*`` (see :data:`DEFAULT_KUBERNETES_CONFIG`).  There are no
``TERMINAL_KUBERNETES_*`` env vars: the existing terminal config bridge
serialises the whole block into ONE internal env var (``TERMINAL_KUBERNETES``)
that only ``tools.terminal_tool`` reads.  ``.env`` is for secrets, and this
backend has no credential surface at all — in-cluster auth is the projected
ServiceAccount token the kubelet mounts, which Hermes never reads or stores.

Pod shape policy — the config defines the API call
--------------------------------------------------
The schema models what the BACKEND has to reason about (placement, auth, the
exec target, workspace lifetime).  Everything that is merely ``PodSpec`` is
expressed as ``terminal.kubernetes.pod_template``, a single PodTemplateSpec
merged over a DEFAULT base by :func:`merge_pod_template`.  The base is a set of
defaults that make the out-of-box config produce a working pod; it is not a
constraint.  Nothing here is reserved: a ``pod_template`` may override any
field, including the exec container's ``command``, ``args``, ``restartPolicy``,
``volumeMounts`` and ``securityContext``.

Validation of the pod's CONTENT is the cluster's job, not Hermes'.  SCC, Pod
Security Admission, ValidatingAdmissionPolicy, NetworkPolicy and RBAC decide
authoritatively what a session pod may be, and every create/patch this backend
issues passes ``field_validation="Strict"`` so a malformed or unknown field
comes back as a ``400`` naming the exact JSON path.  An in-process
approximation of admission control would be redundant and, being an
approximation, wrong.  :func:`validate_kubernetes_config` therefore checks only
what the API server cannot see: the ``provisioner`` enum, and the handful of
types needed to build the request at all.  A pod that cannot serve exec fails
visibly at the first command; that is the operator's error to see.

Merge rule for ``pod_template``
-------------------------------
JSON merge patch, RFC 7386: mappings merge recursively, a ``null`` REMOVES the
key it names (so any base default can be dropped), and lists — volumes, env,
tolerations, imagePullSecrets, ports, volumeMounts, all of them — REPLACE
wholesale.  The ONE exception is ``spec.containers`` and ``spec.initContainers``,
which merge element-wise on ``name``: without it the most common override
(setting ``resources`` on the workspace container) would force the user to
restate image, command and volumeMounts.  A container whose ``name`` is not in
the base is appended.

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
# The volume (and its mount) that carries the agent's cwd. Reserved: it is the
# path `builtin cd -- <cwd>` resolves against on every command.
WORKSPACE_VOLUME_NAME = "workspace"
# emptyDir mounted at /tmp on every session pod. Unconditional: init_session()
# writes its env snapshot there, so a pod_template setting
# readOnlyRootFilesystem: true must not silently break cwd/env tracking.
TMP_VOLUME_NAME = "tmp"
# Grace added to the caller's timeout before the exec loop gives up on its
# own; _wait_for_process is expected to act first.
_EXEC_GRACE_SECONDS = 15
# Terminator for the stdin file-sync payload (see _stdin_upload).
_SYNC_SENTINEL = "__HERMES_TAR_EOF__"
_STDIN_CHUNK_BYTES = 64 * 1024
MANAGED_BY_LABEL = {"app.kubernetes.io/managed-by": "hermes-agent"}
# Stamped on every workspace PVC Hermes creates, and required before one is
# adopted. A PVC cannot carry an ownerReference (it must outlive the agent
# pod), so this is the only provenance an adopting agent can read.
PVC_INSTANCE_ANNOTATION = "hermes.nousresearch.com/created-by-instance"


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
    "provisioner": "pod",             # pod | sandbox
    "namespace": "",                  # "" -> the projected SA namespace file
    "kubeconfig": "",                 # out-of-cluster dev only (a path, not a secret)
    "context": "",                    # kubeconfig context; ignored in-cluster
    # --- workload ------------------------------------------------------
    # Base image. Kept top-level (rather than folded into pod_template)
    # because it is the per-task override channel: RL/benchmark harnesses
    # swap it per task through container_config["kubernetes_image"].  A
    # pod_template that pins spec.containers[].image wins and DISABLES that.
    "image": "nikolaik/python-nodejs:python3.11-nodejs20",
    # The container this backend execs into. Also the name the default base
    # builds; a pod_template may rename or replace it, in which case set this
    # key to match or the exec lands nowhere.
    "container_name": "workspace",
    # Where the workspace volume is mounted. Also the environment's default
    # cwd, so it is backend behaviour, not just pod shape.
    "mount_path": "/workspace",
    # THE user layer. A PodTemplateSpec merged over the default base by
    # merge_pod_template() with RFC 7386 semantics (maps merge, null removes,
    # lists replace) plus the containers/initContainers-by-name exception.
    # Nothing is reserved: every field is overridable.
    "pod_template": {},
    # Whether the operator DECLARES this backend's session pods disposable
    # enough to skip Hermes' dangerous-command approval prompts. Declared,
    # never inferred: Hermes does not read the pod back to guess. Default
    # false = the prompts stay on.
    "trusted_sandbox": False,
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
    # spec.activeDeadlineSeconds, but the APPLICATION rule is backend logic
    # static YAML cannot express: ephemeral pods always, persistent pods only
    # when no ownerReference could be resolved (nothing else would reap them).
    "active_deadline_seconds": 14400,  # 0 -> omit
    "ready_timeout_seconds": 120,
    "owner_reference": "auto",        # auto | off
    # --- sandbox provisioner only -------------------------------------
    "sandbox": {
        "api_group": "agents.x-k8s.io",
        "api_version": "v1beta1",
        # The Sandbox CR spec, submitted verbatim for the CRD's own schema to
        # validate. `podTemplate` is overwritten by the rendered template this
        # backend injects.
        "spec": {},
    },
}

VALID_PROVISIONERS = ("pod", "sandbox")

# The DEFAULT base's ServiceAccount — the no-perms one k8s/rbac.yaml ships.
# Overridable like everything else, via
# pod_template.spec.serviceAccountName; what that SA may do is RBAC's answer.
SESSION_SERVICE_ACCOUNT = "hermes-session-noperms"

# THE validation mechanism for pod content. Unknown/duplicate fields must 400
# with the offending path, not be silently dropped. The python client discards
# the API server's "Warning: 299 - unknown field" header, so Warn (the v1.23+
# server default) is indistinguishable from success: a typo'd
# securityContext.runAsNonroot comes back 201 with runAsNonRoot unset and
# nothing logged. pod_template is free-form user YAML posted verbatim, so every
# create this backend issues passes Strict and the API server — which owns the
# schema — reports the exact JSON path Hermes could only have guessed at.
STRICT_FIELD_VALIDATION: dict[str, str] = {"field_validation": "Strict"}


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


#: The ONE exception to RFC 7386 list-replacement: ``spec.containers`` and
#: ``spec.initContainers`` merge element-wise on ``name``.
#:
#: Without it the most common override there is — setting ``resources`` on the
#: workspace container — would force the user to restate its image, command and
#: volumeMounts verbatim, and a drifting restatement is exactly the bug a merge
#: rule exists to avoid. Every other list replaces wholesale, which is loud (you
#: lose what you did not restate) and needs no ``patchMergeKey`` table for all
#: of PodSpec.
_CONTAINER_LISTS: "frozenset[tuple]" = frozenset({
    ("spec", "containers"),
    ("spec", "initContainers"),
})


def _merge_containers_by_name(base: list, overlay: list, path: tuple) -> list:
    """Merge *overlay* into *base* element-wise on ``name``; append unmatched.

    Two overlay entries with the same ``name`` fold into one, and so do two base
    entries. That is not policed here: Kubernetes forbids duplicate container
    names, so the un-folded object would be a ``400`` from the API server, which
    is the only place that judgement belongs.
    """
    merged = [deepcopy(item) for item in base]
    index = {
        item["name"]: pos
        for pos, item in enumerate(merged)
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    for item in overlay:
        name = item.get("name") if isinstance(item, dict) else None
        if isinstance(name, str) and name in index:
            merged[index[name]] = merge_pod_template(
                merged[index[name]], item, path + ("*",)
            )
        else:
            merged.append(deepcopy(item))
    return merged


def merge_pod_template(base: dict, overlay: Any, _path: tuple = ()) -> dict:
    """Merge ``terminal.kubernetes.pod_template`` onto the default base.

    **JSON merge patch (RFC 7386), plus one documented exception.** Mappings
    merge recursively; a ``null`` value REMOVES the key it names, so any base
    default can be dropped; every list REPLACES the base's list wholesale —
    volumes, volumeMounts, env, tolerations, imagePullSecrets, ports, all of
    them. The exception is :data:`_CONTAINER_LISTS`: ``spec.containers`` and
    ``spec.initContainers`` merge element-wise on ``name``, appending a
    container the base does not declare.

    Nothing is reserved. The base is a set of defaults, so a template may
    override any field in it, including the exec container's ``command``,
    ``args``, ``restartPolicy``, ``volumeMounts`` and ``securityContext``. What
    the resulting pod is allowed to be is the cluster's decision (SCC, Pod
    Security Admission, ValidatingAdmissionPolicy, RBAC), and whether it is
    well-formed is the API server's, via ``field_validation="Strict"``.
    """
    out = deepcopy(base)
    if not isinstance(overlay, dict):
        return out
    for key, value in overlay.items():
        path = _path + (key,)
        current = out.get(key)
        if value is None:
            # RFC 7386: null removes the member.
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(current, dict):
            out[key] = merge_pod_template(current, value, path)
        elif (path in _CONTAINER_LISTS and isinstance(value, list)
                and isinstance(current, list)):
            out[key] = _merge_containers_by_name(current, value, path)
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


def merge_kubernetes_config(user_config: Any) -> dict:
    """Merge a (possibly partial) ``terminal.kubernetes`` block over defaults.

    Two of the three config→env bridges (``cli.py`` and ``gateway/run.py``) do
    NOT deep-merge ``DEFAULT_CONFIG`` before bridging, so a user who sets only
    ``terminal.kubernetes.namespace`` produces ``{"namespace": "..."}`` here.
    Every consumer must therefore go through this function rather than indexing
    the parsed payload directly.
    """
    return _deep_merge(DEFAULT_KUBERNETES_CONFIG, user_config)


def _mapping(node: Any, key: str) -> dict:
    """``node[key]`` when it is a mapping, else ``{}``.

    ``(kcfg.get("volume") or {})`` is not the same thing: a scalar written where
    a block belongs sails through ``or`` and raises ``AttributeError`` at the
    next ``.get``.
    """
    value = node.get(key) if isinstance(node, dict) else None
    return value if isinstance(value, dict) else {}


def validate_kubernetes_config(kcfg: Any) -> list[str]:
    """Return the config problems Hermes is the only one who CAN see.

    Deliberately tiny. Everything about the pod's CONTENT — quantities, RFC-1123
    names, duplicate mountPaths, securityContext combinations, unknown or
    misspelled PodSpec fields — is checked authoritatively by the API server
    (``field_validation="Strict"`` makes an unknown or duplicated field a ``400``
    naming the exact JSON path) and constrained authoritatively by the cluster's
    SCC / Pod Security Admission / ValidatingAdmissionPolicy / RBAC. Re-deriving
    any of that here would be an approximation of admission control, redundant
    where it agreed and wrong where it did not.

    What remains is Hermes-side config the API server never sees:

    * ``provisioner`` — it selects which Kubernetes API this backend calls, so
      an unknown value has no request to be rejected by;
    * the types needed to BUILD a request at all — ``pod_template`` must be a
      mapping to merge, ``sandbox.spec`` must be a mapping to carry the injected
      ``podTemplate``. A scalar there is a ``TypeError`` in a manifest builder,
      not a message from the cluster.

    A pod that is well-formed but cannot serve exec (no shell, a ``command``
    that exits, a securityContext the kubelet refuses) is NOT a problem this
    function reports. It fails visibly on the first command, and that failure is
    the operator's to see.
    """
    if kcfg is not None and not isinstance(kcfg, dict):
        return [
            f"terminal.kubernetes must be a mapping (got {type(kcfg).__name__})"
        ]
    problems: list[str] = []
    if not isinstance(kcfg, dict):
        return problems

    provisioner = str(kcfg.get("provisioner") or "").strip().lower()
    if provisioner not in VALID_PROVISIONERS:
        problems.append(
            f"terminal.kubernetes.provisioner must be one of "
            f"{', '.join(VALID_PROVISIONERS)} (got {provisioner!r})"
        )

    pod_template = kcfg.get("pod_template")
    if pod_template is not None and not isinstance(pod_template, dict):
        problems.append(
            "terminal.kubernetes.pod_template must be a mapping (a "
            f"PodTemplateSpec); got {type(pod_template).__name__}"
        )

    sandbox = kcfg.get("sandbox")
    if sandbox is not None and not isinstance(sandbox, dict):
        problems.append(
            f"terminal.kubernetes.sandbox must be a mapping (got "
            f"{type(sandbox).__name__})"
        )
    cr_spec = _mapping(kcfg, "sandbox").get("spec")
    if cr_spec is not None and not isinstance(cr_spec, dict):
        problems.append(
            "terminal.kubernetes.sandbox.spec must be a mapping (a Sandbox CR "
            f"spec); got {type(cr_spec).__name__}"
        )
    return problems



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
    ``memory_mib`` / ``disk_mib`` are MiB.  They only fill the DEFAULT base's
    ``requests``; a ``pod_template`` container merged by ``name`` replaces the
    whole ``resources`` mapping.
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
    """Name of the container this backend builds and execs into."""
    return str(kcfg.get("container_name") or "").strip() or WORKSPACE_CONTAINER_NAME


def mount_path(kcfg: dict) -> str:
    """Path the workspace volume is mounted at (and the session's default cwd)."""
    return str(kcfg.get("mount_path") or "").strip() or "/workspace"


def _default_base(
    kcfg: dict,
    *,
    persistent: bool,
    image: str,
    resources: Resources,
    pvc_name: str,
    owned: bool = True,
) -> dict:
    """The DEFAULT pod template, before the user layer.

    Defaults, not constraints. Every field below is overridable through
    ``terminal.kubernetes.pod_template``; what they buy is an out-of-box config
    that produces a pod which starts, stays up and can be exec'd into. Locking
    the result down is the cluster administrator's job, and SCC / Pod Security
    Admission / ValidatingAdmissionPolicy / NetworkPolicy / RBAC are where it is
    done authoritatively.
    """
    exec_container = container_name(kcfg)
    workspace_path = mount_path(kcfg)

    # --- sensible defaults --------------------------------------------
    # A conservative starting point for a throwaway session pod. A pod_template
    # may relax any of it; the cluster's admission stack is what decides
    # whether the relaxed pod is allowed.
    pod_security: dict[str, Any] = {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    # runAsUser/fsGroup are OMITTED: OpenShift's restricted-v2 SCC assigns both
    # from the namespace's uid/supplemental-group range, and a hardcoded 1000
    # is outside it (the pod is rejected outright). On vanilla Kubernetes set
    # pod_template.spec.securityContext.runAsUser so runAsNonRoot can schedule
    # a root-default image, plus fsGroup so the non-root uid can write the
    # emptyDir/PVC (they mount root:root 0755 otherwise).
    container_security: dict[str, Any] = {
        "runAsNonRoot": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }

    container: dict[str, Any] = {
        "name": exec_container,
        "image": image,
        # Keep the pod alive so we can exec into it repeatedly.
        "command": ["sleep", "infinity"],
        "workingDir": workspace_path,
        "volumeMounts": [
            {"name": WORKSPACE_VOLUME_NAME, "mountPath": workspace_path},
            # Unconditional: init_session() writes its env snapshot under /tmp,
            # so a pod_template that sets readOnlyRootFilesystem: true must not
            # silently break cwd/env tracking. An emptyDir is free.
            {"name": TMP_VOLUME_NAME, "mountPath": "/tmp"},
        ],
        "securityContext": container_security,
        "resources": {
            "requests": {
                "cpu": _cpu_quantity(resources.cpu),
                "memory": f"{resources.memory_mib}Mi",
            }
        },
    }

    if persistent:
        workspace_volume = {
            "name": WORKSPACE_VOLUME_NAME,
            "persistentVolumeClaim": {"claimName": pvc_name},
        }
    else:
        workspace_volume = {"name": WORKSPACE_VOLUME_NAME, "emptyDir": {}}

    spec: dict[str, Any] = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "serviceAccountName": SESSION_SERVICE_ACCOUNT,
        "enableServiceLinks": False,
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        # `sleep infinity` as PID 1 ignores SIGTERM, so the default 30s grace
        # would stall every teardown (which is on the interrupt path).
        "terminationGracePeriodSeconds": 1,
        "securityContext": pod_security,
        "containers": [container],
        "volumes": [workspace_volume, {"name": TMP_VOLUME_NAME, "emptyDir": {}}],
    }

    deadline = int(kcfg.get("active_deadline_seconds") or 0)
    if deadline > 0 and (not persistent or not owned):
        # Hard lifetime ceiling (leak backstop). Normally ephemeral-only — a
        # persistent workspace is meant to be long-lived — but a persistent pod
        # with no ownerReference has no reaper at all, and its PVC (the durable
        # half) outlives the pod either way. That conditional is why the key
        # stays top-level instead of folding into pod_template.
        spec["activeDeadlineSeconds"] = deadline

    return {"metadata": {"labels": dict(MANAGED_BY_LABEL)}, "spec": spec}


def render_pod_template(
    kcfg: dict,
    *,
    persistent: bool,
    image: str,
    resources: Resources,
    pvc_name: str,
    owned: bool = True,
) -> dict:
    """Render THE pod template — the artifact that reaches the API server.

    A default base is built from backend state (image, resources, the workspace
    volume, the exec container), then ``terminal.kubernetes.pod_template`` is
    merged over it exactly once by :func:`merge_pod_template` (RFC 7386 plus the
    containers-by-name exception). :class:`PodProvisioner` wraps the result in a
    ``Pod``; the sandbox provisioner ASSIGNS it to ``Sandbox.spec.podTemplate``.

    Nothing here rejects anything. The config defines how the API call is made,
    and the API server validates it — every create/patch this backend issues
    passes ``field_validation="Strict"``, so a malformed or unknown field is a
    ``400`` naming the exact JSON path. What the pod is ALLOWED to be is the
    cluster administrator's decision, expressed in SCC, Pod Security Admission,
    ValidatingAdmissionPolicy, NetworkPolicy and RBAC.

    The one thing stamped AFTER the merge is
    ``metadata.labels[app.kubernetes.io/managed-by]``. That is not a security
    control: Hermes uses it to find and adopt its own session pods, and
    ``k8s/networkpolicy.yaml`` selects on it, so a template that dropped it
    would break adoption and silently fall out of the admin's policy. It is
    stamped, not validated — set the key if you like, the stamp wins.

    *owned* is False when no ownerReference could be resolved — the one case
    where a persistent pod also gets the activeDeadlineSeconds backstop, because
    nothing else would ever reap it.
    """
    template = merge_pod_template(
        _default_base(
            kcfg, persistent=persistent, image=image, resources=resources,
            pvc_name=pvc_name, owned=owned,
        ),
        kcfg.get("pod_template"),
    )

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
        # Objects this provisioner REFUSED to adopt (or could not prove were
        # ours). A refusal to reuse has to be a refusal to delete as well: the
        # refusal raises out of ensure(), KubernetesEnvironment.__init__ catches
        # it and calls _best_effort_destroy(), which synthesises a PodRef from
        # the same conventional name — so the guard that protected the read side
        # was handing the write side to the same foreign object.
        self._foreign_names: set[str] = set()

    def _refuse(self, name: str, message: str) -> "RuntimeError":
        """Record *name* as not-ours and build the error to raise."""
        self._foreign_names.add(name)
        return RuntimeError(message)

    def _may_delete(self, name: str) -> bool:
        if name in self._foreign_names:
            logger.warning(
                "k8s: refusing to delete %s: this Hermes instance declined to "
                "adopt it (it is not ours, or ownership could not be read), so "
                "deleting it would destroy another agent's workspace.", name,
            )
            return False
        return True

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
        # _mapping, not `or {}`: a scalar written where the block belongs sails
        # through `or` and raises AttributeError at the next .get. pvc_manifest
        # already reads it this way.
        configured = str(_mapping(self.kcfg, "volume").get("claim_name") or "").strip()
        return configured or f"hermes-ws-{sanitize_name(task_id)}"

    def container_name(self) -> str:
        return container_name(self.kcfg)

    def exec_container(self, pod: Any) -> str:
        """Assert the RECONCILED pod carries the container we exec into.

        The old behaviour was to fall back to the pod's FIRST container when
        the configured name was absent.  ``container_name`` is the exec target
        SELECTOR, so a pod without it means the running pod is not the one this
        backend rendered (or the operator renamed the container in
        ``pod_template`` without updating ``container_name``).  Exec-ing into
        whatever else is there would be that drift, silently — and the very
        next thing that happens is a credential-file upload into it.
        """
        expected = self.container_name()
        names: list[str] = []
        for entry in (getattr(getattr(pod, "spec", None), "containers", None) or []):
            name = getattr(entry, "name", None)
            if name is None and isinstance(entry, dict):
                name = entry.get("name")
            if name:
                names.append(str(name))
        if expected in names:
            return expected
        # No `not names` escape: "we could not establish that the running pod
        # carries the container we rendered" is the same failure as "it carries
        # a different one", and fail-open is the wrong default for a check
        # whose entire purpose is to prove the running pod matches the
        # submitted one. Most plausible on the sandbox path, where the pod is
        # resolved from an operator status shape or a label lookup.
        raise RuntimeError(
            f"session pod has no container {expected!r} (found "
            f"{', '.join(names) or 'no readable container list'}); refusing to "
            "exec into a container this backend did not render. The running "
            "pod does not match the template Hermes submitted and evaluated."
        )

    # -- PVC ------------------------------------------------------------
    def pvc_manifest(self, task_id: str, resources: Resources) -> dict:
        vol = _mapping(self.kcfg, "volume")
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
                # Provenance, not identity: the claim carries no ownerReference
                # (it must outlive the agent pod), so this stamp is what an
                # adopting agent can check.  See _assert_pvc_is_ours.
                "annotations": {PVC_INSTANCE_ANNOTATION: self._instance},
            },
            "spec": spec,
        }

    @staticmethod
    def _metadata_map(obj, field: str) -> dict:
        """``metadata.<field>`` as a dict, from an SDK object or a plain dict."""
        value = getattr(getattr(obj, "metadata", None), field, None)
        if value is None and isinstance(obj, dict):
            value = _dig_dict(obj, "metadata").get(field)
        return value if isinstance(value, dict) else {}

    def _assert_pvc_is_ours(self, pvc, name: str, task_id: str) -> None:
        """Refuse to adopt a PVC this backend cannot tie to a Hermes workspace.

        Adoption is not free: the claim is mounted at ``mount_path``, which is
        the agent's cwd, and ``KubernetesEnvironment`` immediately syncs its
        credential files into ``<cwd>/.hermes`` — i.e. into this claim, at
        rest, on a volume Hermes never deletes.

        What can be proved here is weaker than on the pod path, and the
        difference is deliberate rather than an oversight: the claim carries no
        ownerReference (it must outlive the agent pod) and its name is task-
        scoped rather than instance-scoped, because a persistent workspace must
        resume for the same task after the agent pod is replaced.  So there is
        no per-instance secret to check.  What IS checked is the complete
        provenance stamp ``pvc_manifest`` writes — the managed-by label, the
        component label, the task label and the creating instance annotation —
        rather than the single well-known managed-by label, which any workload
        with ``persistentvolumeclaims/create`` could set on a claim it made
        under the conventional name.  A claim missing the stamp is refused
        (fail closed) with instructions, and a claim stamped by a DIFFERENT
        instance is logged, because cross-instance sharing is designed but
        should never be silent.

        Honest limitation, also stated in k8s/README.md: every field here is
        forgeable by anything that can create a labelled PVC in the session
        namespace.  ``persistentvolumeclaims/create`` in that namespace is a
        trust boundary; keep it to Hermes (RBAC), and prefer an explicit
        ``terminal.kubernetes.volume.claim_name``.
        """
        labels = self._metadata_map(pvc, "labels")
        annotations = self._metadata_map(pvc, "annotations")
        managed_by_key, managed_by_value = next(iter(MANAGED_BY_LABEL.items()))
        advice = (
            " The agent's credential files are synced into this claim. Set "
            "terminal.kubernetes.volume.claim_name to a name of your own, or "
            "let Hermes create the claim."
        )
        if labels.get(managed_by_key) != managed_by_value:
            raise self._refuse(name, (
                f"persistentvolumeclaim {name} already exists and is not a "
                f"Hermes workspace ({managed_by_key}="
                f"{labels.get(managed_by_key)!r}); refusing to mount it." + advice
            ))
        if labels.get("app.kubernetes.io/component") != "hermes-workspace":
            raise self._refuse(name, (
                f"persistentvolumeclaim {name} already exists and does not carry "
                "the Hermes workspace component label; refusing to mount it."
                + advice
            ))
        configured = str(_mapping(self.kcfg, "volume").get("claim_name") or "").strip()
        if not configured:
            # Conventional name -> it must be the claim for THIS task. A
            # configured claim is the operator's own choice and may legitimately
            # be shared across task ids.
            want_task = sanitize_name(task_id)
            if labels.get("hermes.nousresearch.com/task") != want_task:
                raise self._refuse(name, (
                    f"persistentvolumeclaim {name} already exists and is "
                    f"labelled for task "
                    f"{labels.get('hermes.nousresearch.com/task')!r}, not "
                    f"{want_task!r}; refusing to mount it." + advice
                ))
        stamp = annotations.get(PVC_INSTANCE_ANNOTATION)
        if not stamp:
            raise self._refuse(name, (
                f"persistentvolumeclaim {name} already exists but carries no "
                f"{PVC_INSTANCE_ANNOTATION} stamp, so this backend cannot "
                "establish that a Hermes agent created it; refusing to mount "
                "it." + advice + " A claim you pre-created, or one left by a "
                "Hermes build older than this stamp, needs the annotation added "
                "(any value) to record that decision: kubectl -n <ns> annotate "
                f"pvc {name} {PVC_INSTANCE_ANNOTATION}=adopted"
            ))
        if stamp != self._instance:
            # Designed: two agents running the same task id share the claim.
            # Never silent: it is another agent's workspace and its files.
            logger.warning(
                "k8s: adopting persistentvolumeclaim %s created by Hermes "
                "instance %s (this instance is %s). Sharing a workspace claim "
                "is by design for the same task id, but the agent's credential "
                "files are synced into it — set "
                "terminal.kubernetes.volume.claim_name to keep them apart.",
                name, stamp, self._instance,
            )

    def _ensure_pvc(self, task_id: str, resources: Resources) -> None:
        from kubernetes.client.exceptions import ApiException

        name = self.pvc_name(task_id)
        try:
            existing = self._api.read_namespaced_persistent_volume_claim(
                name=name, namespace=self.namespace
            )
            self._assert_pvc_is_ours(existing, name, task_id)
            return
        except ApiException as exc:
            if exc.status != 404:
                raise
        try:
            self._api.create_namespaced_persistent_volume_claim(
                namespace=self.namespace,
                body=self.pvc_manifest(task_id, resources),
                **STRICT_FIELD_VALIDATION,
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
                raise self._refuse(name, (
                    f"persistentvolumeclaim {name} already exists but could not "
                    f"be read ({read_exc}); refusing to mount it."
                )) from read_exc
            self._assert_pvc_is_ours(raced, name, task_id)

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


class PodProvisioner(_BaseProvisioner):
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
        template = render_pod_template(
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
            # .get, not []: a pod_template whose `spec: null` deleted the whole
            # spec is the operator's error, and the API server's 400 ("spec is
            # required") names it better than a KeyError from here would.
            "spec": template.get("spec"),
        }

    def _is_ours(self, pod_name: str) -> bool:
        """True when an existing pod was created by THIS agent instance.

        A 409 on create is only safe to treat as "resume" when the pod is ours;
        otherwise we would silently exec into (and later delete) another
        agent's live workspace.

        A read that FAILS is not the same as a read that says "not ours", and
        collapsing the two produced a wrong message ("was not created by this
        Hermes instance" for a 403 on ``get pods``). Both fail closed, but only
        one of them is a statement about ownership.
        """
        from kubernetes.client.exceptions import ApiException

        try:
            pod = self._api.read_namespaced_pod(
                name=pod_name, namespace=self.namespace
            )
        except ApiException as exc:
            if getattr(exc, "status", None) == 404:
                return False
            raise self._refuse(pod_name, (
                f"session pod {pod_name} already exists but its ownership could "
                f"not be read ({exc}); refusing to reuse or delete it. Grant "
                "'get pods' in this namespace, or use a distinct "
                "terminal.kubernetes.namespace."
            )) from exc
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
                **STRICT_FIELD_VALIDATION,
            )
        except ApiException as exc:
            if exc.status != 409:
                raise
            # 409 = the pod already exists (persistent resume after a soft
            # stop, or a racing session in this same agent).
            if not self._is_ours(pod_name):
                raise self._refuse(pod_name, (
                    f"session pod {pod_name} already exists and was not created "
                    "by this Hermes instance; refusing to reuse it."
                ))

        pod = self.wait_pod_ready(pod_name)
        return PodRef(self.namespace, pod_name, self.exec_container(pod))

    def destroy(self, pod_ref: PodRef, persistent: bool) -> None:
        # A pod we refused to adopt is a pod we must not delete: the refusal
        # raises out of ensure(), and the environment's teardown path then asks
        # to destroy the workspace under exactly that name.
        if not self._may_delete(pod_ref.pod_name):
            return
        self._delete_pod(pod_ref.namespace, pod_ref.pod_name)
        # Persistent: keep the PVC so the next session resumes the filesystem.
        # There is deliberately no automatic PVC deletion — see
        # `hermes` docs / k8s/README.md for the reaper story.


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
    "SESSION_SERVICE_ACCOUNT",
    "STRICT_FIELD_VALIDATION",
    "MANAGED_BY_LABEL",
    "PVC_INSTANCE_ANNOTATION",
    "PodRef",
    "Resources",
    "WorkspaceProvisioner",
    "PodProvisioner",
    "KubernetesEnvironment",
    "render_pod_template",
    "merge_pod_template",
    "container_name",
    "mount_path",
    "merge_kubernetes_config",
    "validate_kubernetes_config",
    "load_kubernetes_apis",
    "resolve_namespace",
    "resolve_owner_reference",
    "sanitize_name",
    "in_cluster",
]
