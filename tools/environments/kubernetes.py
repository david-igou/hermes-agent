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

Pod shape policy — ONE artifact
-------------------------------
The schema models only what the BACKEND has to reason about (placement, auth,
the exec target, workspace lifetime).  Everything that is merely ``PodSpec`` is
expressed as ``terminal.kubernetes.pod_template``, a single PodTemplateSpec
merged over a hardened base by :func:`merge_pod_template`.
:func:`render_pod_template` is the ONLY function that produces a pod template
and there is no layer after it: :class:`PodProvisioner` wraps its result in a
``Pod``, the sandbox provisioner ASSIGNS it to ``Sandbox.spec.podTemplate``, and
:func:`unhardened_reasons` judges the same call.  Layered overrides are what let
the object that was security-checked drift from the object that was submitted.

The handful of fields that make exec possible at all (the exec container and its
``command``, ``restartPolicy``, the workspace mount/volume, the managed-by
label) are REJECTED rather than silently overwritten — see
:func:`reserved_violations`.

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
    # The container this backend builds AND execs into. Reserved: a
    # pod_template that omits it is rejected, never silently repaired.
    "container_name": "workspace",
    # Where the workspace volume is mounted. Also the environment's default
    # cwd, so it is backend behaviour, not just pod shape.
    "mount_path": "/workspace",
    # THE user layer. A PodTemplateSpec merged over the hardened base by
    # merge_pod_template(); mappings merge, lists replace except
    # spec.containers / spec.initContainers / spec.volumes (keyed by `name`)
    # and their volumeMounts (keyed by `mountPath`). Reserved paths are
    # rejected — see reserved_violations().
    "pod_template": {},
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
        # The Sandbox CR spec. `podTemplate` is injected from the ONE rendered
        # template above and is reserved here; so is `sandboxTemplateRef`,
        # which would make the operator author a pod Hermes never renders.
        "spec": {},
    },
}

VALID_PROVISIONERS = ("pod", "sandbox")

# The hardened base's ServiceAccount. A pod that names a different one cannot
# be established as powerless, so unhardened_reasons() flags it.
SESSION_SERVICE_ACCOUNT = "hermes-session-noperms"

# Unknown/duplicate fields in pod_template must 400 with the offending path,
# not be silently dropped. The python client discards the API server's
# "Warning: 299 - unknown field" header, so Warn (the v1.23+ server default)
# is indistinguishable from success: a typo'd securityContext.runAsNonroot
# comes back 201 with runAsNonRoot unset and nothing logged. Under this schema
# that risk is structural — pod_template is free-form user YAML posted
# verbatim — so every create/patch this backend issues passes Strict.
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


#: Lists inside a PodTemplateSpec that merge ELEMENT-WISE, and the key the
#: Kubernetes API server itself keys them on. ``"*"`` matches any list index.
#:
#: Everything else replaces wholesale. That is honest and complete because the
#: hardened base only ever populates these three lists plus
#: ``containers[0].command`` and ``securityContext.capabilities.drop``, which
#: upstream also replaces — so no base content a replacing list could silently
#: destroy is left unaccounted for. Replacement is LOUD (you lose what you did
#: not restate); the old "any list of name-bearing dicts" heuristic was silent
#: and wrong, keying volumeMounts on ``name`` where upstream keys them on
#: ``mountPath`` (a new-name/existing-mountPath mount appended, producing a
#: duplicate-mountPath pod the kubelet rejects).
#:
#: The lists below MUST merge rather than replace: they are the ones carrying
#: reserved core, and a user handed a replace-only rule could neither restate
#: the workspace mount (rejected) nor omit it (dropped).
_MERGE_KEYS: dict[tuple, str] = {
    ("spec", "containers"): "name",
    ("spec", "initContainers"): "name",
    ("spec", "volumes"): "name",
    ("spec", "containers", "*", "volumeMounts"): "mountPath",
    ("spec", "initContainers", "*", "volumeMounts"): "mountPath",
}


def _merge_keyed_list(base: list, overlay: list, key: str, path: tuple) -> list:
    """Merge *overlay* into *base* element-wise on *key*; append unmatched."""
    merged = [deepcopy(item) for item in base]
    index = {
        item[key]: pos
        for pos, item in enumerate(merged)
        if isinstance(item, dict) and key in item
    }
    for item in overlay:
        ident = item.get(key) if isinstance(item, dict) else None
        if ident is not None and ident in index:
            merged[index[ident]] = merge_pod_template(
                merged[index[ident]], item, path + ("*",)
            )
        else:
            merged.append(deepcopy(item))
    return merged


def merge_pod_template(base: dict, overlay: Any, _path: tuple = ()) -> dict:
    """Merge ``terminal.kubernetes.pod_template`` onto the hardened base.

    The rule, in full: **mappings merge recursively; lists replace wholesale,
    except the four paths in :data:`_MERGE_KEYS`, which merge element-wise on
    the key the API server actually uses** (``name`` for containers/
    initContainers/volumes, ``mountPath`` for their volumeMounts). An element
    whose key is absent from the base is appended.

    This is a documented Hermes merge rule, not "a strategic-merge patch". It
    agrees with Kubernetes on every path it merges, and it needs no
    ``patchMergeKey`` table for all of PodSpec — a table Hermes would then have
    to carry and version.

    The footgun a merge heuristic used to guard against (replacing
    ``spec.containers`` drops image/command/volumeMounts/securityContext and
    the pod never becomes Ready) is now caught by :func:`reserved_violations`
    with a named path, before anything is rendered.
    """
    out = deepcopy(base)
    if not isinstance(overlay, dict):
        return out
    for key, value in overlay.items():
        path = _path + (key,)
        current = out.get(key)
        merge_key = _MERGE_KEYS.get(path)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = merge_pod_template(current, value, path)
        elif merge_key and isinstance(value, list) and isinstance(current, list):
            out[key] = _merge_keyed_list(current, value, merge_key, path)
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


MANAGED_BY_KEY = next(iter(MANAGED_BY_LABEL))

#: Non-negotiable pod fields, and why. Hermes owns the fields that make exec
#: possible at all; a supplied template that sets any of them is REJECTED, not
#: silently overwritten, so the operator finds out at config time rather than
#: watching their YAML vanish.
_RESERVED_RATIONALE = {
    "restartPolicy": (
        "Hermes pins restartPolicy: Never so a container restart cannot swap "
        "the workspace out from under an open exec session."
    ),
    "command": (
        'Hermes pins command: ["sleep", "infinity"] so the pod outlives the '
        "session instead of completing."
    ),
}


def _elements(node: Any) -> list:
    """The list at *node*, or ``[]`` when it is absent or not a list."""
    return node if isinstance(node, list) else []


def _find_by(items: list, key: str, value: Any) -> Optional[dict]:
    for item in items:
        if isinstance(item, dict) and item.get(key) == value:
            return item
    return None


def reserved_violations(
    pod_template: Any, *, container_name: str, mount_path: str
) -> list[str]:
    """Reserved-core problems in the USER's ``pod_template`` (empty when clean).

    Scans the user's dict only, never the merged result: the hardened base
    legitimately sets every reserved path, so judging the merge output would
    flag itself.

    Detection is by PRESENCE, not value — setting ``restartPolicy: Never``, the
    same value the base uses, is still a violation. That is the only rule that
    keeps the reserved set decidable and the error text unambiguous.

    Reserved-by-identity (a container by ``name``, a mount by ``mountPath``, a
    volume by ``name``) rather than by whole-list, so adding a second volume or
    a mount at another path passes cleanly. That is exactly why those lists are
    merge-keyed in :data:`_MERGE_KEYS`.
    """
    if not isinstance(pod_template, dict):
        return []
    problems: list[str] = []
    base = "terminal.kubernetes.pod_template"

    # R1 — the selector NetworkPolicy, the admission policy and pod adoption
    # all match on.
    labels = _dig_dict(pod_template, "metadata", "labels")
    if MANAGED_BY_KEY in labels:
        problems.append(
            f"{base}.metadata.labels: {MANAGED_BY_KEY!r} is reserved and cannot "
            "be set. k8s/networkpolicy.yaml, k8s/validatingadmissionpolicy.yaml "
            "and session-pod adoption all select on it. Remove the key."
        )

    spec = pod_template.get("spec")
    if not isinstance(spec, dict):
        return problems

    # R2 — a restart swaps the container out from under an open session.
    if "restartPolicy" in spec:
        problems.append(
            f"{base}.spec.restartPolicy is reserved by the kubernetes backend "
            f"and cannot be set. {_RESERVED_RATIONALE['restartPolicy']} "
            "Remove the key."
        )

    if "containers" in spec:
        containers = _elements(spec.get("containers"))
        target = _find_by(containers, "name", container_name)
        if target is None:
            # R3 — a containers list that omits the exec target produces a pod
            # no session can use. Silently exec-ing into whatever else is there
            # is the validated-object-drift bug this design exists to remove.
            problems.append(
                f"{base}.spec.containers does not declare a container named "
                f"{container_name!r} (terminal.kubernetes.container_name). "
                "Hermes execs into that container; a containers list that omits "
                "it produces a pod no session can use. Add it, rename it, or "
                "set terminal.kubernetes.container_name to match."
            )
        else:
            if "command" in target:
                # R4
                problems.append(
                    f"{base}.spec.containers[name={container_name}].command is "
                    "reserved by the kubernetes backend and cannot be set. "
                    f"{_RESERVED_RATIONALE['command']} Remove the key."
                )
            # R5 — the workspace mount terminal.cwd resolves against.
            if _find_by(
                _elements(target.get("volumeMounts")), "mountPath", mount_path
            ) is not None:
                problems.append(
                    f"{base}.spec.containers[name={container_name}]"
                    f".volumeMounts[mountPath={mount_path}] is reserved by the "
                    "kubernetes backend and cannot be set. That mount is the "
                    "workspace terminal.cwd resolves against. Mount additional "
                    "volumes at other paths, or change "
                    "terminal.kubernetes.mount_path."
                )

    # R6 — the other half of R5. The claim name is computed at runtime from
    # pvc_name(); terminal.kubernetes.volume.claim_name is the way to pin it.
    if _find_by(
        _elements(spec.get("volumes")), "name", WORKSPACE_VOLUME_NAME
    ) is not None:
        problems.append(
            f"{base}.spec.volumes[name={WORKSPACE_VOLUME_NAME}] is reserved by "
            "the kubernetes backend and cannot be set. Hermes builds it from "
            "terminal.kubernetes.persistent and terminal.kubernetes.volume.*. "
            "Add volumes under other names."
        )
    return problems


def reserved_sandbox_spec_violations(cr_spec: Any) -> list[str]:
    """Reserved-core problems in ``terminal.kubernetes.sandbox.spec``."""
    if not isinstance(cr_spec, dict):
        return []
    problems: list[str] = []
    base = "terminal.kubernetes.sandbox.spec"
    if "podTemplate" in cr_spec:
        # S1 — a second pod-template source is the round-2/round-3 bypass:
        # the object that was security-checked stops being the object that is
        # submitted.
        problems.append(
            f"{base}.podTemplate is reserved and cannot be set. The pod "
            "template is rendered once from terminal.kubernetes.pod_template "
            "and injected here; a second source would let the object that is "
            "security-checked differ from the object that is submitted. Move "
            "your changes to terminal.kubernetes.pod_template."
        )
    if "sandboxTemplateRef" in cr_spec:
        # S2 — flat rejection: there is no template_ref config key to redirect
        # to, because an operator-authored pod cannot be rendered or judged.
        problems.append(
            f"{base}.sandboxTemplateRef is reserved and cannot be set. A "
            "SandboxTemplate makes agent-sandbox-operator author a pod this "
            "backend never renders and cannot evaluate, so its hardening "
            "cannot be established."
        )
    return problems


def _shape_problems(node: Any, label: str) -> list[str]:
    """Report a scalar/null where the renderer needs a mapping.

    Not a reserved violation — a malformed layer used to surface as a bare
    AttributeError out of manifest construction while this validator, which
    exists to catch exactly that, reported no problem at all.
    """
    problems: list[str] = []
    for path in (("metadata",), ("metadata", "labels"), ("spec",)):
        present, value = _lookup(node, path)
        if present and not isinstance(value, dict):
            problems.append(
                f"{label}.{'.'.join(path)} must be a mapping (got "
                f"{'null' if value is None else type(value).__name__})"
            )
    return problems


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
    itself before it ever talks to a cluster.  Reserved-core rejection lives
    here (:func:`reserved_violations`), so a config that tries to own a field
    Hermes owns fails loudly with the exact dotted path instead of having its
    YAML silently overwritten.
    """
    problems: list[str] = []
    provisioner = str(kcfg.get("provisioner") or "").strip().lower()
    if provisioner not in VALID_PROVISIONERS:
        problems.append(
            f"terminal.kubernetes.provisioner must be one of "
            f"{', '.join(VALID_PROVISIONERS)} (got {provisioner!r})"
        )

    vol_size = (kcfg.get("volume") or {}).get("size")
    if vol_size and not _QUANTITY_RE.match(str(vol_size)):
        problems.append(
            f"terminal.kubernetes.volume.size={vol_size!r} is not a valid "
            "Kubernetes quantity (e.g. 50Gi)"
        )

    for field in ("namespace", "container_name"):
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

    pod_template = kcfg.get("pod_template")
    problems.extend(
        _shape_problems(pod_template, "terminal.kubernetes.pod_template")
    )
    problems.extend(
        reserved_violations(
            pod_template,
            container_name=container_name(kcfg),
            mount_path=mount_path(kcfg),
        )
    )
    problems.extend(
        reserved_sandbox_spec_violations((kcfg.get("sandbox") or {}).get("spec"))
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
    """Name of the container this backend builds and execs into."""
    return str(kcfg.get("container_name") or "").strip() or WORKSPACE_CONTAINER_NAME


def mount_path(kcfg: dict) -> str:
    """Path the workspace volume is mounted at (and the session's default cwd)."""
    return str(kcfg.get("mount_path") or "").strip() or "/workspace"


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

    This is the ONE function that produces a pod template, and NOTHING runs
    after it.  :class:`PodProvisioner` wraps the result in a ``Pod``; the
    sandbox provisioner ASSIGNS it to ``Sandbox.spec.podTemplate`` (assignment,
    never a merge, so there is no second source);
    :func:`unhardened_reasons` calls it with the same config.  What is judged
    is therefore byte-for-byte what is submitted, for both provisioners.

    A hardened base is built from backend state (image, resources, the
    workspace volume, the exec container), then ``terminal.kubernetes.
    pod_template`` is merged over it exactly once by :func:`merge_pod_template`.

    Raises ``ValueError`` when ``pod_template`` claims a reserved field.  That
    is belt-and-braces over :func:`validate_kubernetes_config` and it buys the
    fail-closed path for free: :func:`unhardened_reasons` converts the raise
    into "could not be rendered", so an unvalidated violating config keeps the
    dangerous-command guards on rather than earning the approval skip.

    *owned* is False when no ownerReference could be resolved — the one case
    where a persistent pod also needs the activeDeadlineSeconds backstop,
    because nothing else would ever reap it.
    """
    exec_container = container_name(kcfg)
    workspace_path = mount_path(kcfg)

    violations = reserved_violations(
        kcfg.get("pod_template"),
        container_name=exec_container,
        mount_path=workspace_path,
    )
    if violations:
        raise ValueError("; ".join(violations))

    # --- the hardened base --------------------------------------------
    # Everything below is what a throwaway session sandbox looks like, and is
    # what unhardened_reasons() checks for. Users relax it through
    # pod_template, and the judge sees the relaxation.
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

    base = {"metadata": {"labels": dict(MANAGED_BY_LABEL)}, "spec": spec}

    # THE one and only user layer.
    template = merge_pod_template(base, kcfg.get("pod_template"))

    # Shape defensiveness, not a second override layer: merge_pod_template
    # faithfully replaces a dict with whatever the overlay supplies, so
    # `metadata: null` used to raise a bare AttributeError out of manifest
    # construction. The managed-by label is not negotiable (it is the selector
    # for k8s/networkpolicy.yaml and the ValidatingAdmissionPolicy
    # matchCondition), and setting it is already rejected above — a malformed
    # template loses its metadata, it does not lose the label.
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

    This is the ONE judge, and it judges the ONE rendered template: it calls
    :func:`render_pod_template` with the same config the selected provisioner
    does, and nothing runs after that call.  Judging a builder's output while a
    provisioner applied a further layer is what let ``provisioner: sandbox``
    keep the approval skip with ``hostPID``, ``hostNetwork``, a hostPath ``/``
    volume and a privileged container, purely by writing them under a second
    override key.  There is now no second key: ``sandbox.spec.podTemplate`` is
    rejected outright.

    Any exception fails closed — see ``_kubernetes_has_host_access``, which
    also treats a raise as untrusted.  That is load-bearing here: a config
    whose ``pod_template`` claims a reserved field makes
    :func:`render_pod_template` raise, and "could not be rendered" correctly
    reads as "not hardened".
    """
    reasons: list[str] = []
    if kcfg.get("persistent"):
        # `rm -rf /workspace` would destroy a PVC the user asked to keep.
        reasons.append("persistent: true (durable PVC workspace)")

    try:
        template = render_pod_template(
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
    # The base pins a no-perms SA, so this is no longer a config-echo check:
    # it fires only when a pod_template names a different one, whose powers
    # Hermes cannot establish. Unknown is not hardened.
    if str(spec.get("serviceAccountName") or "") != SESSION_SERVICE_ACCOUNT:
        reasons.append(
            f"serviceAccountName {spec.get('serviceAccountName')!r} is not the "
            f"no-perms {SESSION_SERVICE_ACCOUNT!r}"
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

    def exec_container(self, pod: Any) -> str:
        """Assert the RECONCILED pod carries the container we exec into.

        The old behaviour was to fall back to the pod's FIRST container when
        the configured name was absent — needed while an operator could author
        the pod from a SandboxTemplate Hermes never read.  Nothing authors the
        pod but :func:`render_pod_template` now, and ``container_name`` is
        reserved, so a missing container means the object that ran is not the
        object that was rendered and judged.  Exec-ing into whatever else is
        there would be that drift, silently.
        """
        expected = self.container_name()
        names: list[str] = []
        for entry in (getattr(getattr(pod, "spec", None), "containers", None) or []):
            name = getattr(entry, "name", None)
            if name is None and isinstance(entry, dict):
                name = entry.get("name")
            if name:
                names.append(str(name))
        if not names or expected in names:
            return expected
        raise RuntimeError(
            f"session pod has no container {expected!r} (found "
            f"{', '.join(names)}); refusing to exec into a container this "
            "backend did not render. The running pod does not match the "
            "template Hermes submitted and evaluated."
        )

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
        round 2 (``PodProvisioner._is_ours``); this path had no check at
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
                **STRICT_FIELD_VALIDATION,
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
        return PodRef(self.namespace, pod_name, self.exec_container(pod))

    def destroy(self, pod_ref: PodRef, persistent: bool) -> None:
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
    "PodRef",
    "Resources",
    "WorkspaceProvisioner",
    "PodProvisioner",
    "KubernetesEnvironment",
    "render_pod_template",
    "merge_pod_template",
    "reserved_violations",
    "reserved_sandbox_spec_violations",
    "container_name",
    "mount_path",
    "unhardened_reasons",
    "merge_kubernetes_config",
    "validate_kubernetes_config",
    "load_kubernetes_apis",
    "resolve_namespace",
    "resolve_owner_reference",
    "sanitize_name",
    "in_cluster",
]
