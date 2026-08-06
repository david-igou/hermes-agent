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
``command``/``args``, ``restartPolicy``, the workspace mount/volume, the
managed-by label and ``metadata.ownerReferences``) are REJECTED rather than
silently overwritten.

Where that rejection is DECIDED matters, and it is the one design rule this
module keeps re-learning: **judge and enforce on the artifact that is actually
submitted, never on the user's input.**  :func:`rendered_reserved_violations`
compares the MERGED template against the hardened base Hermes built and rejects
any difference in the reserved core, so a violation is defined as "the rendered
pod is not the pod Hermes owns" rather than as a list of input shapes that are
known to produce one.  Input shapes are unbounded (a duplicate key in a merge-
keyed list, an alias, a merge quirk, whatever is found next); the rendered
artifact is one object with one set of values, so checking it closes the class.
:func:`reserved_violations` still reads the user's dict, but only as an EARLY,
FRIENDLY diagnostic that can name the offending config key — it is never the
thing that makes the guarantee, and every path that renders a template also
runs the rendered check.

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


#: Identity keys whose value is a filesystem path. A path is not a string for
#: identity purposes: ``/workspace/``, ``//workspace`` and ``/workspace/.`` all
#: name the directory ``/workspace``, and the kubelet mounts them at the same
#: place. Comparing the raw string let a second volumeMount shadow the reserved
#: workspace mount: the alias missed the merge index, so it was appended rather
#: than merged, no duplicate was detected, and the reserved diff still saw its
#: own untouched entry at the exact key. Normalise before every comparison so
#: an alias collides with the entry it aliases.
_PATH_VALUED_KEYS = frozenset({"mountPath", "devicePath"})


def _identity(key: str, value: Any) -> Any:
    """The value of *key* as used for identity, not as written."""
    if key in _PATH_VALUED_KEYS and isinstance(value, str):
        norm = posixpath.normpath(value)
        # normpath preserves exactly two leading slashes ("//workspace"),
        # because POSIX leaves that case implementation-defined. The kubelet
        # does not: it mounts at /workspace. Collapse them or the alias
        # survives normalisation and shadows the reserved mount anyway.
        if norm.startswith("//"):
            norm = "/" + norm.lstrip("/")
        return norm
    return value


def _merge_keyed_list(base: list, overlay: list, key: str, path: tuple) -> list:
    """Merge *overlay* into *base* element-wise on *key*; append unmatched."""
    merged = [deepcopy(item) for item in base]
    index = {
        _identity(key, item[key]): pos
        for pos, item in enumerate(merged)
        if isinstance(item, dict) and key in item
    }
    for item in overlay:
        ident = item.get(key) if isinstance(item, dict) else None
        ident = _identity(key, ident) if ident is not None else None
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


#: Every list inside a PodTemplateSpec that Kubernetes itself keys, and the key
#: it uses.  Superset of :data:`_MERGE_KEYS` (which is only about MERGE
#: semantics): a duplicate key is invalid in ALL of these, whether or not
#: Hermes merges the list element-wise.
#:
#: Duplicates are rejected because the merge HIDES them: ``_merge_keyed_list``
#: folds every overlay element with the same key into one base entry, so two
#: ``containers`` entries named ``workspace`` reach the API server as a single
#: container the server has no duplicate to complain about.  Rejecting them is
#: defence in depth behind :func:`rendered_reserved_violations` (which catches
#: the resulting artifact whatever route produced it), and it also stops a
#: non-reserved duplicate — two ``env`` entries named ``PATH``, say — from
#: silently collapsing into whichever one happens to win.
_KEYED_LIST_KEYS: dict[tuple, str] = {
    ("spec", "containers"): "name",
    ("spec", "initContainers"): "name",
    ("spec", "ephemeralContainers"): "name",
    ("spec", "volumes"): "name",
    ("spec", "imagePullSecrets"): "name",
}
for _field in ("containers", "initContainers", "ephemeralContainers"):
    _KEYED_LIST_KEYS[("spec", _field, "*", "volumeMounts")] = "mountPath"
    _KEYED_LIST_KEYS[("spec", _field, "*", "volumeDevices")] = "devicePath"
    _KEYED_LIST_KEYS[("spec", _field, "*", "env")] = "name"
    _KEYED_LIST_KEYS[("spec", _field, "*", "ports")] = "containerPort"
del _field


def _display_path(path: tuple) -> str:
    """``("spec", "containers", "*", "env")`` -> ``spec.containers[].env``."""
    out = ""
    for part in path:
        if part == "*":
            out += "[]"
        else:
            out += f".{part}" if out else str(part)
    return out


def duplicate_keyed_entry_problems(
    node: Any, label: str = "terminal.kubernetes.pod_template", _path: tuple = ()
) -> list[str]:
    """Duplicate keys in any list Kubernetes keys (empty when clean)."""
    problems: list[str] = []
    if not isinstance(node, dict):
        return problems
    for key, value in node.items():
        path = _path + (key,)
        if isinstance(value, dict):
            problems.extend(duplicate_keyed_entry_problems(value, label, path))
            continue
        if not isinstance(value, list):
            continue
        merge_key = _KEYED_LIST_KEYS.get(path)
        if merge_key is not None:
            counts: dict[Any, int] = {}
            for item in value:
                if isinstance(item, dict) and merge_key in item:
                    # Normalised: '/workspace/' duplicates '/workspace'.
                    ident = _identity(merge_key, item[merge_key])
                    try:
                        counts[ident] = counts.get(ident, 0) + 1
                    except TypeError:  # unhashable key value
                        continue
            for ident, count in counts.items():
                if count > 1:
                    problems.append(
                        f"{label}.{_display_path(path)} declares {count} entries "
                        f"with {merge_key}={ident!r}. Kubernetes keys this list "
                        f"on {merge_key}, so duplicates are invalid — and the "
                        "Hermes merge folds them into ONE entry, which is how a "
                        "second entry reaches the pod without being read as a "
                        "second entry. Declare it once."
                    )
        for item in value:
            if isinstance(item, dict):
                problems.extend(
                    duplicate_keyed_entry_problems(item, label, path + ("*",))
                )
    return problems


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
    # `args` is reserved for the SAME reason `command` is, and reserving only
    # `command` did not deliver the guarantee: the kubelet builds the process
    # as command + args, so `args: ["--boom"]` runs `sleep infinity --boom`,
    # which exits non-zero immediately and — under the pinned
    # restartPolicy: Never — leaves a Failed pod that starts and can never
    # serve a command.
    "args": (
        'Hermes pins command: ["sleep", "infinity"] and the kubelet appends '
        "args to it, so any args value makes that process exit and the pod "
        "complete instead of outliving the session."
    ),
    "ownerReferences": (
        "Hermes owns session-pod adoption and garbage collection: the "
        "ownerReference to the agent's own pod is what reaps the session pod "
        "when the agent dies, and _is_ours()/_assert_ours() read it to decide "
        "whether an existing object may be reused."
    ),
}


def _elements(node: Any) -> list:
    """The list at *node*, or ``[]`` when it is absent or not a list."""
    return node if isinstance(node, list) else []


def _find_by(items: list, key: str, value: Any) -> Optional[dict]:
    """First element whose *key* identifies *value* (paths normalised)."""
    wanted = _identity(key, value)
    for item in items:
        if isinstance(item, dict) and _identity(key, item.get(key)) == wanted:
            return item
    return None


def reserved_violations(
    pod_template: Any, *, container_name: str, mount_path: str
) -> list[str]:
    """Reserved-core problems in the USER's ``pod_template`` (empty when clean).

    An EARLY, FRIENDLY diagnostic, not the enforcement point. It reads the
    user's dict so it can name the exact config key to delete, which the
    rendered comparison cannot do — but it is checking an input shape, and
    input shapes are unbounded. :func:`rendered_reserved_violations` is what
    makes the guarantee; it runs on every render, and a clean result here never
    stands in for a clean result there.

    Scans the user's dict only, never the merged result: the hardened base
    legitimately sets every reserved path, so judging the merge output as
    "present" would flag itself.

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

    # R1b — pod_manifest() only overwrites ownerReferences when an agent
    # identity was resolvable, so out-of-cluster a supplied list was copied
    # verbatim into the submitted Pod and never judged.
    metadata = pod_template.get("metadata")
    if isinstance(metadata, dict) and "ownerReferences" in metadata:
        problems.append(
            f"{base}.metadata.ownerReferences is reserved by the kubernetes "
            f"backend and cannot be set. {_RESERVED_RATIONALE['ownerReferences']} "
            "Remove the key; use terminal.kubernetes.owner_reference: off to "
            "opt out of adoption entirely."
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
            # R4 — the exec target's process. BOTH halves: the kubelet builds
            # it as command + args, so reserving `command` alone still let a
            # template make the session container exit immediately.
            for key in ("command", "args"):
                if key in target:
                    problems.append(
                        f"{base}.spec.containers[name={container_name}].{key} "
                        "is reserved by the kubernetes backend and cannot be "
                        f"set. {_RESERVED_RATIONALE[key]} Remove the key."
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


_RENDERED_PREFIX = (
    "the rendered pod template's {path} is not the value the kubernetes "
    "backend owns"
)


def _reserved_field_problem(path: str, got: Any, want: Any, why: str) -> str:
    return (
        f"{_RENDERED_PREFIX.format(path=path)}: terminal.kubernetes.pod_template "
        f"renders it as {got!r}, Hermes renders it as {want!r}. {why} Remove "
        "whatever in pod_template reaches that field."
    )


def rendered_reserved_violations(
    base: dict, rendered: Any, *, container_name: str, mount_path: str
) -> list[str]:
    """Reserved core on the SUBMITTED artifact — the enforcement point.

    Compares the merged template against the hardened base Hermes built from
    backend state and reports every reserved field the merge changed. It is
    stated as a property of the OUTPUT ("the pod that will be posted still
    carries Hermes' exec contract"), so it does not care what input shape
    produced the difference: a plain key, a duplicate entry in a merge-keyed
    list that ``_merge_keyed_list`` folded into the base entry, an alias, or
    anything not yet invented. Round 4 was exactly that — two ``containers``
    entries named ``workspace``, of which the input-side check read only the
    first while the merge applied both.

    Reserved paths, and why each is the pod's exec contract rather than pod
    shape (see :data:`_RESERVED_RATIONALE`):

    * ``metadata.labels[app.kubernetes.io/managed-by]`` — the selector for the
      NetworkPolicy, the admission policy and pod adoption;
    * ``metadata.ownerReferences`` — session-pod adoption and GC;
    * ``spec.restartPolicy`` — a restart swaps the workspace out mid-session;
    * the exec container: it must exist EXACTLY once, and its ``command`` /
      ``args`` are the process that outlives the session;
    * that container's mount at ``mount_path`` — the path ``terminal.cwd``
      resolves against;
    * ``spec.volumes[name=workspace]`` — the other half of that mount.
    """
    problems: list[str] = []
    if not isinstance(rendered, dict):
        return [
            "the rendered pod template is not a mapping "
            f"(got {type(rendered).__name__})"
        ]

    # A1 — the managed-by label. Absent only when the whole metadata/labels node
    # was replaced by a non-mapping, which _shape_problems reports and
    # render_pod_template repairs by re-stamping.
    want_key = MANAGED_BY_KEY
    present, value = _lookup(rendered, ("metadata", "labels", want_key))
    _, want = _lookup(base, ("metadata", "labels", want_key))
    if present and value != want:
        problems.append(_reserved_field_problem(
            f"metadata.labels[{want_key}]", value, want,
            "k8s/networkpolicy.yaml, k8s/validatingadmissionpolicy.yaml and "
            "session-pod adoption all select on that label.",
        ))

    # A2 — ownerReferences. The base never sets them; pod_manifest() adds the
    # agent's own reference when one was resolvable.
    metadata = rendered.get("metadata")
    if isinstance(metadata, dict) and "ownerReferences" in metadata:
        problems.append(_reserved_field_problem(
            "metadata.ownerReferences", metadata["ownerReferences"], None,
            _RESERVED_RATIONALE["ownerReferences"],
        ))

    spec = rendered.get("spec")
    base_spec = base.get("spec")
    if not isinstance(spec, dict) or not isinstance(base_spec, dict):
        return problems + ["the rendered pod template has no spec mapping"]

    # A3 — restartPolicy.
    if spec.get("restartPolicy") != base_spec.get("restartPolicy"):
        problems.append(_reserved_field_problem(
            "spec.restartPolicy", spec.get("restartPolicy"),
            base_spec.get("restartPolicy"),
            _RESERVED_RATIONALE["restartPolicy"],
        ))

    # A4 — the exec container, ONCE, with Hermes' process.
    targets = [
        entry for entry in _elements(spec.get("containers"))
        if isinstance(entry, dict) and entry.get("name") == container_name
    ]
    base_target = _find_by(
        _elements(base_spec.get("containers")), "name", container_name
    ) or {}
    if len(targets) != 1:
        problems.append(
            f"the rendered pod template declares {len(targets)} containers "
            f"named {container_name!r}; Hermes execs into exactly one "
            "(terminal.kubernetes.container_name). A pod that carries none is "
            "a pod no session can use, and duplicates are invalid to the API "
            "server, so this backend will not submit either."
        )
    else:
        # Kubernetes requires container names to be unique across all three
        # lists, and exec_container() resolves the name against the running
        # pod, so a same-named init/ephemeral container is both invalid and
        # ambiguous about which process the session would land in.
        for field in ("initContainers", "ephemeralContainers"):
            if any(
                isinstance(entry, dict) and entry.get("name") == container_name
                for entry in _elements(spec.get(field))
            ):
                problems.append(
                    f"the rendered pod template declares spec.{field}"
                    f"[name={container_name}] alongside the exec container of "
                    "the same name. Container names are unique across "
                    "containers, initContainers and ephemeralContainers; give "
                    "it another name."
                )
        target = targets[0]
        for key in ("command", "args"):
            got_present, got = _lookup(target, (key,))
            want_present, wanted = _lookup(base_target, (key,))
            if (got_present, got) != (want_present, wanted):
                problems.append(_reserved_field_problem(
                    f"spec.containers[name={container_name}].{key}",
                    got if got_present else None,
                    wanted if want_present else None,
                    _RESERVED_RATIONALE[key],
                ))
        # A5 — the workspace mount terminal.cwd resolves against.
        got_mounts = [
            m for m in _elements(target.get("volumeMounts"))
            if isinstance(m, dict) and m.get("mountPath") == mount_path
        ]
        want_mount = _find_by(
            _elements(base_target.get("volumeMounts")), "mountPath", mount_path
        )
        if got_mounts != ([want_mount] if want_mount is not None else []):
            problems.append(_reserved_field_problem(
                f"spec.containers[name={container_name}]"
                f".volumeMounts[mountPath={mount_path}]",
                got_mounts, want_mount,
                "That mount is the workspace terminal.cwd resolves against. "
                "Mount additional volumes at other paths, or change "
                "terminal.kubernetes.mount_path.",
            ))

    # A6 — the workspace volume itself.
    got_volumes = [
        v for v in _elements(spec.get("volumes"))
        if isinstance(v, dict) and v.get("name") == WORKSPACE_VOLUME_NAME
    ]
    want_volume = _find_by(
        _elements(base_spec.get("volumes")), "name", WORKSPACE_VOLUME_NAME
    )
    if got_volumes != ([want_volume] if want_volume is not None else []):
        problems.append(_reserved_field_problem(
            f"spec.volumes[name={WORKSPACE_VOLUME_NAME}]",
            got_volumes, want_volume,
            "Hermes builds it from terminal.kubernetes.persistent and "
            "terminal.kubernetes.volume.*.",
        ))
    return problems


#: Keys of the ``Sandbox`` CR spec that Hermes has actually reviewed and can
#: reason about — the allowlist half of the sandbox rule.
#:
#: ``ttlSeconds`` is here because it only ever SHORTENS the workspace's life
#: (it is the CR-level analogue of ``active_deadline_seconds``), so it cannot
#: relax the hardened pod. Everything else is unreviewed by construction: the
#: CRD is a third party's, ``sandbox.api_group``/``api_version`` are themselves
#: user config, and a two-name denylist cannot survive a CRD version whose
#: pod-authoring field has another name.
#:
#: Keyed by name AND shape: the ttlSeconds rationale ("it only ever SHORTENS
#: the workspace's life") is a claim about an integer, not about the name, so
#: an object smuggled under that key is unreviewed like anything else.
_REVIEWED_SANDBOX_SPEC_KEYS: dict[str, tuple] = {"ttlSeconds": (int, float)}


def _is_reviewed_sandbox_value(key: str, value: Any) -> bool:
    types = _REVIEWED_SANDBOX_SPEC_KEYS.get(key)
    if types is None:
        return False
    # bool is an int subclass, and `ttlSeconds: true` is not a TTL.
    return isinstance(value, types) and not isinstance(value, bool)


def unreviewed_sandbox_spec_keys(cr_spec: Any) -> list[str]:
    """CR-spec keys Hermes neither renders nor understands.

    On the sandbox path the artifact actually SUBMITTED is the whole Sandbox
    CR, not just its ``podTemplate``: :meth:`SandboxProvisioner.sandbox_manifest`
    deep-copies ``terminal.kubernetes.sandbox.spec`` into the body. Requirement
    2 ("exactly one artifact to render and to security-check") therefore only
    holds on that path if every part of the CR is either rendered by Hermes,
    reviewed by Hermes, or JUDGED as unknown.

    These keys are deliberately not a validation ERROR — a CR is extensible by
    design and a cluster may legitimately serve fields this Hermes build has
    never heard of. They are a JUDGE input instead: an unreviewed CR field
    costs the approval skip (see :func:`unhardened_reasons`) rather than being
    invisible, so the failure mode is "dangerous-command guards stay on", not
    "an unread field reached the API server wearing a hardened badge".
    """
    if not isinstance(cr_spec, dict):
        return []
    reserved = {"podTemplate", "sandboxTemplateRef"}
    return sorted(
        key for key, value in cr_spec.items()
        if not _is_reviewed_sandbox_value(key, value) and key not in reserved
    )


def sandbox_spec_reasons(cr_spec: Any) -> list[str]:
    """Why the SUBMITTED Sandbox CR cannot be established as a throwaway sandbox.

    The judge's sandbox arm. Reserved keys make the pod shape unknowable
    (``sandboxTemplateRef`` hands pod authorship to the operator; a second
    ``podTemplate`` decouples judged from submitted), and unreviewed keys are
    CR spec Hermes never read. Both are "unknown", and unknown is not hardened.
    """
    if cr_spec is not None and not isinstance(cr_spec, dict):
        # Unknown is not hardened, and a scalar here is a CR body this backend
        # cannot read at all (it also used to crash the manifest builder with a
        # bare TypeError while the judge said nothing).
        return [
            f"sandbox.spec is not a mapping (got {type(cr_spec).__name__}); this "
            "backend cannot establish what would be submitted"
        ]
    reasons = [
        f"sandbox.spec.{key} is an unreviewed Sandbox CR field: it is submitted "
        "verbatim and this backend cannot establish what it does to the pod"
        for key in unreviewed_sandbox_spec_keys(cr_spec)
    ]
    if isinstance(cr_spec, dict):
        if "sandboxTemplateRef" in cr_spec:
            reasons.append(
                "sandbox.spec.sandboxTemplateRef: the pod shape comes from a "
                "SandboxTemplate this backend never reads and cannot evaluate"
            )
        if "podTemplate" in cr_spec:
            reasons.append(
                "sandbox.spec.podTemplate: a second pod-template source means "
                "the object that was judged is not the object that is submitted"
            )
    return reasons


def reserved_sandbox_spec_violations(cr_spec: Any) -> list[str]:
    """Reserved-core problems in ``terminal.kubernetes.sandbox.spec``."""
    base = "terminal.kubernetes.sandbox.spec"
    if cr_spec is not None and not isinstance(cr_spec, dict):
        # Fail loudly HERE rather than as a TypeError from
        # `spec["podTemplate"] = ...` in the CR builder.
        return [f"{base} must be a mapping (got {type(cr_spec).__name__})"]
    if not isinstance(cr_spec, dict):
        return []
    problems: list[str] = []
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
    # The node ITSELF first. `pod_template:` written as a YAML list (a very
    # plausible mistake given the old "overrides" framing) used to be silently
    # discarded by merge_pod_template's non-dict early return — the whole user
    # layer vanished and the bare hardened base was submitted with no message.
    if node is not None and not isinstance(node, dict):
        return [f"{label} must be a mapping (got {type(node).__name__})"]
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


#: The keys the ~30-key collapse DELETED, and where their shape lives now.
#: Named individually so a config.yaml that still carries one gets told what
#: to do rather than a bare "unknown key".
_REMOVED_KUBERNETES_KEYS = {
    "pod_template_overrides": "pod_template",
    "image_pull_policy": "pod_template.spec.containers[].imagePullPolicy",
    "image_pull_secrets": "pod_template.spec.imagePullSecrets",
    "service_account": "pod_template.spec.serviceAccountName",
    "automount_service_account_token":
        "pod_template.spec.automountServiceAccountToken",
    "runtime_class_name": "pod_template.spec.runtimeClassName",
    "node_selector": "pod_template.spec.nodeSelector",
    "tolerations": "pod_template.spec.tolerations",
    "labels": "pod_template.metadata.labels",
    "annotations": "pod_template.metadata.annotations",
    "env": "pod_template.spec.containers[].env",
    "security_context": "pod_template.spec.securityContext (pod) / "
                        "pod_template.spec.containers[].securityContext",
    "resources": "pod_template.spec.containers[].resources",
}

#: Sub-blocks whose keys are enumerated (so unknown ones are rejected) versus
#: the two free-form nodes, which are open by construction.
_ENUMERATED_SUBTREES = ("volume", "sandbox")
_FREE_FORM_PATHS = frozenset({"pod_template", "sandbox.spec"})


def _unknown_key_problems(kcfg: Any) -> list[str]:
    """Reject keys that are not in the schema — the config-layer Strict.

    The API layer posts everything with ``field_validation="Strict"`` precisely
    so nothing user-supplied is silently dropped. The config layer used to do
    the opposite: a config.yaml still carrying ``security_context`` or
    ``node_selector`` (or a typo) validated clean, rendered without them, and
    said nothing — ``read_only_root_filesystem: true`` quietly became false.
    Only ``_migrate_to_34`` named those keys, and it fires once, only through
    hermes_cli, and only below ``_config_version`` 34; a hand-authored,
    gateway-bridged or already-migrated config kept them forever.
    """
    if not isinstance(kcfg, dict):
        return []
    problems: list[str] = []
    hint = (
        "Pod shape is ONE PodTemplateSpec under terminal.kubernetes."
        "pod_template, merged over a hardened base; see cli-config.yaml.example."
    )

    def _check(node: dict, schema: dict, prefix: str) -> None:
        for key in node:
            path = f"{prefix}{key}"
            if path in _FREE_FORM_PATHS or key in schema:
                continue
            moved = _REMOVED_KUBERNETES_KEYS.get(key)
            if moved:
                problems.append(
                    f"terminal.kubernetes.{path} was removed in config version "
                    f"34 and is now ignored. Re-express it as {moved}."
                )
            else:
                problems.append(
                    f"terminal.kubernetes.{path} is not a known setting. {hint}"
                )

    _check(kcfg, DEFAULT_KUBERNETES_CONFIG, "")
    for block in _ENUMERATED_SUBTREES:
        node = kcfg.get(block)
        if isinstance(node, dict):
            _check(node, DEFAULT_KUBERNETES_CONFIG[block], f"{block}.")
    return problems


def _mapping(node: Any, key: str) -> dict:
    """``node[key]`` when it is a mapping, else ``{}``.

    ``(kcfg.get("volume") or {})`` is not the same thing: a scalar written where
    a block belongs sails through ``or`` and made the VALIDATOR — the function
    whose whole job is to turn that into a message — raise AttributeError
    instead. :func:`_block_shape_problems` reports it; this keeps the rest of
    the checks running so the user gets the full list.
    """
    value = node.get(key) if isinstance(node, dict) else None
    return value if isinstance(value, dict) else {}


def _block_shape_problems(kcfg: dict) -> list[str]:
    """Scalars written where an enumerated sub-block belongs."""
    problems: list[str] = []
    if not isinstance(kcfg, dict):
        return problems
    for block in _ENUMERATED_SUBTREES:
        value = kcfg.get(block)
        if value is not None and not isinstance(value, dict):
            problems.append(
                f"terminal.kubernetes.{block} must be a mapping (got "
                f"{type(value).__name__})"
            )
    # sandbox.spec has its own reporter (reserved_sandbox_spec_violations), so
    # it is deliberately not repeated here.
    return problems


def _root_uid_problems(kcfg: dict) -> list[str]:
    """uid 0 requested against a base that pins ``runAsNonRoot: true``.

    The kubelet refuses such a container outright (CreateContainerConfigError),
    so this is a config error, not a privilege escape — but it is one the
    offline validator is here to catch. ``dry_run="All"`` + Strict cannot: the
    object is schema-valid, and Strict only rejects UNKNOWN fields.

    Judged on the EFFECTIVE value the kubelet computes — the container's
    ``securityContext`` falling back to the pod's — not per scope in isolation.
    Per-scope was blind to the most natural "let this session run as root"
    config there is: ``spec.securityContext: {runAsNonRoot: false, runAsUser:
    0}``. The pod scope is skipped because that scope's own ``runAsNonRoot`` is
    false, the container scope is skipped because that scope has no
    ``runAsUser`` — while the kubelet pairs the container's ``runAsNonRoot:
    true`` (which the hardened base pins) with the uid 0 it inherits from the
    pod, and refuses the pod. Setting it on the CONTAINER is the way to run as
    root, because that is the scope the kubelet actually reads.
    """
    try:
        template = render_pod_template(
            kcfg,
            persistent=bool(kcfg.get("persistent")),
            image=str(kcfg.get("image") or ""),
            resources=Resources(),
            pvc_name="hermes-ws",
        )
    except Exception:
        # Already reported by reserved_violations()/_shape_problems().
        return []
    spec = template.get("spec")
    if not isinstance(spec, dict):
        return []
    problems: list[str] = []
    pod_sctx = spec.get("securityContext")
    pod_sctx = pod_sctx if isinstance(pod_sctx, dict) else {}
    for field in ("containers", "initContainers"):
        for entry in _elements(spec.get(field)):
            if not isinstance(entry, dict):
                continue
            sctx = entry.get("securityContext")
            sctx = sctx if isinstance(sctx, dict) else {}
            # The kubelet's rule: the container's value when it has one, the
            # pod's otherwise. Each half can come from a different scope.
            uid_present, uid = _lookup(sctx, ("runAsUser",))
            if not uid_present:
                uid_present, uid = _lookup(pod_sctx, ("runAsUser",))
            nonroot_present, nonroot = _lookup(sctx, ("runAsNonRoot",))
            if not nonroot_present:
                nonroot_present, nonroot = _lookup(pod_sctx, ("runAsNonRoot",))
            if uid_present and uid == 0 and nonroot is not False:
                problems.append(
                    "terminal.kubernetes.pod_template.spec."
                    f"{field}[name={entry.get('name')}]: the EFFECTIVE "
                    "securityContext is runAsUser=0 with runAsNonRoot true "
                    "(either scope's value counts, and the hardened base pins "
                    "runAsNonRoot: true on the container), which the kubelet "
                    "rejects with CreateContainerConfigError. Pick a non-zero "
                    "uid, or set runAsNonRoot: false on the CONTAINER — the "
                    "scope the kubelet reads."
                )
    return problems


def validate_kubernetes_config(kcfg: dict) -> list[str]:
    """Return a list of human-readable config problems (empty when valid).

    Cheap, offline checks only — used by ``hermes doctor`` and by the backend
    itself before it ever talks to a cluster.  Reserved-core rejection lives
    here (:func:`pod_template_problems`), so a config that tries to own a field
    Hermes owns fails loudly with the exact dotted path instead of having its
    YAML silently overwritten.  It is the SAME function the renderer raises
    from, evaluated against the same rendered artifact, so "validates clean"
    and "renders" cannot come apart.

    Unknown and REMOVED keys are rejected too (:func:`_unknown_key_problems`):
    a hard cut that accepts the keys it cut is a silent no-op, which is the
    same class of bug ``field_validation="Strict"`` exists to close at the API
    layer.
    """
    problems: list[str] = []
    problems.extend(_unknown_key_problems(kcfg))
    problems.extend(_block_shape_problems(kcfg))
    provisioner = str(kcfg.get("provisioner") or "").strip().lower()
    if provisioner not in VALID_PROVISIONERS:
        problems.append(
            f"terminal.kubernetes.provisioner must be one of "
            f"{', '.join(VALID_PROVISIONERS)} (got {provisioner!r})"
        )

    vol_size = _mapping(kcfg, "volume").get("size")
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
    claim_name = str(_mapping(kcfg, "volume").get("claim_name") or "")
    if claim_name and not _is_rfc1123_name(claim_name):
        problems.append(
            f"terminal.kubernetes.volume.claim_name={claim_name!r} is not a "
            "valid RFC-1123 name (lowercase alphanumeric, '-', max 63 chars)"
        )

    # The /tmp emptyDir is unconditional (init_session() writes its env
    # snapshot there), so a workspace mounted at the same path is a
    # duplicate-mountPath pod the API server rejects at create time. Catching
    # it offline is this validator's whole job.
    if mount_path(kcfg) == "/tmp":
        problems.append(
            "terminal.kubernetes.mount_path=/tmp collides with the "
            "unconditional /tmp emptyDir this backend mounts on every session "
            "pod (init_session() writes its env snapshot there). The API "
            "server rejects duplicate mountPaths; pick another path."
        )

    problems.extend(pod_template_problems(kcfg))
    problems.extend(
        reserved_sandbox_spec_violations(_mapping(kcfg, "sandbox").get("spec"))
    )
    problems.extend(_root_uid_problems(kcfg))
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


def _hardened_base(
    kcfg: dict,
    *,
    persistent: bool,
    image: str,
    resources: Resources,
    pvc_name: str,
    owned: bool = True,
) -> dict:
    """The pod template Hermes owns, before any user layer.

    Split out of :func:`render_pod_template` so the reserved-core check can
    compare the RENDERED artifact against the values this function produced,
    rather than against a second hand-written copy of them that could drift.
    """
    exec_container = container_name(kcfg)
    workspace_path = mount_path(kcfg)

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

    return {"metadata": {"labels": dict(MANAGED_BY_LABEL)}, "spec": spec}


def pod_template_problems(kcfg: Any) -> list[str]:
    """Every ``pod_template`` problem, judged on the artifact it RENDERS.

    One implementation shared by :func:`validate_kubernetes_config` (which
    reports) and :func:`render_pod_template` (which raises), so the two can
    never disagree about what is acceptable — the config that validates clean
    is exactly the config that renders.

    The render arguments here are representative: they change the base's image,
    PVC name and deadline, none of which is reserved. The reserved comparison is
    always base-versus-rendered from the SAME base, so it is exact either way.
    """
    if not isinstance(kcfg, dict):
        return []
    base = _hardened_base(
        kcfg,
        persistent=bool(kcfg.get("persistent")),
        image=str(kcfg.get("image") or ""),
        resources=Resources(),
        pvc_name="hermes-ws",
    )
    rendered = merge_pod_template(base, kcfg.get("pod_template"))
    return (
        _shape_problems(kcfg.get("pod_template"), "terminal.kubernetes.pod_template")
        + _reserved_problems(kcfg, base, rendered)
    )


def _reserved_problems(kcfg: dict, base: dict, rendered: Any) -> list[str]:
    """Duplicate-key + reserved-core problems for one rendered template.

    Deliberately NOT the shape checks: a malformed ``metadata`` is repaired by
    the re-stamp in :func:`render_pod_template` and reported by
    :func:`_shape_problems`, so it must not also make rendering fail.
    """
    pod_template = kcfg.get("pod_template")
    problems = duplicate_keyed_entry_problems(pod_template)
    # The friendly, input-side diagnostic (names the config key to delete)...
    problems.extend(reserved_violations(
        pod_template,
        container_name=container_name(kcfg),
        mount_path=mount_path(kcfg),
    ))
    # ...and the one that makes the guarantee, on what would be submitted.
    problems.extend(rendered_reserved_violations(
        base, rendered,
        container_name=container_name(kcfg),
        mount_path=mount_path(kcfg),
    ))
    return problems


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
    pod_template`` is merged over it exactly once by :func:`merge_pod_template`,
    and the RESULT is compared against that base
    (:func:`rendered_reserved_violations`).  Checking the output rather than
    the input is what makes the reserved core hold for input shapes nobody
    enumerated.

    Raises ``ValueError`` when the rendered template's reserved core differs
    from the base's (or when ``pod_template`` claims a reserved field, or
    declares a duplicate key in a list Kubernetes keys).  That is
    belt-and-braces over :func:`validate_kubernetes_config` and it buys the
    fail-closed path for free: :func:`unhardened_reasons` converts the raise
    into "could not be rendered", so an unvalidated violating config keeps the
    dangerous-command guards on rather than earning the approval skip.

    *owned* is False when no ownerReference could be resolved — the one case
    where a persistent pod also needs the activeDeadlineSeconds backstop,
    because nothing else would ever reap it.
    """
    base = _hardened_base(
        kcfg, persistent=persistent, image=image, resources=resources,
        pvc_name=pvc_name, owned=owned,
    )

    # THE one and only user layer.
    template = merge_pod_template(base, kcfg.get("pod_template"))

    violations = _reserved_problems(kcfg, base, template)
    if violations:
        raise ValueError("; ".join(violations))

    # Shape defensiveness, not a second override layer: merge_pod_template
    # faithfully replaces a dict with whatever the overlay supplies, so
    # `metadata: null` used to raise a bare AttributeError out of manifest
    # construction. The managed-by label is not negotiable (it is the selector
    # for k8s/networkpolicy.yaml and the ValidatingAdmissionPolicy
    # matchCondition), and CHANGING it is already rejected above — a malformed
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


#: seccomp profile types that keep the syscall floor the hardened base pins.
_CONFINED_SECCOMP_TYPES = frozenset({"RuntimeDefault", "Localhost"})


def _confinement_reasons(
    sctx: Any, label: str, *, require_seccomp: bool = False
) -> list[str]:
    """Runtime-confinement floors a securityContext can silently relax.

    The base pins ``seccompProfile: RuntimeDefault``; ``pod_template`` is the
    documented free-form layer sitting on top of it, so every axis that turns
    that confinement off has to cost the approval skip. AppArmor/SELinux are
    here for the same reason ``spc_t`` is a well-known OpenShift escape.

    *require_seccomp* is the pod scope, where the profile is a FLOOR rather
    than an override: reading a value only when it is present made an explicit
    ``seccompProfile: null`` — which the merge faithfully applies, deleting the
    base's RuntimeDefault — invisible to the very check that exists to notice
    it. Container scopes inherit the pod's, so absence there is normal.
    """
    if not isinstance(sctx, dict):
        return []
    reasons: list[str] = []
    seccomp = sctx.get("seccompProfile")
    if isinstance(seccomp, dict):
        if str(seccomp.get("type") or "") not in _CONFINED_SECCOMP_TYPES:
            reasons.append(
                f"{label}.seccompProfile.type is {seccomp.get('type')!r}, not "
                "RuntimeDefault/Localhost"
            )
    elif seccomp is not None:
        reasons.append(f"{label}.seccompProfile is not a mapping")
    elif require_seccomp:
        reasons.append(
            f"{label}.seccompProfile is not set; the hardened base pins "
            "RuntimeDefault, so the pod submitted has no seccomp floor"
        )
    apparmor = sctx.get("appArmorProfile")
    if isinstance(apparmor, dict) and str(apparmor.get("type") or "") == "Unconfined":
        reasons.append(f"{label}.appArmorProfile.type is Unconfined")
    if sctx.get("seLinuxOptions"):
        reasons.append(
            f"{label}.seLinuxOptions is set; this backend cannot establish "
            "what the requested SELinux context permits"
        )
    return reasons


#: Annotation families that change the sandbox itself rather than describe it.
#: ``metadata.annotations`` is copied verbatim into the submitted template and
#: is not reserved, so the judge is the only thing that sees these.
_APPARMOR_ANNOTATION = "container.apparmor.security.beta.kubernetes.io/"
_KATA_ANNOTATION = "io.katacontainers.config."


def _annotation_reasons(template: Any) -> list[str]:
    """Pod annotations that relax or reconfigure the sandbox.

    The deprecated AppArmor beta annotation is a metadata KEY, not a
    securityContext field, so the ``appArmorProfile`` check never sees it —
    ``…/workspace: unconfined`` turned confinement off in complete silence. The
    Kata family is the same shape and matters more here: when the runtime
    handler allowlists them, ``io.katacontainers.config.hypervisor.*`` changes
    the VM the workload runs in, and this backend has reviewed none of it.
    """
    reasons: list[str] = []
    for key, value in _dig_dict(template, "metadata", "annotations").items():
        name = str(key)
        if name.startswith(_APPARMOR_ANNOTATION):
            text = str(value)
            if text != "runtime/default" and not text.startswith("localhost/"):
                reasons.append(
                    f"annotation {name}={text!r} relaxes AppArmor confinement"
                )
        elif name.startswith(_KATA_ANNOTATION):
            reasons.append(
                f"annotation {name} reconfigures the Kata sandbox VM and is not "
                "reviewed by this backend"
            )
    return reasons


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

    On the sandbox path the object SUBMITTED is the whole Sandbox CR, so the
    judge also evaluates ``sandbox.spec`` (:func:`sandbox_spec_reasons`) —
    independently of whether ``validate_kubernetes_config`` was ever called.
    That is deliberate: the judge must not depend on validation having run,
    because a reserved ``sandboxTemplateRef`` makes the pod shape unknowable
    and unknown is not hardened.
    """
    reasons: list[str] = []
    if kcfg.get("persistent"):
        # `rm -rf /workspace` would destroy a PVC the user asked to keep.
        reasons.append("persistent: true (durable PVC workspace)")

    # The sandbox arm. NOT gated on validation: unknown is not hardened, and a
    # future change that turns validation into a warning must not silently
    # reopen the operator-authored-pod door.
    if str(kcfg.get("provisioner") or "").strip().lower() == "sandbox":
        sandbox = kcfg.get("sandbox")
        if sandbox is not None and not isinstance(sandbox, dict):
            reasons.append(
                f"sandbox is not a mapping (got {type(sandbox).__name__}); this "
                "backend cannot establish what would be submitted"
            )
        reasons.extend(sandbox_spec_reasons(_mapping(kcfg, "sandbox").get("spec")))

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

    return reasons + template_reasons(template)


def template_reasons(template: dict) -> list[str]:
    """Judge a RENDERED pod template — the object provisioners actually submit.

    Split out of :func:`unhardened_reasons` so a test can judge the artifact a
    provisioner really POSTs, rather than re-judging the config and trusting
    that the two agree. That equality is requirement 2, and asserting it needs
    a judge that takes a template.
    """
    reasons: list[str] = []
    spec = template.get("spec")
    if not isinstance(spec, dict):
        return reasons + ["pod template has no spec mapping"]
    psc = spec.get("securityContext") or {}
    if psc.get("runAsNonRoot") is not True:
        reasons.append("pod securityContext.runAsNonRoot is not true")
    if psc.get("runAsUser") == 0:
        reasons.append("pod securityContext.runAsUser is 0")
    reasons.extend(
        _confinement_reasons(psc, "pod securityContext", require_seccomp=True)
    )
    reasons.extend(_annotation_reasons(template))
    if spec.get("shareProcessNamespace"):
        # Every container sees (and can /proc-inspect) every other container's
        # process tree, including anything a sidecar holds in memory.
        reasons.append("shareProcessNamespace is enabled")
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
        reasons.extend(
            _confinement_reasons(csc, f"container {name} securityContext")
        )
        if csc.get("procMount") not in (None, "Default"):
            # Unmasked exposes /proc/kcore, /proc/sysrq-trigger and friends.
            reasons.append(
                f"container {name} sets procMount {csc['procMount']!r} "
                "(not Default)"
            )
        if entry.get("lifecycle"):
            # postStart/preStop run as the container's user with the pod's
            # network and mounts, and nothing here renders or reviews them.
            reasons.append(
                f"container {name} declares a lifecycle hook this backend did "
                "not render"
            )
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
            "spec": template["spec"],
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
    "reserved_violations",
    "rendered_reserved_violations",
    "duplicate_keyed_entry_problems",
    "pod_template_problems",
    "reserved_sandbox_spec_violations",
    "unreviewed_sandbox_spec_keys",
    "sandbox_spec_reasons",
    "container_name",
    "mount_path",
    "unhardened_reasons",
    "template_reasons",
    "merge_kubernetes_config",
    "validate_kubernetes_config",
    "load_kubernetes_apis",
    "resolve_namespace",
    "resolve_owner_reference",
    "sanitize_name",
    "in_cluster",
]
