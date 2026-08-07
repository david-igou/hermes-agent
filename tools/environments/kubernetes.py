"""Kubernetes session-pod execution environment.

Runs each agent command by exec-ing into a session pod.  Session pods are
STATELESS: the workspace is an emptyDir that dies with the pod.

A session pod is scoped to the Hermes PROCESS, not to a conversation:
:func:`_resolve_container_task_id` collapses nearly every caller to the key
``"default"``, so concurrent browser sessions, crons and chat-platform users
served by one gateway share one pod and one ``/workspace`` — the same
behaviour as the docker backend.  A distinct pod appears only for a distinct
Hermes process, or when a harness registers an isolation override.  See the
"Session scope" section of ``k8s/README.md``.

:class:`PodProvisioner`, behind the :class:`WorkspaceProvisioner` seam,
creates the session pod directly via the core API from
``terminal.kubernetes.spec``, which is REQUIRED and is the whole
PodTemplateSpec.  Its ``spec`` is posted verbatim: no default base, no merge,
nothing reserved.  Hermes sets only ``metadata`` it must compute (name,
namespace, ownerReferences, the managed-by/instance labels when absent) — see
:func:`render_session_object`.

That is deliberate.  The first cut shipped a default base plus an RFC 7386
merge with a containers-by-name exception, which meant predicting your own pod
required knowing a base you could not see and simulating a merge rule in your
head.  A template you read start to finish has no such failure mode; the cost
is that you write the whole thing, and ``k8s/session-pod-template.yaml`` is
there so you start from something that works.

Validating the pod is the CLUSTER's job.  SCC, Pod Security Admission,
ValidatingAdmissionPolicy, NetworkPolicy and RBAC decide what a session pod
may be; every create passes ``field_validation="Strict"`` so a malformed field
is a ``400`` naming the exact JSON path.  There is deliberately no in-process
config validation — an approximation of admission control is redundant where
it agrees and wrong where it does not.

Every setting lives in ``config.yaml`` under ``terminal.kubernetes.*`` (see
:data:`DEFAULT_KUBERNETES_CONFIG`), bridged as ONE internal
``TERMINAL_KUBERNETES`` var: ``.env`` is for secrets, and this backend has no
credential of its own.  Auth resolution: an explicit ``terminal.kubernetes.kubeconfig`` wins,
otherwise the in-cluster ServiceAccount, otherwise the ambient ``KUBECONFIG``.

``kubernetes`` SDK imports are function-local so this module (and its manifest
builders) load without the client installed.  See ``k8s/README.md`` for the
deployment manifests.
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
import uuid
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
#: Stamped with :func:`_instance_discriminator`, so an operator can tell THIS
#: process's session pods from a previous process's leftovers. Diagnostic
#: only — nothing in this backend selects on it, and there is deliberately no
#: automatic sweep: a sweep cannot distinguish "a pod my crashed predecessor
#: left" from "a pod a live sibling process is using", and deleting the second
#: kind destroys a running agent's workspace. Leftovers are collected by the
#: ownerReference (agent pod dies -> session pods GC) and by whatever
#: ``spec.activeDeadlineSeconds`` your template sets.
INSTANCE_LABEL = "hermes.nousresearch.com/instance"


#: SCAFFOLDING, not a default. `hermes setup` WRITES this into the user's
#: config.yaml under terminal.kubernetes so they start from
#: something that runs; nothing merges it at request time, and a config that
#: lacks a spec is an error rather than a quiet fallback to this. Keep it in
#: step with k8s/session-pod-template.yaml, which is the same object with the
#: explanation attached (pinned by
#: test_the_starter_constant_matches_the_shipped_yaml).
#:
#: Shaped like the config block it seeds — apiVersion/kind/metadata/spec — so
#: `hermes setup` writes something an operator can also read as a manifest.
STARTER_SESSION_OBJECT: dict[str, Any] = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"labels": dict(MANAGED_BY_LABEL)},
    "spec": {
        "containers": [{
            "name": "workspace",
            "image": "ubuntu:26.04",
            "command": ["sleep", "infinity"],
            "workingDir": "/workspace",
            "volumeMounts": [
                {"name": "workspace", "mountPath": "/workspace"},
                {"name": "tmp", "mountPath": "/tmp"},
            ],
            "securityContext": {
                "runAsNonRoot": True,
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
            },
        }],
        "volumes": [
            {"name": "workspace", "emptyDir": {}},
            {"name": "tmp", "emptyDir": {}},
        ],
        "shareProcessNamespace": True,
        "restartPolicy": "Never",
        "terminationGracePeriodSeconds": 1,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        "activeDeadlineSeconds": 14400,
        "securityContext": {
            "runAsNonRoot": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    },
}


# ---------------------------------------------------------------------------
# Configuration schema
# ---------------------------------------------------------------------------
#
# Mirrored verbatim in hermes_cli/config_defaults.py -> DEFAULT_CONFIG
# ["terminal"]["kubernetes"] (a literal is required there so `hermes config
# set` key validation and the desktop schema can walk it).  The two are pinned
# together by tests/tools/test_kubernetes_config_schema.py.
# The block is SHAPED LIKE THE OBJECT IT CREATES. `apiVersion`, `kind`,
# `metadata` and `spec` mean exactly what they mean in any manifest, so a pod
# you already have is a copy-paste away from being your session pod, and
# `kubectl explain` is the reference for three quarters of this schema.
# Connection and backend-behaviour keys sit alongside them.
DEFAULT_KUBERNETES_CONFIG: dict[str, Any] = {
    # --- connection ----------------------------------------------------
    "namespace": "",                  # "" -> the projected SA namespace file
    "kubeconfig": "",                 # out-of-cluster dev only (a path, not a secret)
    "context": "",                    # kubeconfig context; ignored in-cluster
    # --- the object ----------------------------------------------------
    # `kind` is the provisioner seam. It replaced a `provisioner: pod` enum
    # that named the same thing twice: an operator writing `kind: Pod` has
    # already said which provisioner they want, and a second kind (a sandbox
    # CRD, say) then needs no new config key at all — just a dispatch entry in
    # PROVISIONERS_BY_KIND. Unknown kinds fail in-process, because nothing
    # downstream could tell you which kinds this Hermes actually implements.
    "apiVersion": "v1",
    "kind": "Pod",
    # Labels/annotations for the objects Hermes creates. `name` and `namespace`
    # are NOT yours (see PodProvisioner.pod_manifest) — they are computed per
    # pod and are how Hermes finds the object again.
    "metadata": {},
    # REQUIRED, and it is the whole PodSpec: posted verbatim, no default base,
    # no merge, nothing filled in. Empty means unset — render_session_object()
    # raises a pointer to k8s/session-pod-template.yaml rather than inventing
    # a pod. (Was `pod_template`, which held metadata and spec together and so
    # had to explain which half was really yours.)
    "spec": {},
    # --- backend behaviour ----------------------------------------------
    # WHICH container in `spec` this backend execs into. A pointer into the
    # spec, not a thing that creates one.
    "exec_container_name": "workspace",
    # What marks an object as THIS backend's. Stamped into `metadata.labels`
    # when absent, and matched in PodProvisioner._is_ours before a 409 is
    # treated as "resume". Configurable because it used to be a hardcoded
    # constant: an operator relabelling their pods (chargeback, a different
    # platform convention) fell out of the ownership check against their own
    # objects. The ownerReference UID remains the actual proof; this is the
    # cheap filter and the thing k8s/networkpolicy.yaml selects on.
    # Empty means :data:`MANAGED_BY_LABEL`. Deliberately empty rather than
    # spelled out: a non-empty mapping default gets flattened into the web
    # settings schema as `...owned_selector.app.kubernetes.io/managed-by`, the
    # only schema path in the codebase with a `/` inside a segment — the
    # dashboard's dotted-path splitter then rewrites it as nested objects on
    # any edit or category Reset, and every pod create 422s on an invalid
    # label value. An empty default also makes "replace vs merge" moot.
    "owned_selector": {},
    # --- lifetime -------------------------------------------------------
    # No active_deadline_seconds key: that is spec.activeDeadlineSeconds and
    # belongs in `spec` like every other PodSpec field. Set it — without it
    # nothing bounds a session pod whose agent died unowned.
    #
    # This one is NOT pod shape: it is how long Hermes waits for Ready before
    # giving up, so it stays config.
    "ready_timeout_seconds": 120,
    "owner_reference": "auto",        # auto | off
}

#: Which provisioner serves which object kind. The seam the old
#: `provisioner` enum existed to provide, expressed in the field an operator
#: was going to write anyway.
PROVISIONERS_BY_KIND: dict[tuple, str] = {
    ("v1", "Pod"): "pod",
}

# The token is what actually matters, and it is off in the SHIPPED TEMPLATE —
# not "regardless", which is what this comment used to claim. `spec` is yours,
# so a spec that omits `automountServiceAccountToken: false` projects the
# namespace default SA's credentials straight into the agent's shell. That is
# a question no admission controller asks, so preflight_spec() warns about it.
# Set spec.serviceAccountName to bind a specific SA (the no-perms one in
# k8s/rbac.yaml, or your own); what it may then do is RBAC's answer.

# THE validation mechanism for pod content. Unknown/duplicate fields must 400
# with the offending path, not be silently dropped. The python client discards
# the API server's "Warning: 299 - unknown field" header, so Warn (the v1.23+
# server default) is indistinguishable from success: a typo'd
# securityContext.runAsNonroot comes back 201 with runAsNonRoot unset and
# nothing logged. `spec` is free-form user YAML posted verbatim, so every
# create this backend issues passes Strict and the API server — which owns the
# schema — reports the exact JSON path Hermes could only have guessed at.
STRICT_FIELD_VALIDATION: dict[str, str] = {"field_validation": "Strict"}

# Socket-level ceiling on every API call this backend issues. The python
# client leaves `_request_timeout` unset by default, which means urllib3
# builds no Timeout at all and a blackholed apiserver (dropped SYN/ACK on a
# rolling control plane, a wedged LB) pins the calling thread forever —
# `ready_timeout_seconds` cannot expire, because the deadline is only checked
# BETWEEN polls. Tuple is (connect, read).
API_TIMEOUT: tuple[float, float] = (5.0, 30.0)
# Transient statuses worth retrying, mirroring the taxonomy the repo already
# uses for HTTP APIs (tools/microsoft_graph_client.py). 429 = apiserver
# priority-and-fairness shedding load; 5xx = an apiserver/etcd hiccup or a
# rolling control plane. Never 4xx-other: those are our request being wrong,
# and retrying them just repeats the mistake.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_RETRY_ATTEMPTS = 4


def _retry_after_seconds(exc: Any, attempt: int) -> float:
    """Honour the apiserver's Retry-After, else exponential backoff."""
    headers = getattr(exc, "headers", None)
    if headers is not None:
        try:
            raw = headers.get("Retry-After")
            if raw is not None:
                return max(0.0, min(30.0, float(raw)))
        except (TypeError, ValueError, AttributeError):
            pass
    return min(8.0, 0.5 * (2 ** attempt))


def _reload_kubernetes_auth() -> None:
    """Re-read in-cluster credentials after a 401.

    Only meaningful in-cluster, where the kubelet rotates the projected
    ServiceAccount token on disk; out-of-cluster the kubeconfig's own exec/
    refresh plugins already handle expiry, and reloading would clobber an
    explicitly selected context.
    """
    if not in_cluster():
        return
    from kubernetes import config as k8s_config

    k8s_config.load_incluster_config()


def api_call(fn, *args, **kwargs):
    """Invoke a kubernetes client method with a timeout and transient retries.

    Every non-exec call this backend makes goes through here. Two things the
    client does not do for you:

    * ``_request_timeout`` — unset by default (see :data:`API_TIMEOUT`);
    * retries — ``Configuration.retries`` is None, so urllib3 does not retry
      either, and a single 503 during a control-plane rollout would abort a
      session start (and, worse, trip the cleanup path that deletes the pod
      it had just created).

    Exec is deliberately NOT routed through here: it owns its own deadline
    and cancellation semantics, and a retried exec would re-run a command.
    """
    import time as _time

    from kubernetes.client.exceptions import ApiException

    kwargs.setdefault("_request_timeout", API_TIMEOUT)
    last: Exception
    refreshed = False
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            return fn(*args, **kwargs)
        except ApiException as exc:
            if exc.status == 401 and not refreshed:
                # The in-cluster loader installs a hook that re-reads the
                # projected token, but nothing RETRIES the call that raced
                # its rotation — and a long-lived agent outlives any token.
                # One reload, one retry, then surface it. 403 is deliberately
                # NOT retried: that is RBAC, and the message we already raise
                # names the missing verb better than a retry ever could.
                refreshed = True
                logger.info("got 401; reloading credentials and retrying")
                try:
                    _reload_kubernetes_auth()
                except Exception as reload_exc:
                    logger.debug("credential reload failed: %s", reload_exc)
                    raise
                continue
            if exc.status not in _RETRY_STATUSES:
                raise
            last = exc
        except TypeError:
            # Mocked/older client without _request_timeout: call it plainly
            # rather than failing, but do not silently drop the timeout for
            # real clients — only this one call loses it.
            kwargs.pop("_request_timeout", None)
            return fn(*args, **kwargs)
        except (OSError, ConnectionError) as exc:
            # Connection reset / DNS blip / apiserver LB failover.
            last = exc
        if attempt < _RETRY_ATTEMPTS - 1:
            delay = _retry_after_seconds(last, attempt)
            logger.info(
                "retrying %s after transient error (%s); attempt %d/%d "
                "in %.1fs", getattr(fn, "__name__", fn), last, attempt + 2,
                _RETRY_ATTEMPTS, delay,
            )
            _time.sleep(delay)
    raise last


def pod_cannot_exec(pod: Any, exec_container: str) -> bool:
    """True when *pod* exists but can never serve another exec.

    Three shapes, all of which leave the object PRESENT (so a 404-only or
    phase-only check misses them) while `connect_get_namespaced_pod_exec`
    starts returning 400/500 forever:

    * **phase Failed/Succeeded** — activeDeadlineSeconds, eviction, or the
      last container exiting under ``restartPolicy: Never``;
    * **the exec container terminated inside a still-Running pod** — the
      phase only turns terminal once EVERY regular container has exited, so
      a pod with a sidecar (one the operator added through `spec`, or an
      injected mesh proxy) stays Running while the container we exec into is
      gone;
    * **deletionTimestamp set** — a pod stuck Terminating (node loss, a
      finalizer) reports phase Running indefinitely.
    """
    status = getattr(pod, "status", None)
    if getattr(status, "phase", "") in ("Failed", "Succeeded"):
        return True
    metadata = getattr(pod, "metadata", None)
    if getattr(metadata, "deletion_timestamp", None) is not None:
        return True
    for entry in (getattr(status, "container_statuses", None) or []):
        if getattr(entry, "name", None) != exec_container:
            continue
        state = getattr(entry, "state", None)
        if getattr(state, "terminated", None) is not None:
            return True
    return False


def merge_kubernetes_config(user_config: Any) -> dict:
    """Merge a (possibly partial) ``terminal.kubernetes`` block over defaults.

    Two of the three config→env bridges (``cli.py`` and ``gateway/run.py``) do
    NOT deep-merge ``DEFAULT_CONFIG`` before bridging, so a user who sets only
    ``terminal.kubernetes.namespace`` produces ``{"namespace": "..."}`` here.
    Every consumer must therefore go through this function rather than indexing
    the parsed payload directly.

    A SHALLOW update, deliberately. Every dict-valued default here is ``{}``
    (``metadata``, ``spec``, ``owned_selector``), so a recursive merge could
    only ever bottom out in a copy of the user's value — it was an identity
    wrapper. Shallow also gives the semantics the keys want: a user's
    ``owned_selector`` REPLACES rather than accumulating onto a default label
    they never wrote.

    Pinned by ``test_every_nested_default_is_empty``: adding a non-empty dict
    default here would silently flip that key from replace to merge.
    """
    merged = deepcopy(DEFAULT_KUBERNETES_CONFIG)
    if isinstance(user_config, dict):
        merged.update(deepcopy(user_config))
    return merged


# There is deliberately no validate_kubernetes_config(). The API server owns
# the schema (every create passes fieldValidation=Strict, so a malformed or
# unknown field is a 400 naming the exact JSON path) and the cluster's
# admission stack owns what a pod may be. The one thing Hermes must decide
# itself — which provisioner to build — raises in the environment factory.


# ---------------------------------------------------------------------------
# Small value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PodRef:
    """Coordinates for exec-ing into a session pod.

    ``uid`` makes teardown precise. Session pod names are deterministic, and
    ``api_call`` retries a DELETE whose response was lost — so without a
    precondition a retry can land on a REPLACEMENT pod that a concurrent
    session created under the same name. Empty when the pod was never read
    (a synthesised ref on the failure path), which simply omits the
    precondition.
    """

    namespace: str
    pod_name: str
    container: str
    uid: str = ""


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
    # and silently shared one credential-file sync.
    if len(slug) > max_len or slug != str(raw or ""):
        digest = hashlib.sha1(str(raw or "default").encode("utf-8")).hexdigest()[:6]
        slug = f"{slug[: max_len - 7].strip('-') or 'task'}-{digest}"
    return slug


def _instance_discriminator(owner_pod_uid: str = "") -> str:
    """Per-PROCESS suffix, so two Hermes processes never share a pod name.

    ``_resolve_container_task_id`` collapses almost every session to
    ``"default"``, so without a discriminator two Hermes processes both target
    ``hermes-ws-default``: the second create 409s, gets silently "reused", and
    each execs into (and later deletes) the other's workspace.  The pod UID
    alone is NOT enough — two processes in ONE agent pod (the dashboard-chat
    gateway subprocess, per-profile s6 gateways) share it, and ``_is_ours``
    cannot tell "my own other process" from "me" — so the pid is mixed in.
    Process-scoped naming is safe precisely because workspaces are stateless:
    nothing resumes across a restart, and a restarted process abandons its old
    pod to ownerReference GC / the deadline backstop.
    """
    seed = f"{owner_pod_uid or socket.gethostname() or 'hermes'}:{os.getpid()}"
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


def load_core_api(kcfg: dict):
    """Return a ``CoreV1Api`` for the configured cluster.

    Precedence, in the order the code actually applies it: an explicit
    ``terminal.kubernetes.kubeconfig`` WINS (it is only consulted when set, and
    setting it skips the in-cluster attempt entirely), otherwise the in-cluster
    ServiceAccount — the topology this backend is built for — otherwise the
    ambient ``KUBECONFIG``/``~/.kube/config`` for out-of-cluster dev.
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
                + (f"Tried terminal.kubernetes.kubeconfig={kubeconfig} "
                   if kubeconfig else
                   "Tried the in-cluster ServiceAccount, then ")
                + f"KUBECONFIG/~/.kube/config. Underlying error: {exc}"
            ) from exc

    return k8s_client.CoreV1Api()


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
    if owner_reference_disabled(kcfg):
        return None

    name = (os.getenv("HERMES_POD_NAME") or "").strip()
    uid = (os.getenv("HERMES_POD_UID") or "").strip()
    if not (name and uid):
        if not in_cluster() or core_api is None:
            return None
        try:
            pod = api_call(
                core_api.read_namespaced_pod,
                name=socket.gethostname(), namespace=namespace,
            )
            name = getattr(pod.metadata, "name", "") or ""
            uid = getattr(pod.metadata, "uid", "") or ""
        except Exception as exc:
            # Not cosmetic: with no ownerReference the session pod loses its
            # only garbage-collection path, so say so out loud.
            logger.warning(
                "could not resolve the agent pod identity (%s: %s); session "
                "pods will carry no ownerReference and will NOT be garbage "
                "collected when this agent dies. Set HERMES_POD_NAME/"
                "HERMES_POD_UID from the downward API, or grant 'get pods'.",
                type(exc).__name__, exc,
            )
            return None
    if not (name and uid):
        logger.warning(
            "agent pod identity incomplete (name=%r uid=%r); session pods "
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
# Pod template construction
# ---------------------------------------------------------------------------


def exec_container_name(kcfg: dict) -> str:
    """Name of the container this backend builds and execs into."""
    return str(kcfg.get("exec_container_name") or "").strip() or WORKSPACE_CONTAINER_NAME


#: Where a session starts when the exec container declares no ``workingDir``.
#: Only reachable via that omission; the template is the source of truth.
FALLBACK_SESSION_CWD = "/workspace"


def session_cwd(kcfg: dict) -> str:
    """The session's default cwd — read from ``spec``, not a config key.

    It is the exec container's ``workingDir``. There used to be a
    ``workspace_mount_path`` key alongside it, which meant two places stated
    the same fact and could disagree: the docs had to say "must match", and a
    mismatch produced a pod that mounted the workspace at one path while every
    command ran ``builtin cd`` into another. Deriving it removes the
    disagreement instead of documenting it.

    Falls back to :data:`FALLBACK_SESSION_CWD` when the container declares no
    ``workingDir`` — the container then starts in the image's ``WORKDIR``,
    which Hermes has no way to read. ``TERMINAL_CWD`` still overrides both.
    """
    expected = exec_container_name(kcfg)
    for container in (kcfg.get("spec") or {}).get("containers") or []:
        if container.get("name") == expected:
            return str(container.get("workingDir") or "").strip() or FALLBACK_SESSION_CWD
    return FALLBACK_SESSION_CWD


def object_kind(kcfg: dict) -> tuple:
    """The NORMALISED ``(apiVersion, kind)`` — the single source for both.

    Dispatch used to strip while the manifest builder did not, so a YAML block
    scalar (``kind: |``) gave ``"Pod\n"``: doctor printed a cheerful
    ``v1/Pod -> pod provisioner`` and the create then failed with a scheme
    error whose offending character is invisible in the message. One function,
    used by both.
    """
    api_version = str(kcfg.get("apiVersion") or "").strip() or "v1"
    kind = str(kcfg.get("kind") or "").strip() or "Pod"
    return api_version, kind


def resolve_provisioner_kind(kcfg: dict) -> str:
    """Which provisioner serves the configured ``apiVersion``/``kind``.

    The ONE thing Hermes must decide in-process rather than delegate: nothing
    downstream could tell an operator which kinds this build implements, and
    an unrecognised kind posted blindly would come back as an unhelpful 404 on
    a REST path they never wrote.
    """
    api_version, kind = object_kind(kcfg)
    try:
        return PROVISIONERS_BY_KIND[(api_version, kind)]
    except KeyError:
        supported = ", ".join(
            f"{a}/{k}" for a, k in sorted(PROVISIONERS_BY_KIND)
        )
        raise ValueError(
            f"kubernetes backend: no provisioner for {api_version}/{kind}. "
            f"Supported: {supported}. Set terminal.kubernetes.apiVersion and "
            "terminal.kubernetes.kind."
        ) from None


def owner_reference_disabled(kcfg: dict) -> bool:
    """True when the operator turned ownerReferences off.

    One predicate, called from both sites, so the rule is spelled once.

    ``False`` counts, and that is not a nicety: YAML 1.1 parses an unquoted
    ``off`` as the boolean ``False``, and ``k8s/README.md`` tells operators to
    write exactly ``owner_reference: off``. Comparing only against the string
    made the documented syntax a silent no-op — the pod kept an ownerReference
    the operator believed they had turned off.
    """
    value = kcfg.get("owner_reference", "")
    if value is False:
        return True
    return str(value).strip().lower() == "off"


def owned_selector(kcfg: dict) -> dict:
    """The labels that mark an object as this backend's.

    Both halves of ownership use it: it is stamped into ``metadata.labels``
    when absent, and matched in :meth:`PodProvisioner._is_ours` before a 409 is
    treated as "resume". Deriving both from one key is what keeps a relabelled
    deployment recognising its own pods.
    """
    selector = kcfg.get("owned_selector")
    if not isinstance(selector, dict) or not selector:
        return dict(MANAGED_BY_LABEL)
    return {str(k): str(v) for k, v in selector.items()}


def preflight_spec(kcfg: dict) -> tuple:
    """Check the invariants only HERMES can check. Returns ``(errors, warnings)``.

    This is not a retreat from "the cluster validates the pod". Every item here
    is a question the API server has no opinion on, because it is about how
    Hermes will USE the pod rather than whether the pod is legal: a pod whose
    containers are all named ``sidecar`` is perfectly valid Kubernetes and
    perfectly useless as an exec target. Admission control cannot answer these,
    so nobody answers them unless this does.

    Sharpened by a live scenario sweep: of five realistic operator omissions,
    all five passed ``fieldValidation=Strict`` AND produced a green
    ``hermes doctor``, then misbehaved with no operator-facing signal — the
    worst possible outcome for a design that requires the operator to write the
    whole spec.

    ERRORS are things that cannot work. WARNINGS are things that work until
    they do not, and each names the symptom you would otherwise have to debug
    from inside an agent.
    """
    errors: list = []
    warnings: list = []
    spec = kcfg.get("spec")
    if not isinstance(spec, dict) or not spec:
        # Same pointer render_session_object gives: whichever surface an
        # operator hits first should name the file to copy.
        return ([
            "terminal.kubernetes.spec is required. Copy "
            "k8s/session-pod-template.yaml as a starting point."
        ], warnings)

    wanted = exec_container_name(kcfg)
    containers = spec.get("containers")
    names = [c.get("name") for c in containers or [] if isinstance(c, dict)]
    container = next(
        (c for c in containers or []
         if isinstance(c, dict) and c.get("name") == wanted),
        None,
    )
    if container is None:
        errors.append(
            f"terminal.kubernetes.exec_container_name is {wanted!r} but "
            f"spec.containers declares {names or 'none'}. Every command would "
            f"fail with \"session pod has no container {wanted!r}\" — after "
            "the pod is created and pulled, which is a slow way to learn it."
        )
        return errors, warnings

    if not str(container.get("workingDir") or "").strip():
        warnings.append(
            f"spec.containers[{wanted}].workingDir is unset, so the session "
            f"falls back to {FALLBACK_SESSION_CWD}. If your workspace volume "
            "is mounted somewhere else the agent silently works in the image's "
            "WORKDIR and never touches the volume."
        )
    if not spec.get("shareProcessNamespace"):
        warnings.append(
            "spec.shareProcessNamespace is not true. `sleep` as PID 1 never "
            "reaps, so a backgrounded command's wrapper zombifies and Hermes "
            "never detects it finished."
        )
    elif len(containers or []) > 1:
        others = [n for n in names if n != wanted]
        warnings.append(
            "spec.shareProcessNamespace is true AND this pod has more than one "
            f"container ({', '.join(others)}). A shared PID namespace is a "
            "shared /proc: the agent's shell can read those containers' "
            "/proc/<pid>/environ and /proc/<pid>/root — including a Secret "
            "volume mounted only into them — and can signal their processes. "
            "Hermes needs the shared namespace to detect background "
            "completion, so this is a trade you make deliberately: keep "
            "credential-holding sidecars out of the session pod."
        )
    mounts = {
        m.get("mountPath") for m in container.get("volumeMounts") or []
        if isinstance(m, dict)
    }
    read_only_root = (container.get("securityContext") or {}).get(
        "readOnlyRootFilesystem")
    if read_only_root and "/tmp" not in mounts:
        errors.append(
            "readOnlyRootFilesystem is true and nothing is mounted at /tmp. "
            "init_session() writes its environment snapshot there, so cwd and "
            "environment stop persisting between commands — silently."
        )
    if spec.get("automountServiceAccountToken") is not False:
        warnings.append(
            "spec.automountServiceAccountToken is not false, so the "
            "ServiceAccount's token is projected into the session pod and any "
            "command the agent runs can read it. Nothing rejects this: it "
            "passes fieldValidation=Strict, and only you know whether that SA "
            "is harmless."
        )
    selector = owned_selector(kcfg)
    if selector.get("app.kubernetes.io/managed-by") != "hermes-agent":
        warnings.append(
            "owned_selector no longer carries "
            "app.kubernetes.io/managed-by=hermes-agent, which is what the "
            "shipped k8s/networkpolicy.yaml podSelectors and the "
            "k8s/validatingadmissionpolicy.yaml matchCondition select on. "
            "Session pods will not be covered by either until you update them "
            "— egress is then unrestricted and none of the admission rules run."
        )
    if not spec.get("activeDeadlineSeconds") and \
            owner_reference_disabled(kcfg):
        warnings.append(
            "spec.activeDeadlineSeconds is unset and owner_reference is off, "
            "so nothing bounds a session pod whose agent died. That is a "
            "`sleep infinity` pod running until someone notices."
        )
    return errors, warnings


def render_session_object(kcfg: dict, instance: str = "") -> dict:
    """Render the object body — ``metadata`` + ``spec``, as configured.

    ``terminal.kubernetes.spec`` is REQUIRED and is posted verbatim: there is
    no default base, no merge, and so no merge semantics to learn. If you want
    a field you write it; if you do not write it, it is not there.

    ``metadata`` is yours too, with two exceptions that :meth:`PodProvisioner.
    pod_manifest` applies: ``name`` and ``namespace`` are computed per pod and
    are how Hermes finds the object again. Everything else you put under
    ``metadata`` — annotations, extra labels, finalizers — is posted as
    written. Hermes only ADDS: the :func:`owned_selector` labels and the
    instance label, each only when your ``metadata`` does not already set that
    key.

    Nothing here validates the spec: whether it is well-formed is the API
    server's answer, given via ``field_validation="Strict"`` (a 400 naming the
    exact JSON path), and what it is ALLOWED to be is the cluster
    administrator's, expressed in SCC, Pod Security Admission,
    ValidatingAdmissionPolicy, NetworkPolicy and RBAC.

    See ``k8s/session-pod-template.yaml`` for an object that works, and "What
    Hermes needs from your spec" in ``k8s/README.md`` for the short list of
    fields this backend actually depends on and why.
    """
    spec = kcfg.get("spec")
    if not isinstance(spec, dict) or not spec:
        raise ValueError(
            "kubernetes backend: terminal.kubernetes.spec is required. This "
            "backend has no default pod: you declare the pod you want. Copy "
            "k8s/session-pod-template.yaml as a starting point, or see 'What "
            "Hermes needs from your spec' in k8s/README.md."
        )

    metadata = deepcopy(kcfg.get("metadata"))
    if not isinstance(metadata, dict):
        metadata = {}
    labels = metadata.get("labels")
    if not isinstance(labels, dict):
        labels = {}
    metadata["labels"] = labels
    for key, value in owned_selector(kcfg).items():
        labels.setdefault(key, value)
    if instance:
        labels.setdefault(INSTANCE_LABEL, instance)
    return {"metadata": metadata, "spec": deepcopy(spec)}


# ---------------------------------------------------------------------------
# Provisioners
# ---------------------------------------------------------------------------


class WorkspaceProvisioner(ABC):
    """Creates and destroys the session pod.

    :class:`PodProvisioner` is the only implementation today, and the seam is
    load-bearing anyway: :class:`KubernetesEnvironment` takes its provisioner
    by injection, so the environment tests drive the whole exec/recovery/
    teardown surface against fakes without a cluster or the SDK.  It is also
    """

    #: Namespace the session objects live in.
    namespace: str

    @abstractmethod
    def ensure(self, task_id: str) -> PodRef:
        """Create (or resume) the session workspace; return a Ready PodRef."""
        ...

    @abstractmethod
    def destroy(self, pod_ref: PodRef) -> None:
        """Tear down the session workspace."""
        ...

    @abstractmethod
    def workspace_name(self, task_id: str) -> str:
        """Conventional object name for this task's workspace.

        The environment recomputes it to tear down a workspace whose
        ``ensure()`` raised, so it must be derivable from ``task_id`` alone.
        """
        ...


class PodProvisioner(WorkspaceProvisioner):
    """Creates session pods directly via the Kubernetes core API.

    Naming and readiness polling live here too.  This class supplies NO pod
    content: the hardening an earlier revision promised here (no host
    namespaces, drop-ALL capabilities, an unmounted ServiceAccount token) now
    lives in ``k8s/session-pod-template.yaml``, which the operator copies and
    may relax — :func:`preflight_spec` only warns.  What this class does add
    is metadata: the pod name, the namespace, the :func:`owned_selector`
    labels, and an ownerReference to the agent's own pod so the session pod is
    garbage-collected if the agent crashes.
    """

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
                "refusing to delete %s: this Hermes instance declined to "
                "adopt it (it is not ours, or ownership could not be read), so "
                "deleting it would destroy another agent's workspace.", name,
            )
            return False
        return True

    # -- naming ---------------------------------------------------------
    def workspace_name(self, task_id: str) -> str:
        return f"hermes-ws-{self._instance}-{sanitize_name(task_id)}"

    def exec_container_name(self) -> str:
        return exec_container_name(self.kcfg)

    def exec_container(self, pod: Any) -> str:
        """Assert the RECONCILED pod carries the container we exec into.

        ``exec_container_name`` is the exec target SELECTOR, so a pod without it
        means the running pod is not the one this backend expects — the
        operator renamed the container in ``spec`` without updating
        ``exec_container_name``.  Falling back to
        whatever else is there would hide that drift, and the very next thing
        that happens is a credential-file upload into it.
        """
        expected = self.exec_container_name()
        names: list[str] = []
        for entry in (getattr(getattr(pod, "spec", None), "containers", None) or []):
            name = getattr(entry, "name", None)
            if name:
                names.append(str(name))
        if expected in names:
            return expected
        # No `not names` escape: "we could not establish that the running pod
        # carries the container we rendered" is the same failure as "it carries
        # a different one", and fail-open is the wrong default for a check
        # whose entire purpose is to prove the running pod matches the
        # submitted one.
        raise RuntimeError(
            f"session pod has no container {expected!r} (found "
            f"{', '.join(names) or 'no readable container list'}). "
            "terminal.kubernetes.exec_container_name names the container to "
            "exec into, and it must match a name in "
            "terminal.kubernetes.spec.containers[]. Either point "
            f"exec_container_name at one of {', '.join(names) or 'them'}, or "
            f"rename a container in your spec to {expected!r}. "
            "(`hermes doctor` catches this before a pod is ever created.)"
        )

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
                pod = api_call(
                    self._api.read_namespaced_pod,
                    name=pod_name, namespace=self.namespace,
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

    def _delete_pod(self, namespace: str, pod_name: str, uid: str = "") -> None:
        """Delete a session pod, optionally only if it is still the same object.

        *uid* becomes a delete precondition: session pod names are
        deterministic, so without it a delete racing a re-provision can
        remove the REPLACEMENT pod that now holds the same name.
        """
        from kubernetes.client.exceptions import ApiException

        kwargs: dict[str, Any] = {"grace_period_seconds": 0}
        if uid:
            from kubernetes import client as k8s_client

            kwargs["body"] = k8s_client.V1DeleteOptions(
                preconditions=k8s_client.V1Preconditions(uid=uid),
                grace_period_seconds=0,
            )
        try:
            api_call(
                self._api.delete_namespaced_pod,
                name=pod_name, namespace=namespace, **kwargs
            )
        except ApiException as exc:
            if exc.status == 409:
                # Precondition failed: the name now belongs to a different
                # object. Not ours to delete — that is the point.
                logger.info(
                    "pod %s was replaced before our delete landed; "
                    "leaving the new one alone.", pod_name,
                )
            elif exc.status != 404:
                logger.warning("failed to delete pod %s: %s", pod_name, exc)

    def _terminal_pod_uid(self, pod_name: str) -> str:
        """The uid of *pod_name* when it exists but can never serve exec again.

        Returns "" when the pod is usable, missing or unreadable. The uid is
        what makes the follow-up delete precise (see :meth:`_delete_pod`).
        """
        try:
            pod = api_call(
                self._api.read_namespaced_pod,
                name=pod_name, namespace=self.namespace,
            )
        except Exception:
            return ""
        if not pod_cannot_exec(pod, self.exec_container_name()):
            return ""
        return str(getattr(getattr(pod, "metadata", None), "uid", "") or "")

    def _wait_pod_gone(self, pod_name: str, timeout: int = 30) -> bool:
        """Block until a deleted pod's name is free. False if it never freed.

        It used to fall off the end silently, so a pod stuck ``Terminating``
        (a kata sandbox that will not tear down, a finalizer, a lost node) was
        handed to :meth:`wait_pod_ready`, which burned the whole
        ``ready_timeout_seconds`` and then blamed a slow image pull — pointing
        the operator at the one knob that makes the hang longer. Observed live:
        two ``hermes-ws-*`` pods Terminating for 12h on kata nodes.
        """
        from kubernetes.client.exceptions import ApiException

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pod = api_call(
                    self._api.read_namespaced_pod,
                    name=pod_name, namespace=self.namespace,
                )
            except ApiException as exc:
                if exc.status == 404:
                    return True
                raise
            time.sleep(0.5)
        stamp = getattr(
            getattr(pod, "metadata", None), "deletion_timestamp", None,
        )
        logger.warning(
            "session pod %s is still Terminating after %ss (deletionTimestamp "
            "%s). It is not a slow image pull: something is holding the pod "
            "(a finalizer, a lost node, or a sandbox runtime that will not "
            "tear down). `kubectl describe pod %s` names it.",
            pod_name, timeout, stamp, pod_name,
        )
        return False

    def pod_manifest(self, task_id: str) -> dict:
        """The Pod body. Your ``metadata`` passes through; two keys cannot.

        ``name`` and ``namespace`` are Hermes': the name is computed per
        process and is how the pod is found again on the next command, so a
        template-supplied one would simply be lost. Everything else you write
        under ``metadata`` — ``annotations``, ``labels``, ``finalizers`` — is
        yours.

        ``ownerReferences`` is the one that MERGES rather than yielding.
        Hermes' reference is APPENDED to yours, never replaced and never
        skipped, because that reference is the ownership proof
        :meth:`_is_ours` checks: honouring a user-supplied list by itself
        produced a pod Hermes had just created and could then neither adopt
        nor delete, so the 409 path refused it, the terminal was dead for the
        life of the process and the pod leaked. Kubernetes allows several
        owners (at most one ``controller: true``), so both intents survive —
        note the consequence, that the pod is collected only once ALL of its
        owners are gone, which is why ``spec.activeDeadlineSeconds`` is the
        backstop worth setting.
        """
        api_version, kind = object_kind(self.kcfg)
        obj = render_session_object(self.kcfg, self._instance)
        metadata = dict(obj["metadata"])
        metadata["name"] = self.workspace_name(task_id)
        metadata["namespace"] = self.namespace
        if self._owner_reference is not None:
            # GC the session pod when the agent pod dies — appended to any
            # owners the operator declared, not substituted for them. See the
            # docstring: this reference doubles as the ownership proof.
            existing = list(metadata.get("ownerReferences") or [])
            our_uid = self._owner_reference.get("uid")
            # Dicts only: `existing` is metadata the operator wrote, parsed
            # from YAML/JSON, never a client model object.
            if not any(o.get("uid") == our_uid for o in existing):
                existing.append(dict(self._owner_reference))
            metadata["ownerReferences"] = existing
        return {
            # Echoed from config rather than hardcoded, but through the same
            # normaliser dispatch used, so what is POSTED is what was
            # DISPATCHED — see object_kind().
            "apiVersion": api_version,
            "kind": kind,
            "metadata": metadata,
            "spec": obj["spec"],
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
            pod = api_call(
                self._api.read_namespaced_pod,
                name=pod_name, namespace=self.namespace,
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
        # `owned_selector` is what marks an object as ours, and it is the same
        # key that stamped these labels on at create time — so an operator who
        # relabels (chargeback, a different platform convention) still
        # recognises their own pods. It used to be a hardcoded constant, which
        # meant relabelling broke adoption against your own objects. The
        # ownerReference UID below is the actual proof; this is the cheap
        # first filter.
        expected = owned_selector(self.kcfg)
        labels = getattr(pod.metadata, "labels", None) or {}
        for key, value in expected.items():
            if labels.get(key) != value:
                return False
        if self._owner_reference is None:
            # No agent identity to compare against (out-of-cluster dev, or
            # owner_reference: off). The pod NAME is not evidence — it is
            # derived from a hostname and a pid and is readable by anyone with
            # `get pods` — so fall back to the instance label, which a foreign
            # object carries a different value for. Adoption is not free: the
            # very next thing that happens is a credential-file upload into
            # whatever we adopted.
            return labels.get(INSTANCE_LABEL) == self._instance
        owners = getattr(pod.metadata, "owner_references", None) or []
        our_uid = self._owner_reference.get("uid")
        # No `or not owners` fallback: an unowned pod carrying our label is
        # exactly what another agent's workspace looks like, and adopting it
        # means uploading our credential files into it and later deleting it.
        # Ownership has to be proved, not assumed.
        return any(getattr(o, "uid", None) == our_uid for o in owners)

    def ensure(self, task_id: str) -> PodRef:
        from kubernetes.client.exceptions import ApiException

        pod_name = self.workspace_name(task_id)
        for attempt in (1, 2):
            try:
                api_call(
                    self._api.create_namespaced_pod,
                    namespace=self.namespace,
                    body=self.pod_manifest(task_id),
                    **STRICT_FIELD_VALIDATION,
                )
            except ApiException as exc:
                if exc.status != 409:
                    raise
                # 409 = the pod already exists (a racing session in this same
                # agent, or a leftover from a previous run).
                if not self._is_ours(pod_name):
                    raise self._refuse(pod_name, (
                        f"session pod {pod_name} already exists and was not "
                        "created by this Hermes instance; refusing to reuse it."
                    ))
                # Our own pod, but dead (deadline, eviction, OOMKill under
                # restartPolicy: Never leave it in phase Failed, PRESENT).
                # Handing it to wait_pod_ready would raise immediately, so
                # delete the corpse and recreate under the same name.
                dead_uid = self._terminal_pod_uid(pod_name) if attempt == 1 else ""
                if dead_uid:
                    logger.warning(
                        "session pod %s can no longer serve exec; "
                        "deleting and re-provisioning.", pod_name,
                    )
                    self._delete_pod(self.namespace, pod_name, uid=dead_uid)
                    if not self._wait_pod_gone(pod_name):
                        # Naming the real cause here, rather than letting
                        # wait_pod_ready time out and blame the image pull.
                        raise RuntimeError(
                            f"session pod {pod_name} is stuck Terminating and "
                            "the name cannot be reused. This is not a slow "
                            "image pull — raising "
                            "terminal.kubernetes.ready_timeout_seconds will "
                            f"not help. Run `kubectl describe pod {pod_name} "
                            f"-n {self.namespace}` to see what is holding it "
                            "(a finalizer, a lost node, or a sandbox runtime "
                            "that will not tear down)."
                        )
                    continue
            break

        pod = self.wait_pod_ready(pod_name)
        return PodRef(
            self.namespace, pod_name, self.exec_container(pod),
            uid=str(getattr(getattr(pod, "metadata", None), "uid", "") or ""),
        )

    def destroy(self, pod_ref: PodRef) -> None:
        # A pod we refused to adopt is a pod we must not delete: the refusal
        # raises out of ensure(), and the environment's teardown path then asks
        # to destroy the workspace under exactly that name.
        if not self._may_delete(pod_ref.pod_name):
            return
        self._delete_pod(pod_ref.namespace, pod_ref.pod_name, uid=pod_ref.uid)


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
        cwd: str = "/workspace",
        timeout: int = 60,
        api=None,
        sync_files: bool = True,
    ):
        super().__init__(cwd=cwd, timeout=timeout)
        self._provisioner = provisioner
        self._task_id = task_id
        self._exec_api = api  # configured CoreV1Api; falls back to a fresh one
        self._lock = threading.Lock()
        # Held across a whole re-provision (see _ensure_pod). Distinct from
        # _lock, which guards field access only and must never be held over
        # an API call.
        self._provision_lock = threading.Lock()
        self._sync_manager = None
        # Captured once: the agent may `cd` away, but the synced ~/.hermes tree
        # must stay where the first sync put it.
        self._hermes_base = posixpath.join(cwd or "/workspace", ".hermes")
        # Where a re-provisioned session restarts (the workspace is stateless,
        # so a tracked cwd inside the old pod cannot survive it).
        self._initial_cwd = cwd or "/workspace"
        # Set by _ensure_pod after a re-provision; the next execute() result
        # carries a one-line note so the MODEL learns the workspace reset —
        # a logger.warning is invisible to it.
        self._reset_note_pending = False
        # Set alongside it on re-provision, cleared on the very next execute()
        # whatever kind of caller that is — see execute().
        self._cwd_invalidated = False
        # cleanup() is final: a background poller must not resurrect the
        # environment into an untracked pod after teardown.
        self._torn_down = False

        try:
            self._pod_ref = provisioner.ensure(task_id=task_id)
        except BaseException:
            # A pod created but never Ready (image pull, quota, SCC denial)
            # would otherwise linger until activeDeadlineSeconds.
            self._pod_ref = None
            self._best_effort_destroy(task_id)
            raise

        if sync_files:
            # Session pods are not bind-mounted, so skills, ~/.hermes
            # credential files and the agent cache have to be pushed in.
            # Deliberately one-way: no bulk_download_fn and no sync_back() on
            # cleanup. The synced set is host-authored (credentials, skills,
            # caches), so there is nothing of value to pull back, and the
            # workspace itself is a stateless emptyDir by design.
            self._sync_manager = FileSyncManager(
                get_files_fn=lambda: iter_sync_files(self._hermes_base),
                upload_fn=self._upload_file,
                delete_fn=self._delete_files,
                bulk_upload_fn=self._bulk_upload,
            )
            try:
                self._sync_manager.sync(force=True)
            except Exception as exc:
                logger.warning("initial file sync failed: %s", exc)

        self.init_session()

    # -- provisioning ---------------------------------------------------
    def _best_effort_destroy(self, task_id: str) -> None:
        try:
            ref = PodRef(
                self._provisioner.namespace,
                self._provisioner.workspace_name(task_id),
                WORKSPACE_CONTAINER_NAME,
            )
            self._provisioner.destroy(ref)
        except Exception:
            pass

    def _ensure_pod(self) -> PodRef:
        """Re-provision after the session pod went away.

        Reached when the pod genuinely died — activeDeadlineSeconds, an
        operator TTL, an eviction, an OOMKill.  Without it a single dead pod
        bricks the session: every later exec fails and the agent sees empty
        output with rc=1 until the idle reaper evicts the environment.
        (Cancellation deliberately does NOT destroy the pod, so it never
        lands here — see :meth:`_run_bash`.)
        """
        # Serialise the whole re-provision, not just the ref check. Up to 8
        # tool workers share one environment; with the check and the create
        # unlocked, two of them each delete the dead pod (the recovery path
        # is destructive now) and then delete the OTHER's fresh replacement.
        with self._provision_lock:
            with self._lock:
                if self._torn_down:
                    raise RuntimeError(
                        "kubernetes environment has been cleaned up; refusing "
                        "to provision a new session pod for it"
                    )
                if self._pod_ref is not None:
                    return self._pod_ref
            logger.warning(
                "session pod for task %s is gone; provisioning a new one "
                "— the workspace starts empty again.", self._task_id,
            )
            pod_ref = self._provisioner.ensure(task_id=self._task_id)
            with self._lock:
                torn_down = self._torn_down
                if not torn_down:
                    self._pod_ref = pod_ref
            if torn_down:
                # cleanup() ran while we were provisioning. It saw _pod_ref
                # None and returned early, so this object is ours to destroy
                # here or nothing ever will.
                logger.warning(
                    "environment was cleaned up mid-provision; "
                    "destroying the session pod it created.",
                )
                try:
                    self._provisioner.destroy(pod_ref)
                except Exception as exc:
                    logger.warning("mid-provision cleanup failed: %s", exc)
                raise RuntimeError(
                    "kubernetes environment was cleaned up while provisioning"
                )
        # The tracked cwd pointed inside the old pod's workspace; a fresh
        # emptyDir has only the mount root.
        self.cwd = self._initial_cwd
        self._reset_note_pending = True
        # ...and self.cwd alone does NOT settle it. base.execute() computes
        # `effective_cwd = cwd or self.cwd`, and terminal_tool always passes an
        # explicit cwd from the per-session record — which still names a
        # directory inside the pod that just died. Without this flag the first
        # recovered command runs `builtin cd -- <gone> || exit 126` in the
        # fresh pod, dies without running, and is handed a note claiming the
        # cwd was reset.
        self._cwd_invalidated = True
        # A fresh pod has none of the synced files or the env snapshot. The
        # sync manager's per-file mtime cache still describes the DEAD pod, and
        # force=True only bypasses the rate limit — so without dropping that
        # state first the replacement pod receives nothing at all.
        if self._sync_manager is not None:
            try:
                self._sync_manager.forget_remote_state()
                self._sync_manager.sync(force=True)
            except Exception as exc:
                logger.warning("file re-sync failed: %s", exc)
        self._snapshot_ready = False
        # Bare, as __init__ does: base.init_session() already swallows its own
        # body and logs, so this handler caught essentially nothing while
        # disagreeing with the sibling call site.
        self.init_session()
        return pod_ref

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        # Provision HERE rather than leaving it to base's _before_execute().
        # Both run before the command, but base computes
        # `effective_cwd = cwd or self.cwd` (base.py:1321) AFTER the hook, and
        # terminal_tool always passes an explicit cwd from the per-session
        # record — so a re-provision discovered inside the hook could not
        # affect the cwd the command actually used. Doing it first is what
        # lets the override below apply to the recovered command instead of
        # the one after it. _ensure_pod() is idempotent and returns fast when
        # the pod is alive; base calls it again a moment later.
        self._ensure_pod()
        if self._cwd_invalidated:
            # Cleared here rather than on the note path: the caller-supplied
            # cwd is stale for EVERY consumer after a re-provision, not just
            # the model-facing one.
            cwd = self._initial_cwd
            self._cwd_invalidated = False
        result = super().execute(command, cwd, **kwargs)
        # ONLY on the model-facing foreground path. `bounded_capture` is set
        # by exactly one caller (tools/terminal_tool.py) and left False by
        # every internal full-fidelity consumer — `cat` reads that feed the
        # patch engine, `stat` output parsed with int(), `command -v` probes,
        # the code-execution JSON-RPC loop. Prefixing prose onto those
        # corrupts data rather than informing anyone: it made file_size parse
        # as 0, cached _has_command False for the process, and broke
        # json.loads. The note is for the model, so it rides the model's path.
        if self._reset_note_pending and kwargs.get("bounded_capture"):
            # Once, on the first model-visible result after a re-provision:
            # the model (not the operator log) is who has to react to a
            # vanished workspace.
            self._reset_note_pending = False
            note = (
                "[note: the session workspace was re-provisioned and starts "
                "empty — files, installed packages and previously saved tool "
                f"outputs are gone; cwd reset to {self._initial_cwd}]\n"
            )
            result = dict(result)
            result["output"] = note + (result.get("output") or "")
        return result

    def _before_execute(self) -> None:
        self._ensure_pod()
        if self._sync_manager is not None:
            try:
                self._sync_manager.sync()
            except Exception as exc:
                logger.debug("file sync skipped: %s", exc)

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
        # No fallback: ApiClient(None) re-runs the identical expression that
        # would have raised (its __init__ substitutes the default
        # configuration), so the old `except` could only repeat the failure.
        # _run_bash surfaces a real constructor error as [kubernetes exec error].
        api_client = (
            ApiClient(configuration) if configuration is not None else ApiClient()
        )
        return CoreV1Api(api_client), api_client

    def _open_stream(self, command: list[str], *, stdin: bool = False):
        """Open an exec websocket, bounded by :data:`API_TIMEOUT`.

        ``kubernetes.stream.stream()`` ignores ``_request_timeout`` — it builds
        a ``WebSocket`` whose ``sock_opt.timeout`` is None, so the TCP connect
        and TLS handshake are unbounded. That matters because every deadline in
        this module is computed AFTER the connect returns, and ``cancel()``
        cannot help while the stream is still None. (``websocket``'s
        ``setdefaulttimeout`` does not reach this path: ``WebSocket.connect()``
        never consults it.) So the connect runs in a bounded worker; a peer
        that accepts and then goes silent hits the join deadline instead of
        pinning the caller's thread.
        """
        from kubernetes.stream import stream as k8s_stream

        ref = self._pod_ref
        if ref is None:
            raise RuntimeError("kubernetes session pod is not provisioned")
        api, api_client = self._exec_client()

        result: dict[str, Any] = {}

        def _connect() -> None:
            try:
                result["stream"] = k8s_stream(
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
            except BaseException as exc:  # re-raised on the caller's thread
                result["error"] = exc

        worker = threading.Thread(
            target=_connect, name="k8s-exec-connect", daemon=True
        )
        worker.start()
        worker.join(API_TIMEOUT[0] + API_TIMEOUT[1])
        try:
            if worker.is_alive():
                raise TimeoutError(
                    "kubernetes exec: the API server accepted no websocket "
                    f"within {API_TIMEOUT[0] + API_TIMEOUT[1]:.0f}s "
                    f"(pod {ref.pod_name})"
                )
            if "error" in result:
                raise self._explain_exec_failure(result["error"])
            return result["stream"]
        finally:
            # The returned WSClient owns its own websocket; the ApiClient was
            # only needed to build the request, so it can go immediately.
            try:
                api_client.close()
            except Exception:
                pass

    def _explain_exec_failure(self, exc: BaseException) -> BaseException:
        """Turn an opaque websocket-handshake failure into something actionable.

        When the API server refuses the exec upgrade, the python client never
        sees an ApiException: it tries to read a body that is not there and
        dies with ``AttributeError: 'NoneType' object has no attribute
        'decode'``. That string is what an operator gets for a missing RBAC
        verb, a pod that is not running, or an admission refusal — three very
        different problems, none of them named.

        The commonest cause by far is RBAC, and it is cheap to check: ask the
        API server directly whether this identity may exec. Anything else is
        passed through untouched.
        """
        if not isinstance(exc, AttributeError) or "decode" not in str(exc):
            return exc
        missing = []
        try:
            from kubernetes import client as k8s_client

            api_client = getattr(self._exec_api, "api_client", None)
            auth = k8s_client.AuthorizationV1Api(api_client)
            for verb in ("get", "create"):
                review = k8s_client.V1SelfSubjectAccessReview(
                    spec=k8s_client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=k8s_client.V1ResourceAttributes(
                            namespace=self._pod_ref.namespace if self._pod_ref else "",
                            group="", resource="pods/exec", verb=verb,
                        )
                    )
                )
                allowed = getattr(
                    api_call(auth.create_self_subject_access_review, review).status,
                    "allowed", False,
                )
                if not allowed:
                    missing.append(verb)
        except Exception:
            return RuntimeError(
                "kubernetes exec: the API server refused the websocket upgrade "
                f"({exc}). Usual causes: the ServiceAccount lacks 'get' and "
                "'create' on pods/exec, the session pod is not Running, or an "
                "admission policy refused the connection."
            )
        if missing:
            return RuntimeError(
                "kubernetes exec: refused — this ServiceAccount is missing "
                f"{', '.join(missing)} on pods/exec in "
                f"{self._pod_ref.namespace if self._pod_ref else 'the namespace'}. "
                "BOTH verbs are required (see k8s/rbac.yaml); `kubectl auth "
                "can-i get pods/exec` answering yes is not sufficient."
            )
        return RuntimeError(
            "kubernetes exec: the API server refused the websocket upgrade "
            f"({exc}), and RBAC on pods/exec looks correct. Check that the "
            "session pod is Running and that no admission policy or proxy is "
            "blocking the connection upgrade."
        )

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

    def _forget_pod_if_dead(self, exc: Exception) -> bool:
        """Drop the pod ref when the pod is gone OR terminal-but-present.

        404 is the easy case (the pod was deleted underneath us). The
        insidious one: activeDeadlineSeconds, node-pressure eviction or an
        OOMKill under ``restartPolicy: Never`` moves the pod to phase Failed
        and Kubernetes does NOT delete it — exec then returns 400, not 404,
        forever.  So on any other exec error, ask the API server whether the
        pod can still serve exec at all; a terminal phase clears the ref, and
        the provisioner's 409 path deletes the corpse on re-provision.
        """
        dead = (
            getattr(exc, "status", None) == 404
            or "not found" in str(exc).lower()
        )
        if not dead:
            with self._lock:
                ref = self._pod_ref
            api = self._exec_api
            if ref is None or api is None:
                return False
            try:
                pod = api_call(
                    api.read_namespaced_pod,
                    name=ref.pod_name, namespace=ref.namespace,
                )
                dead = pod_cannot_exec(pod, ref.container)
            except Exception as read_exc:
                dead = getattr(read_exc, "status", None) == 404
        if not dead:
            return False
        with self._lock:
            self._pod_ref = None
        self._snapshot_ready = False
        return True

    def _run_bash(
        self, cmd_string: str, *, login: bool = False, timeout: int = 120,
        stdin_data: str | None = None,
    ):
        shell = "bash -l -c" if login else "bash -c"
        # Every exec is tagged with a unique marker exported into its
        # environment. Closing the websocket does NOT stop the remote process
        # — verified against Kubernetes 1.36: a loop kept writing for at least
        # 8s after the stream was closed — so cancel() needs a way to identify
        # this command's process tree from a SECOND exec. The marker is that
        # handle. `exec` replaces the tagged shell so the marker belongs to
        # the command itself rather than a wrapper that exits immediately.
        marker = f"HERMES_EXEC_{uuid.uuid4().hex[:16]}"
        tagged = f"export {marker}=1; exec {shell} {shlex.quote(cmd_string)}"
        command = ["bash", "-c", tagged]
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
                    logger.warning("exec stream error: %s", exc)
                    # Ask whether the pod died BEFORE composing the message:
                    # exec against a completed pod fails deep inside the
                    # websocket client ("'NoneType' object has no attribute
                    # 'decode'"), which tells the model nothing it can act on.
                    died = self._forget_pod_if_dead(exc)
                    chunks.append(
                        "\n[the session workspace stopped (deadline, eviction "
                        "or OOM) and its files are gone; the next command "
                        "provisions a fresh one]"
                        if died else f"\n[kubernetes exec error: {exc}]"
                    )
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
            # Closing the websocket frees OUR side. It does not stop the
            # remote process: the kubelet leaves a non-TTY exec running, so
            # without the kill below a timed-out or interrupted command runs
            # on to completion — up to the template's activeDeadlineSeconds —
            # while the model is told it stopped and happily re-runs it. That is
            # actively harmful for anything non-idempotent.
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
            # Kill the tagged tree from a second exec. Best effort by design:
            # the pod may already be gone, and a failure here must never mask
            # the interrupt the caller asked for.
            try:
                self._exec_capture(
                    ["sh", "-c",
                     "for p in $(grep -lz " + marker + "=1 /proc/*/environ "
                     "2>/dev/null | sed 's#/proc/##;s#/environ##'); do "
                     "kill -TERM -$(ps -o pgid= -p \"$p\" 2>/dev/null | tr -d ' ') "
                     "2>/dev/null || kill -TERM \"$p\" 2>/dev/null; done; "
                     "sleep 0.3; "
                     "for p in $(grep -lz " + marker + "=1 /proc/*/environ "
                     "2>/dev/null | sed 's#/proc/##;s#/environ##'); do "
                     "kill -KILL \"$p\" 2>/dev/null; done; true"],
                    timeout=15,
                )
            except Exception as exc:
                logger.debug("exec cancel: kill pass failed: %s", exc)

            # The pod is deliberately NOT destroyed here. _wait_for_process
            # calls _kill_process() on an ORDINARY TIMEOUT as well as on a
            # user interrupt (base.py), so tearing the pod down wiped
            # /workspace — every file the agent had just written — whenever a
            # command ran past its timeout, with no notice to the agent.

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
                    logger.debug("skipping %s: %s", host_path, exc)
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
        # Established BEFORE the write loop, not after it: writes are the
        # phase most likely to block (the remote `tar` stops draining, so the
        # websocket send buffer fills), and a deadline set afterwards cannot
        # bound the thing that already hung.
        deadline = time.monotonic() + max(1, timeout)
        try:
            if not encoded.endswith("\n"):
                encoded += "\n"
            for offset in range(0, len(encoded), _STDIN_CHUNK_BYTES):
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                resp.write_stdin(encoded[offset:offset + _STDIN_CHUNK_BYTES])
                # Pump the read side so the remote's output cannot backpressure
                # us into a deadlock while we are still writing.
                self._drain(resp, chunks)
            if not timed_out:
                resp.write_stdin(f"{_SYNC_SENTINEL}\n")
            if getattr(resp, "subprotocol", None) == V5_CHANNEL_PROTOCOL:
                try:
                    resp.close_channel(STDIN_CHANNEL)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("stdin half-close unavailable: %s", exc)

            while not timed_out:
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
            # Final: an orphaned background poller calling _ensure_pod after
            # this must fail, not resurrect the environment into an untracked
            # pod.
            self._torn_down = True
        if ref is None:
            return
        try:
            self._provisioner.destroy(ref)
        except Exception as exc:
            logger.warning("cleanup failed: %s", exc)
