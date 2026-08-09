"""SandboxClaim provisioner — session workspaces from a SandboxWarmPool.

The second implementation behind :class:`WorkspaceProvisioner`, and the reason
``terminal.kubernetes`` is shaped like a manifest. Selecting it is a config
edit, not a new key::

    terminal:
      kubernetes:
        namespace: hermes-agents
        apiVersion: extensions.agents.x-k8s.io/v1beta1
        kind: SandboxClaim
        spec:
          warmPoolRef: {name: hermes-session-pool}
          lifecycle: {shutdownPolicy: Delete}

``kind`` picks this class out of :data:`PROVISIONERS_BY_KIND`; ``spec`` is the
CLAIM's spec, posted verbatim exactly as a PodSpec is on the pod path.

What differs from the pod path, and why:

* **Hermes does not author the pod.** The pool's ``SandboxTemplate`` does, so
  ``exec_container_name`` has to match a container the ADMIN defined, and
  :func:`preflight_spec` cannot check it — see :func:`_preflight_claim` for
  what it checks instead.
* **Deleting the CLAIM is the teardown.** The controller owns the Sandbox, the
  Sandbox owns the pod, and a checked-out sandbox is never returned to the
  pool on its own.
* **Ownership is proved on the claim**, not the pod: the pod belongs to the
  Sandbox, so :meth:`_assert_pod_belongs` checks the pod carries an
  ownerReference to the Sandbox the claim reports before anything is uploaded
  into it.

RBAC: the agent SA needs ``sandboxclaims`` create/get/delete
(``extensions.agents.x-k8s.io``), ``sandboxes`` get (``agents.x-k8s.io``), and
``pods`` get + ``pods/exec`` — notably NOT ``pods create``. That is the
security case for this provisioner: the agent can check a workspace out of a
pool the admin defined, but cannot define a pod.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from tools.environments.kubernetes import (
    INSTANCE_LABEL,
    PodProvisioner,
    PodRef,
    STRICT_FIELD_VALIDATION,
    api_call,
    object_kind,
    session_cwd,
    pod_cannot_exec,
    render_session_object,
)

logger = logging.getLogger(__name__)


def _dig_dict(obj: Any, *keys: str) -> dict:
    """Walk nested dicts, returning {} at the first non-dict. Custom-object
    responses are plain dicts whose optional sub-objects are simply absent."""
    for key in keys:
        if not isinstance(obj, dict):
            return {}
        obj = obj.get(key)
    return obj if isinstance(obj, dict) else {}


# Pinned, not configurable: this module consumes a specific API contract.
# The Red Hat build serves the same groups, so one pin covers both.
SANDBOX_API_GROUP = "agents.x-k8s.io"
EXTENSIONS_API_GROUP = "extensions.agents.x-k8s.io"
SANDBOX_API_VERSION = "v1beta1"

#: How the sandbox controller records which pod backs a Sandbox that adopted
#: a warm pod (see resolvePodName in the agent-sandbox sandbox controller).
#: Absent, the pod is named after the Sandbox.
POD_NAME_ANNOTATION = "agents.x-k8s.io/pod-name"

_READY_CONDITION = "Ready"
_CLAIM_EXPIRED_REASON = "ClaimExpired"
#: Ready-condition reasons that mean the bound sandbox's pod reached a
#: terminal phase (deadline, OOMKill, completion) — the controller never
#: restarts it, so the claim is dead and must be replaced, not waited on.
_DEAD_REASONS = frozenset({"PodFailed", "PodSucceeded", "SandboxExpired"})


class _ClaimDead(RuntimeError):
    """The claim can never become usable again (finished pod, expiry)."""


class SandboxClaimProvisioner(PodProvisioner):
    """Checks session workspaces out of a ``SandboxWarmPool`` via claims.

    Security shape: the agent's ServiceAccount needs ``sandboxclaims``
    create/get/delete (``extensions.agents.x-k8s.io``), ``sandboxes`` get
    (``agents.x-k8s.io``), and ``pods`` get + ``pods/exec`` — nothing that
    lets it define a pod.
    """

    def __init__(self, kcfg: dict, namespace: str, api=None, owner_reference=None,
                 custom_api=None):
        super().__init__(kcfg, namespace, api=api, owner_reference=owner_reference)
        self._custom = custom_api
        # For MESSAGES only — the claim spec carries the real reference.
        self.warm_pool = str(
            ((kcfg.get("spec") or {}).get("warmPoolRef") or {}).get("name") or ""
        ).strip()
        # Claim names this provisioner created (or proved were ours), so
        # destroy() deletes the right object — and NOTHING when there is no
        # such name.
        self._created_names: set[str] = set()

    # -- manifests ------------------------------------------------------
    def claim_manifest(self, task_id: str) -> dict:
        """The SandboxClaim body — ``spec`` posted VERBATIM, like the pod path.

        An earlier revision synthesised this from a
        ``terminal.kubernetes.sandbox.warm_pool`` key and computed a
        ``lifecycle`` block. Under the manifest-shaped config the operator
        writes the claim spec directly, so ~35 lines of synthesis became a
        ``deepcopy`` — which is the clearest evidence that ``spec`` meaning
        "the spec of whatever ``kind`` you named" was the right seam.

        Deliberately NO ``additionalPodMetadata``: the claim controller runs
        those labels through a strict domain allowlist that defaults to
        ``sandbox.users.io``, and no install path ships the ConfigMap that
        widens it — so any label Hermes set there (including
        ``app.kubernetes.io/managed-by``) made EVERY claim fail with
        InvalidMetadata on a stock install. The POD's managed-by label, which
        ``k8s/networkpolicy.yaml`` selects on, belongs in the admin's
        SandboxTemplate — see "The other kind: SandboxClaim" in
        ``k8s/README.md``, which says so in the comparison table.
        """
        api_version, kind = object_kind(self.kcfg)
        obj = render_session_object(self.kcfg, self._instance)
        metadata = dict(obj["metadata"])
        metadata["name"] = self.workspace_name(task_id)
        metadata["namespace"] = self.namespace
        if self._owner_reference is not None:
            existing = list(metadata.get("ownerReferences") or [])
            our_uid = self._owner_reference.get("uid")
            if not any(o.get("uid") == our_uid for o in existing):
                # GC chain: agent pod -> claim -> Sandbox -> pod.
                existing.append(dict(self._owner_reference))
            metadata["ownerReferences"] = existing
        return {
            "apiVersion": api_version,
            "kind": kind,
            "metadata": metadata,
            "spec": obj["spec"],
        }

    # -- API helpers ----------------------------------------------------
    def _get_claim(self, name: str) -> dict:
        return api_call(
            self._custom.get_namespaced_custom_object,
            group=EXTENSIONS_API_GROUP, version=SANDBOX_API_VERSION,
            namespace=self.namespace, plural="sandboxclaims", name=name,
        )

    def _get_sandbox(self, name: str) -> dict:
        return api_call(
            self._custom.get_namespaced_custom_object,
            group=SANDBOX_API_GROUP, version=SANDBOX_API_VERSION,
            namespace=self.namespace, plural="sandboxes", name=name,
        )

    def _create_claim(self, body: dict) -> bool:
        """Create the claim. Returns True when it already existed (409)."""
        from kubernetes.client.exceptions import ApiException

        try:
            api_call(
                self._custom.create_namespaced_custom_object,
                group=EXTENSIONS_API_GROUP, version=SANDBOX_API_VERSION,
                namespace=self.namespace, plural="sandboxclaims", body=body,
                **STRICT_FIELD_VALIDATION,
            )
        except ApiException as exc:
            if exc.status == 404:
                raise RuntimeError(
                    "kubernetes backend: sandboxclaims."
                    f"{EXTENSIONS_API_GROUP}/{SANDBOX_API_VERSION} is not "
                    "served by this cluster. Install agent-sandbox WITH its "
                    "extensions (SandboxClaim/SandboxTemplate/SandboxWarmPool "
                    "— sandbox-with-extensions.yaml, or the Red Hat build), "
                    "or set terminal.kubernetes.provisioner: pod."
                ) from exc
            if exc.status != 409:
                raise
            # Already exists — the caller must prove it is ours before reuse.
            return True
        return False

    def _assert_ours(self, name: str) -> None:
        """Refuse to adopt a pre-existing claim this agent did not create.

        Adoption is not free: ``KubernetesEnvironment.__init__`` immediately
        uploads the agent's credential files into whatever pod the claim is
        bound to, and ``destroy()`` later deletes the claim.
        """
        if self._owner_reference is None:
            # No agent identity (out-of-cluster dev, or owner_reference: off).
            # The claim NAME is not evidence — anyone with `get sandboxclaims`
            # can read it — so compare the instance label instead. Adopting a
            # foreign claim means uploading credential files into someone
            # else's bound sandbox and deleting their claim at teardown.
            try:
                existing = self._get_claim(name)
            except Exception as exc:
                raise self._refuse(name, (
                    f"sandboxclaim {name} already exists but could not be read "
                    f"({exc}); refusing to reuse or delete it."
                )) from exc
            labels = _dig_dict(existing, "metadata").get("labels") or {}
            if labels.get(INSTANCE_LABEL) != self._instance:
                raise self._refuse(name, (
                    f"sandboxclaim {name} already exists and carries a "
                    f"different instance label "
                    f"({labels.get(INSTANCE_LABEL)!r} != {self._instance!r}); "
                    "refusing to reuse it. With no ownerReference to check "
                    "(out-of-cluster, or owner_reference: off) this label is "
                    "the only ownership evidence there is."
                ))
            return
        try:
            existing = self._get_claim(name)
        except Exception as exc:
            raise self._refuse(name, (
                f"sandboxclaim {name} already exists but could not be read "
                f"({exc}); refusing to reuse or delete it."
            )) from exc
        owners = _dig_dict(existing, "metadata").get("ownerReferences") or []
        our_uid = self._owner_reference.get("uid")
        if not any(
            isinstance(o, dict) and o.get("uid") == our_uid for o in owners
        ):
            raise self._refuse(name, (
                f"sandboxclaim {name} already exists and was not created by "
                "this Hermes instance; refusing to reuse it."
            ))

    # -- readiness ------------------------------------------------------
    @staticmethod
    def _ready_condition(claim: dict) -> Optional[dict]:
        for cond in (claim.get("status") or {}).get("conditions") or []:
            if isinstance(cond, dict) and cond.get("type") == _READY_CONDITION:
                return cond
        return None

    @staticmethod
    def _bound_sandbox_name(claim: dict) -> str:
        value = _dig_dict(claim, "status", "sandbox").get("name")
        return value if isinstance(value, str) else ""

    @staticmethod
    def _finished_condition(claim: dict) -> Optional[dict]:
        for cond in (claim.get("status") or {}).get("conditions") or []:
            if (isinstance(cond, dict) and cond.get("type") == "Finished"
                    and str(cond.get("status")) == "True"):
                return cond
        return None

    def _wait_claim(self, name: str) -> str:
        """Poll the claim until it is bound; return the bound Sandbox name.

        Raises :class:`_ClaimDead` when the claim can never bind again
        (expired, or its sandbox's pod finished) — the caller replaces the
        claim, because the controller never restarts a finished pod.
        """
        import time

        from kubernetes.client.exceptions import ApiException

        deadline = time.monotonic() + self.ready_timeout
        last_reason = ""
        while time.monotonic() < deadline:
            try:
                claim = self._get_claim(name)
            except ApiException as exc:
                if exc.status == 404:
                    # A claim WE created that vanished mid-wait was deleted by
                    # an admin or the controller; it is gone for good.
                    raise RuntimeError(
                        f"sandboxclaim {name} was deleted while binding; not "
                        "retrying. If an admin removed it, re-run the command."
                    ) from exc
                raise
            cond = self._ready_condition(claim) or {}
            reason = str(cond.get("reason") or "")
            finished = self._finished_condition(claim)
            if (reason == _CLAIM_EXPIRED_REASON or reason in _DEAD_REASONS
                    or finished is not None):
                detail = (finished or cond)
                raise _ClaimDead(
                    f"sandboxclaim {name} is dead "
                    f"({detail.get('reason')}: {detail.get('message') or ''})"
                )
            sandbox_name = self._bound_sandbox_name(claim)
            # Both, not either: the condition can flip before the status
            # carries the sandbox name, and vice versa across controller
            # versions.
            if str(cond.get("status")) == "True" and sandbox_name:
                return sandbox_name
            if cond:
                last_reason = f"{reason}: {cond.get('message') or ''}".strip(": ")
            time.sleep(0.5)
        # Lead with the controller's own reason — it names the actual problem
        # (InvalidMetadata, quota, ...). Pool advice only when the reason is
        # pool-shaped, so it cannot bury a real error.
        message = (
            f"sandboxclaim {name} was not bound within {self.ready_timeout}s: "
            f"{last_reason or 'no Ready condition reported'}."
        )
        if not last_reason or "DependenciesNotReady" in last_reason:
            message += (
                f" If the SandboxWarmPool '{self.warm_pool}' is exhausted this "
                "is a cold start still in progress — the claim is left in "
                "place and the next attempt resumes it; raise "
                "terminal.kubernetes.ready_timeout_seconds (kata boots easily "
                "exceed the default), or raise the pool's replicas."
            )
        raise TimeoutError(message)

    @staticmethod
    def _pod_name_from_sandbox(sandbox: dict) -> str:
        """resolvePodName(), as the sandbox controller defines it."""
        annotations = _dig_dict(sandbox, "metadata").get("annotations") or {}
        adopted = annotations.get(POD_NAME_ANNOTATION)
        if isinstance(adopted, str) and adopted:
            return adopted
        return str(_dig_dict(sandbox, "metadata").get("name") or "")

    def _assert_pod_belongs(self, pod, pod_name: str, sandbox: dict) -> None:
        """Refuse to exec into a pod the bound Sandbox does not own.

        The very next thing that happens to this pod is a credential-file
        upload, so ownership is POSITIVELY established or we stop: the pod
        must carry an ownerReference to the Sandbox the claim reports.
        """
        sandbox_uid = _dig_dict(sandbox, "metadata").get("uid")
        owners = getattr(
            getattr(pod, "metadata", None), "owner_references", None
        ) or []
        if sandbox_uid and any(
            getattr(o, "uid", None) == sandbox_uid for o in owners
        ):
            return
        raise RuntimeError(
            f"pod {pod_name} does not carry an ownerReference to sandbox "
            f"{_dig_dict(sandbox, 'metadata').get('name')} "
            f"(uid {sandbox_uid}); refusing to exec into it."
        )

    def _list_session_objects(self, selector: str) -> "list[tuple[str, str]]":
        listing = api_call(
            self._custom.list_namespaced_custom_object,
            group=EXTENSIONS_API_GROUP, version=SANDBOX_API_VERSION,
            namespace=self.namespace, plural="sandboxclaims",
            label_selector=selector,
        )
        out = []
        for item in (listing or {}).get("items", []):
            meta = _dig_dict(item, "metadata")
            name = meta.get("name")
            if name:
                out.append((name, (meta.get("labels") or {}).get(INSTANCE_LABEL, "")))
        return out

    def _reap_session_object(self, name: str) -> None:
        # Deleting the claim cascades to the Sandbox and its pod.
        self._delete_claim_and_wait(name, timeout=5)

    def _delete_claim_and_wait(self, name: str, timeout: int = 30) -> None:
        """Delete a claim and block until the name is free for re-creation.

        Guarded by a uid precondition: claim names are deterministic, so a
        delete racing a concurrent re-provision would otherwise remove the
        REPLACEMENT claim (and burn a second warm-pool checkout).
        """
        import time

        from kubernetes.client.exceptions import ApiException

        try:
            uid = _dig_dict(self._get_claim(name), "metadata").get("uid")
        except Exception:
            uid = None
        body = {"preconditions": {"uid": uid}} if uid else None
        try:
            api_call(
                self._custom.delete_namespaced_custom_object,
                group=EXTENSIONS_API_GROUP, version=SANDBOX_API_VERSION,
                namespace=self.namespace, plural="sandboxclaims", name=name,
                **({"body": body} if body else {}),
            )
        except ApiException as exc:
            if exc.status == 409:
                logger.info(
                    "sandboxclaim %s was replaced before our delete "
                    "landed; leaving the new one alone.", name,
                )
                return
            if exc.status != 404:
                raise
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._get_claim(name)
            except ApiException as exc:
                if exc.status == 404:
                    return
                raise
            time.sleep(0.5)
        # Not fatal — the create below will 409 and be handled — but silence
        # here reappears later as a confusing "already exists" or "is dead".
        logger.warning(
            "sandboxclaim %s still present %ss after delete; proceeding.",
            name, timeout,
        )

    # -- WorkspaceProvisioner ------------------------------------------
    def ensure(self, task_id: str) -> PodRef:
        name = self.workspace_name(task_id)
        existed = self._create_claim(self.claim_manifest(task_id))
        if existed:
            self._assert_ours(name)

        for attempt in (1, 2):
            try:
                return self._bind(name)
            except _ClaimDead as dead:
                if attempt == 2:
                    raise RuntimeError(str(dead))
                # Our claim, but its sandbox is unusable — finished (deadline,
                # OOMKill), expired, or its exec container died behind a
                # sidecar. The controller never restarts a finished pod, so
                # replace the claim and bind fresh.
                logger.warning("%s; replacing it.", dead)
                self._delete_claim_and_wait(name)
                self._create_claim(self.claim_manifest(task_id))
        raise RuntimeError(f"sandboxclaim {name} could not be bound")

    def _bind(self, name: str) -> PodRef:
        """One bind attempt: wait for the claim, resolve its pod, prove it is
        usable. Raises :class:`_ClaimDead` when the caller should replace the
        claim rather than keep waiting on it."""
        sandbox_name = self._wait_claim(name)
        # Recorded the moment the claim BINDS: from here on a bound sandbox
        # is checked out of the pool, so teardown must delete it even if the
        # pod checks below fail. (Before binding it is deliberately NOT
        # recorded — see the readiness-timeout note in _wait_claim.)
        self._created_names.add(name)

        sandbox = self._get_sandbox(sandbox_name)
        pod_name = self._pod_name_from_sandbox(sandbox)
        if not pod_name:
            raise RuntimeError(
                f"sandboxclaim {name} is bound to sandbox {sandbox_name!r} "
                "but no pod name could be resolved from it."
            )

        # The claim's conditions are derived from POD PHASE, which only turns
        # terminal once EVERY container exits — so a pod whose exec container
        # died behind a sidecar still reports Ready, and waiting on it just
        # rebinds the same corpse on every attempt. Ask the pod itself before
        # committing to it.
        try:
            bound = api_call(
                self._api.read_namespaced_pod,
                name=pod_name, namespace=self.namespace,
            )
        except Exception:
            bound = None
        if bound is not None and pod_cannot_exec(bound, self.exec_container_name()):
            raise _ClaimDead(
                f"sandboxclaim {name} is bound to sandbox {sandbox_name}, "
                f"whose pod {pod_name} can no longer serve exec"
            )

        pod = self.wait_pod_ready(pod_name)
        self._assert_pod_belongs(pod, pod_name, sandbox)
        self._assert_cwd_matches(pod)
        # uid, like the pod path: without it a pod the sandbox controller
        # recreates under the same name is silently substituted — workspace
        # wiped, env snapshot gone, synced skills gone, no reset note, and the
        # recorded cwd bricked at rc 126 on every later command. The
        # environment compares this uid to spot the swap.
        return PodRef(
            self.namespace, pod_name, self.exec_container(pod),
            uid=str(getattr(getattr(pod, "metadata", None), "uid", "") or ""),
        )

    def _assert_cwd_matches(self, pod) -> None:
        """Refuse a bound pod whose workingDir is not the session's cwd.

        On the pod path ``session_cwd()`` READS the exec container's
        ``workingDir`` out of ``spec``, so the two cannot disagree. A
        SandboxClaim's spec has no containers — the pod comes from the admin's
        SandboxTemplate — so config-derived cwd is a guess, and a wrong guess
        is silent: every command runs `builtin cd` into a directory that does
        not exist, the shell lands in the container-root overlay, and the
        ~/.hermes sync fails into a host-side log the model never sees.

        Loud beats silent here. The operator can align either side: change the
        SandboxTemplate, or set ``terminal.cwd``.
        """
        wanted = session_cwd(self.kcfg)
        expected = self.exec_container_name()
        for container in getattr(getattr(pod, "spec", None), "containers", None) or []:
            if getattr(container, "name", None) != expected:
                continue
            actual = str(getattr(container, "working_dir", "") or "").strip()
            if actual and actual != wanted:
                raise RuntimeError(
                    f"the SandboxTemplate's container {expected!r} has "
                    f"workingDir {actual!r}, but this session would run in "
                    f"{wanted!r}. On kind: SandboxClaim the pod comes from the "
                    "admin's template, so Hermes cannot derive the cwd from "
                    "terminal.kubernetes.spec — set terminal.cwd to "
                    f"{actual!r}, or change the template."
                )
            return

    def has_outstanding(self) -> bool:
        return bool(self._created_names)

    def destroy(self, pod_ref: PodRef) -> None:
        from kubernetes.client.exceptions import ApiException

        # Deleting the CLAIM is what tears everything down: the controller
        # owns the Sandbox, the Sandbox owns the pod, and a checked-out
        # sandbox is never returned to the pool. Delete only the claim names
        # we actually created — a claim we refused to adopt was recorded as
        # foreign, not created, so refusal to reuse stays refusal to delete.
        names = sorted(self._created_names)
        if not names:
            logger.info(
                "no bound sandboxclaim to delete for pod %s (binding "
                "never completed, or the claim was foreign — an unbound claim "
                "is deliberately left for the next attempt to adopt).",
                pod_ref.pod_name,
            )
        for name in names:
            try:
                api_call(
                    self._custom.delete_namespaced_custom_object,
                    group=EXTENSIONS_API_GROUP, version=SANDBOX_API_VERSION,
                    namespace=self.namespace, plural="sandboxclaims", name=name,
                )
            except ApiException as exc:
                if exc.status != 404:
                    logger.warning(
                        "failed to delete sandboxclaim %s: %s", name, exc
                    )
            except Exception as exc:
                logger.warning(
                    "failed to delete sandboxclaim %s: %s", name, exc
                )
        self._created_names.clear()
