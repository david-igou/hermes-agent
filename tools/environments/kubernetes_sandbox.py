"""``SandboxClaim`` provisioner for the Kubernetes terminal backend.

Consumes `kubernetes-sigs/agent-sandbox
<https://github.com/kubernetes-sigs/agent-sandbox>`_ (and the Red Hat build of
it) the way the project intends to be consumed:

* the cluster admin owns a ``SandboxTemplate`` — the POD SHAPE lives there,
  authored and admission-controlled cluster-side, not in Hermes config;
* the admin owns a ``SandboxWarmPool`` that keeps N sandboxes pre-provisioned
  from that template (this is what absorbs Kata cold starts);
* Hermes creates a ``SandboxClaim`` naming the pool, and the claim controller
  binds it to a warm sandbox in milliseconds.

Hermes therefore never authors a pod on this path.  ``pod_template`` is not
consulted, and the agent's ServiceAccount needs ``sandboxclaims`` — not
``pods create``, and not ``sandboxes create``.  That is the point: with the
raw-``Sandbox`` design this module replaced, Hermes-supplied pod YAML reached
the cluster through the operator's own ServiceAccount, so neither the shipped
ValidatingAdmissionPolicy nor OpenShift SCC ever saw it.  A claim carries no
pod spec to smuggle: what the pod may be is decided entirely by the admin's
template plus the admission stack, and RBAC on ``sandboxtemplates``/
``sandboxwarmpools`` keeps it that way.

A warm pod predates the session, but it contains nothing session-specific
until the claim binds — the credential-file sync happens strictly after
binding, and the sandbox dies with the claim (``shutdownPolicy: Delete``; a
checked-out sandbox is never returned to the pool).  So per-session isolation
holds exactly as it does on the pod path.

Resolution chain, every hop provable::

    claim.status.sandbox.name
      -> Sandbox CR (agents.x-k8s.io/v1beta1): uid + pod name
         (the agents.x-k8s.io/pod-name annotation when the pod was adopted
          from the pool, else the Sandbox's own name)
        -> pod, whose ownerReferences must carry the Sandbox uid.

Deliberately a separate module.  Everything claim-specific is here plus ONE
config key (``terminal.kubernetes.sandbox.warm_pool``), the ``provisioner ==
"sandbox"`` branch of the environment factory and the sandbox arm of ``hermes
doctor`` — so a pod-only build is this file plus those call sites, with
nothing to unpick in the shared code.

The claim deliberately sets neither ``env`` nor ``volumeClaimTemplates``:
both force a cold start (the warm pod does not have them), which defeats the
pool.  Session state enters the pod through the existing exec-based file
sync, same as the pod path.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from tools.environments.kubernetes import (
    INSTANCE_LABEL,
    MANAGED_BY_LABEL,
    STRICT_FIELD_VALIDATION,
    PodRef,
    _BaseProvisioner,
    _dig_dict,
    _mapping,
    api_call,
)

logger = logging.getLogger(__name__)

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


class SandboxClaimProvisioner(_BaseProvisioner):
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
        self.warm_pool = str(
            _mapping(kcfg, "sandbox").get("warm_pool") or ""
        ).strip()
        # Claim names this provisioner created (or proved were ours), so
        # destroy() deletes the right object — and NOTHING when there is no
        # such name.
        self._created_names: set[str] = set()

    # -- manifests ------------------------------------------------------
    def claim_manifest(self, task_id: str) -> dict:
        """Build the SandboxClaim. No pod spec: the pool's template owns that."""
        if not self.warm_pool:
            raise RuntimeError(
                "kubernetes backend: provisioner: sandbox requires "
                "terminal.kubernetes.sandbox.warm_pool to name a "
                "SandboxWarmPool in the session namespace. The pool (and the "
                "SandboxTemplate it instantiates) are the cluster admin's "
                "objects — see k8s/README.md. Or set "
                "terminal.kubernetes.provisioner: pod."
            )
        lifecycle: dict[str, Any] = {
            # The controller default is Retain, which would leave the claim
            # behind on expiry. A session workspace is disposable.
            "shutdownPolicy": "Delete",
        }
        # ALWAYS emitted, even at active_deadline_seconds: 0. On the pod path
        # 0 means "no activeDeadlineSeconds", which merely declines a ceiling;
        # here it would remove the claim's ONLY reaper (nothing else expires a
        # bound claim), so a crashed process would hold a warm-pool checkout
        # forever. 0 falls back to the schema default rather than to "never".
        deadline = int(self.kcfg.get("active_deadline_seconds") or 0) or 14400
        expires = datetime.now(timezone.utc) + timedelta(seconds=deadline)
        lifecycle["shutdownTime"] = (
            expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )

        metadata: dict[str, Any] = {
            "name": self.workspace_name(task_id),
            "namespace": self.namespace,
            "labels": {**MANAGED_BY_LABEL, INSTANCE_LABEL: self._instance},
        }
        if self._owner_reference is not None:
            # GC chain: agent pod -> claim -> (controller-owned) Sandbox -> pod.
            metadata["ownerReferences"] = [dict(self._owner_reference)]
        return {
            "apiVersion": f"{EXTENSIONS_API_GROUP}/{SANDBOX_API_VERSION}",
            "kind": "SandboxClaim",
            "metadata": metadata,
            # Deliberately NO additionalPodMetadata: the claim controller
            # runs its labels through a strict domain allowlist that defaults
            # to sandbox.users.io (no install path ships the ConfigMap that
            # widens it), so any label Hermes set there — including
            # app.kubernetes.io/managed-by — made EVERY claim fail with
            # InvalidMetadata on a stock install. The pod's managed-by label
            # (what k8s/networkpolicy.yaml selects on) belongs in the admin's
            # SandboxTemplate, where the README sample already puts it.
            "spec": {
                "warmPoolRef": {"name": self.warm_pool},
                "lifecycle": lifecycle,
            },
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
            # Out-of-cluster dev: no agent identity to compare against, so the
            # instance discriminator in the name is the only guard there is.
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
                    "k8s: sandboxclaim %s was replaced before our delete "
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
            "k8s: sandboxclaim %s still present %ss after delete; proceeding.",
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
                sandbox_name = self._wait_claim(name)
            except _ClaimDead as dead:
                if attempt == 2:
                    raise RuntimeError(str(dead))
                # Our claim, but its sandbox finished (deadline, OOMKill) or
                # it expired — the controller never restarts a finished pod,
                # so replace the claim and bind fresh.
                logger.warning("k8s: %s; replacing it.", dead)
                self._delete_claim_and_wait(name)
                self._create_claim(self.claim_manifest(task_id))
                continue
            break

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
        pod = self.wait_pod_ready(pod_name)
        self._assert_pod_belongs(pod, pod_name, sandbox)
        return PodRef(self.namespace, pod_name, self.exec_container(pod))

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
                "k8s: no bound sandboxclaim to delete for pod %s (binding "
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
                        "k8s: failed to delete sandboxclaim %s: %s", name, exc
                    )
            except Exception as exc:
                logger.warning(
                    "k8s: failed to delete sandboxclaim %s: %s", name, exc
                )
        self._created_names.clear()


__all__ = [
    "SandboxClaimProvisioner",
    "SANDBOX_API_GROUP",
    "EXTENSIONS_API_GROUP",
    "SANDBOX_API_VERSION",
    "POD_NAME_ANNOTATION",
]
