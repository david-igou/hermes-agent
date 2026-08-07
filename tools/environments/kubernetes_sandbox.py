"""``Sandbox`` CR provisioner for the Kubernetes terminal backend.

The second implementation of :class:`~tools.environments.kubernetes.
WorkspaceProvisioner`, and the reason that ABC exists: it provisions session
workspaces as ``agents.x-k8s.io/v1beta1`` ``Sandbox`` custom resources and lets
agent-sandbox-operator reconcile the pod, while the exec loop and the file sync
are shared with ``provisioner: pod`` unchanged.

Deliberately a separate module.  Everything Sandbox-specific is here plus the
three ``terminal.kubernetes.sandbox.*`` keys, the ``provisioner == "sandbox"``
branch of the environment factory and the sandbox arm of ``hermes doctor`` — so
a pod-only build is this file plus those three call sites, with nothing to
unpick in the shared code.

The pod template is NOT authored here.  ``render_pod_template`` produces it and
:meth:`SandboxProvisioner.sandbox_manifest` ASSIGNS it to ``spec.podTemplate``,
so a ``sandbox.spec.podTemplate`` written in config is overwritten by the
rendered one.  Everything else in ``terminal.kubernetes.sandbox.spec`` is
submitted verbatim and validated by the CRD's own schema under
``field_validation="Strict"``.
"""

import logging
from copy import deepcopy
from typing import Any, Optional

from tools.environments.kubernetes import (
    MANAGED_BY_LABEL,
    STRICT_FIELD_VALIDATION,
    PodRef,
    Resources,
    _BaseProvisioner,
    _dig_dict,
    render_pod_template,
)

logger = logging.getLogger(__name__)

#: The Sandbox status condition that means "reconciled". Part of the CRD
#: contract ``sandbox.api_version`` already pins, so it is a constant rather
#: than a per-deploy knob nothing was setting.
_SANDBOX_READY_CONDITION = "Ready"


def _singular(plural: str) -> str:
    """``sandboxes`` -> ``sandbox``. ``plural[:-1]`` said "sandboxe"."""
    if plural.endswith("es") and plural[:-2].endswith(("s", "x", "z", "ch", "sh")):
        return plural[:-2]
    return plural[:-1] if plural.endswith("s") else plural


class SandboxProvisioner(_BaseProvisioner):
    """Provisions session workspaces as ``Sandbox`` custom resources.

    Creates ``agents.x-k8s.io/v1beta1`` ``Sandbox`` objects and lets
    agent-sandbox-operator reconcile the pod.  Exec still happens by exec-ing
    into the resulting pod, so the exec loop is identical to the pod path.

    Security upside: the agent's ServiceAccount needs ``sandboxes`` create/
    delete but does NOT need bare ``pods`` create/delete.
    """

    def __init__(self, kcfg: dict, namespace: str, api=None, owner_reference=None,
                 custom_api=None):
        super().__init__(kcfg, namespace, api=api, owner_reference=owner_reference)
        self._custom = custom_api
        sb = kcfg.get("sandbox")
        sb = sb if isinstance(sb, dict) else {}
        self.group = str(sb.get("api_group") or "agents.x-k8s.io")
        self.version = str(sb.get("api_version") or "v1beta1")
        # terminal.kubernetes.sandbox.spec — the Sandbox CR spec. The
        # podTemplate this provisioner injects overwrites any written here;
        # everything else is submitted verbatim for the CRD schema to validate.
        # A non-mapping is REPORTED by validate_kubernetes_config() (the factory
        # refuses to build this provisioner); the {} fallback only keeps
        # sandbox_manifest() from dying with a TypeError on item assignment if
        # it is ever called without validation having run.
        spec_cfg = sb.get("spec")
        self.cr_spec = spec_cfg if isinstance(spec_cfg, dict) else {}
        # CR names this provisioner created (or proved were ours), so destroy()
        # deletes the right object even when the reconciled pod has a different
        # name — and deletes NOTHING when there is no such name.
        self._created_names: set[str] = set()

    # -- manifests ------------------------------------------------------
    def sandbox_manifest(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> dict:
        """Build the Sandbox CR carrying the rendered pod template.

        ``spec.podTemplate`` is ASSIGNED, never merged: the Sandbox CRD is
        itself ``spec.podTemplate.spec``, so the same dict feeds both
        provisioners. A ``podTemplate`` written in ``sandbox.spec`` is therefore
        overwritten rather than rejected; a ``sandboxTemplateRef`` written there
        is submitted, and what the operator then does with it is the operator's
        and the cluster's business, not this backend's.
        """
        spec: dict[str, Any] = deepcopy(self.cr_spec)
        spec["podTemplate"] = render_pod_template(
            self.kcfg,
            persistent=persistent,
            image=image,
            resources=resources,
            pvc_name=self.pvc_name(task_id),
            owned=self._owner_reference is not None,
        )

        metadata: dict[str, Any] = {
            "name": self.workspace_name(task_id),
            "namespace": self.namespace,
            "labels": dict(MANAGED_BY_LABEL),
        }
        if self._owner_reference is not None:
            metadata["ownerReferences"] = [dict(self._owner_reference)]
        return {
            "apiVersion": f"{self.group}/{self.version}",
            "kind": "Sandbox",
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
                plural=plural, body=body, **STRICT_FIELD_VALIDATION,
            )
        except ApiException as exc:
            if exc.status == 404:
                raise RuntimeError(
                    f"kubernetes backend: {plural}.{group}/{self.version} is not "
                    "served by this cluster. Install agent-sandbox-operator "
                    "(v0.9.0+) or set terminal.kubernetes.provisioner: pod."
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
            raise self._refuse(name, (
                f"{_singular(plural)} {name} already exists but could not be "
                f"read ({exc}); refusing to reuse or delete it."
            )) from exc
        owners = _dig_dict(existing, "metadata").get("ownerReferences") or []
        our_uid = self._owner_reference.get("uid")
        if not any(
            isinstance(o, dict) and o.get("uid") == our_uid for o in owners
        ):
            raise self._refuse(name, (
                f"{_singular(plural)} {name} already exists and was not created "
                "by this Hermes instance; refusing to reuse it."
            ))

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

    def _wait_sandbox(self, name: str) -> dict:
        """Poll a Sandbox until it reports Ready (or times out)."""
        import time

        deadline = time.monotonic() + self.ready_timeout
        last: dict = {}
        while time.monotonic() < deadline:
            last = self._get_object(self.group, "sandboxes", name)
            conditions = (last.get("status") or {}).get("conditions") or []
            for cond in conditions:
                if cond.get("type") == _SANDBOX_READY_CONDITION:
                    if str(cond.get("status")) == "True":
                        return last
                    if str(cond.get("reason") or "").endswith("Failed"):
                        raise RuntimeError(
                            f"sandbox {name} failed: "
                            f"{cond.get('message') or cond.get('reason')}"
                        )
            # Some operator versions surface the pod before the condition
            # flips; that's good enough because we still gate on pod Ready.
            # Status-only (no LIST): this runs every 0.5s.
            if self._pod_name_from_status(last):
                return last
            time.sleep(0.5)
        raise TimeoutError(
            f"sandbox {name} did not report {_SANDBOX_READY_CONDITION}=True "
            f"within {self.ready_timeout}s. Last status: {last.get('status')}"
        )

    # -- WorkspaceProvisioner ------------------------------------------
    def ensure(
        self, task_id: str, persistent: bool, image: str, resources: Resources
    ) -> PodRef:
        name = self.workspace_name(task_id)
        if persistent:
            self._ensure_pvc(task_id, resources)

        existed = self._create_object(
            self.group, "sandboxes",
            self.sandbox_manifest(task_id, persistent, image, resources),
        )
        if existed:
            self._assert_ours(self.group, "sandboxes", name)
        self._created_names.add(name)

        sandbox = self._wait_sandbox(name)
        pod_name, proven = self._resolve_pod_name(sandbox, name)
        pod = self.wait_pod_ready(pod_name)
        self._assert_pod_belongs(pod, pod_name, sandbox, name, proven=proven)
        return PodRef(self.namespace, pod_name, self.exec_container(pod))

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
                "is unrecognised — file it, or use provisioner: pod."
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
        # The reconciled pod may be named after the CR or resolved via labels,
        # so delete by the CR names we actually created — and ONLY those. The
        # old `or [pod_ref.pod_name]` fallback fired precisely when _assert_ours
        # had refused to adopt a foreign CR (nothing had been recorded), so the
        # refusal to reuse it was followed by deleting it.
        names = sorted(self._created_names)
        if not names:
            logger.warning(
                "k8s: not deleting sandbox %s: this provisioner never created "
                "or adopted it.", pod_ref.pod_name,
            )
        for name in names:
            try:
                self._custom.delete_namespaced_custom_object(
                    group=self.group, version=self.version,
                    namespace=self.namespace, plural="sandboxes", name=name,
                )
            except ApiException as exc:
                if exc.status != 404:
                    logger.warning("k8s: failed to delete sandbox %s: %s", name, exc)
            except Exception as exc:
                logger.warning("k8s: failed to delete sandbox %s: %s", name, exc)
        self._created_names.clear()


__all__ = ["SandboxProvisioner"]
