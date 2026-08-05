# Kubernetes terminal backend — deployment manifests

Manifests for running Hermes' [`kubernetes` terminal backend](../tools/environments/kubernetes.py) on a real cluster. The backend runs each agent shell command in a **session pod** instead of in the agent's own container, isolating the agent from Hermes' home directory, credential files, and ServiceAccount token.

| File | What it is | Why |
|---|---|---|
| [`rbac.yaml`](./rbac.yaml) | Session `ServiceAccount` + one `Role`/`RoleBinding` per provisioner | Give the agent SA only the verbs it needs, in its own namespace. |
| [`networkpolicy.yaml`](./networkpolicy.yaml) | Default-deny egress + optional internet allowance | Without it a session pod reaches the Kubernetes API and every ClusterIP Service in the cluster. |
| [`validatingadmissionpolicy.yaml`](./validatingadmissionpolicy.yaml) | Namespace-scoped `ValidatingAdmissionPolicy` | Constrains session-pod shape on vanilla Kubernetes. **Largely redundant on OpenShift** — read the header before applying. |

## Configuration lives in config.yaml, not .env

Every setting for this backend is a `config.yaml` key under `terminal.kubernetes.*`. There are **no `TERMINAL_KUBERNETES_*` environment variables**, and none should be added: `.env` is for secrets, and this backend has no credential of its own — in-cluster auth is the projected ServiceAccount token the kubelet mounts, which Hermes never reads or stores.

Minimum config to select it:

```yaml
terminal:
  backend: kubernetes
  cwd: /workspace
  kubernetes:
    namespace: hermes-agents     # optional in-cluster; resolved from the SA otherwise
```

See `cli-config.yaml.example` (OPTION 7) for the full annotated block, or run `hermes setup` and pick *Kubernetes*.

## Apply

```bash
# 1. Edit rbac.yaml: replace <AGENT_NAMESPACE> and <AGENT_SA>.
#    Apply the Role matching terminal.kubernetes.provisioner:
#      direct  -> hermes-session-exec
#      sandbox -> hermes-session-sandbox
kubectl apply -f rbac.yaml

# 2. Network isolation for session pods (edit <AGENT_NAMESPACE> first).
kubectl apply -f networkpolicy.yaml

# 3. Vanilla Kubernetes only — on OpenShift, SCC already covers most of this.
kubectl label namespace <AGENT_NAMESPACE> hermes-agent/session-pods=enforce
kubectl apply -f validatingadmissionpolicy.yaml
```

Then verify with `hermes doctor`, which runs `SelfSubjectAccessReview` for `create pods`, `create pods/exec`, and (in sandbox mode) `create sandboxes.agents.x-k8s.io` — RBAC is where in-cluster deployments actually fail.

Manual equivalent:

```bash
SA=system:serviceaccount:<AGENT_NAMESPACE>:<AGENT_SA>
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i create pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i create deployments --as=$SA -n <AGENT_NAMESPACE>   # no
kubectl auth can-i create secrets     --as=$SA -n <AGENT_NAMESPACE>   # no
```

## Agent Deployment requirements

The Hermes pod itself needs:

* the ServiceAccount bound in `rbac.yaml`;
* the `kubernetes` python client — `pip install 'hermes-agent[kubernetes]'`, or let Hermes lazy-install it on first use.

**Downward API is optional.** Session pods carry an `ownerReference` to the agent pod, so they are garbage-collected if the agent crashes. Hermes resolves its own pod identity by looking itself up on the pod hostname, which needs no extra env. If you prefer to inject it explicitly, these three are honoured when present (they are runtime identity, not user configuration — do not put them in `.env.example`):

```yaml
env:
  - name: HERMES_POD_NAME
    valueFrom: {fieldRef: {fieldPath: metadata.name}}
  - name: HERMES_POD_UID
    valueFrom: {fieldRef: {fieldPath: metadata.uid}}
  - name: HERMES_POD_NAMESPACE
    valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
```

Set `terminal.kubernetes.owner_reference: off` to skip ownerReferences entirely (out-of-cluster dev, or a topology where the agent is not a pod). Ephemeral session pods are still bounded by `terminal.kubernetes.active_deadline_seconds`.

## OpenShift 4.21 notes

* **Do not pin `security_context.run_as_user`.** `restricted-v2` uses `runAsUser: MustRunAsRange` with the range from the namespace's `openshift.io/sa.scc.uid-range` annotation, so a hard-coded `1000` is rejected outright (`must be in the ranges: [1000700000, 1000709999]`). The shipped default leaves `run_as_user`/`fs_group` unset so SCC assigns both. Set them only on vanilla Kubernetes, where `runAsNonRoot` needs a concrete UID to schedule a root-default image.
* **Set resource limits.** A namespace `ResourceQuota` covering `limits.cpu`/`limits.memory` rejects a requests-only pod. Use `terminal.kubernetes.resources.limits`.
* **Sandboxed containers (kata).** Set `terminal.kubernetes.runtime_class_name: kata` and raise `ready_timeout_seconds` — kata cold starts routinely exceed the 120s default.
* **SCC RBAC is usually unnecessary.** With the shipped defaults the session SA satisfies `restricted-v2`, which every authenticated SA already has. The commented block at the bottom of `rbac.yaml` covers the case where you pin a UID or need a custom SCC.

## Provisioners

`terminal.kubernetes.provisioner` selects how the workspace is created. Both produce a pod that Hermes exec's into, and both build the same pod template from the same `terminal.kubernetes.*` keys, so switching is a one-line change.

* **`direct`** (default) — a raw `Pod` (plus a `PersistentVolumeClaim` when `persistent: true`) via the core API.
* **`sandbox`** — a `Sandbox` custom resource (`agents.x-k8s.io/v1beta1`) reconciled by [agent-sandbox-operator](https://github.com/kubernetes-sigs/agent-sandbox) v0.9.0+. Optionally a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) against a `SandboxTemplate`, so a `SandboxWarmPool` can hand back a pre-warmed pod: set `sandbox.use_claim: true` and `sandbox.template_ref`.

  Security upside: the agent SA needs `sandboxes` create/delete but **not** bare `pods` create/delete.

  When `sandbox.template_ref` is set, the operator's template supplies the pod shape and the shared pod-shape keys (`image`, `security_context`, `resources`, …) are not sent.

## Workspace persistence

`terminal.kubernetes.persistent` is deliberately **independent of** the shared `terminal.container_persistent` (which defaults `true` for docker/daytona): a cluster sandbox defaults to ephemeral.

When enabled, a PVC named `hermes-ws-<task>` is created and **never deleted by Hermes** — it must outlive the agent pod for the workspace to resume, so it carries no `ownerReference`. Persistent workspaces therefore accumulate. Reap them yourself:

```bash
kubectl -n <AGENT_NAMESPACE> get pvc -l app.kubernetes.io/managed-by=hermes-agent
```

Persistent sessions also keep the dangerous-command approval prompts on (see `tools/approval.py`): `rm -rf /workspace` against a retained PVC destroys durable state, so it is not treated as a throwaway sandbox.

## What this does NOT protect against

Stated plainly, because the upstream sample overclaimed here:

* The ValidatingAdmissionPolicy hooks on a label the pod creator chooses. A fully compromised agent could omit it. The containment boundary is the RBAC grant (and SCC on OpenShift), not the policy.
* `create pods` in a namespace remains a powerful verb. The policy narrows *shape*; it does not make the grant harmless. Run Hermes in a dedicated namespace with nothing else in it.
* Session pods share the cluster network unless `networkpolicy.yaml` is applied.
