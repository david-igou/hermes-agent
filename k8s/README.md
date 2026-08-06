# Kubernetes terminal backend — deployment manifests

Manifests for running Hermes' [`kubernetes` terminal backend](../tools/environments/kubernetes.py) on a real cluster. The backend runs each agent shell command in a **session pod** instead of in the agent's own container, isolating commands from the Hermes process, its ServiceAccount token, and the agent container's filesystem.

> **The session pod is an execution boundary, not a secrets boundary.** Registered credential files and skills ARE synced into it on session start (same as the Modal/Daytona backends), because skills need them. Only the ServiceAccount-token isolation is absolute.

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
#      pod     -> hermes-session-exec
#      sandbox -> hermes-session-sandbox
kubectl apply -f rbac.yaml

# 2. Network isolation for session pods (edit <AGENT_NAMESPACE> first).
kubectl apply -f networkpolicy.yaml

# 3. Vanilla Kubernetes only — on OpenShift, SCC already covers most of this.
kubectl label namespace <AGENT_NAMESPACE> hermes-agent/session-pods=enforce
kubectl apply -f validatingadmissionpolicy.yaml
```

Then verify with `hermes doctor`, which runs `SelfSubjectAccessReview` for `create pods`, `get pods/exec`, and (in sandbox mode) `create sandboxes.agents.x-k8s.io` — RBAC is where in-cluster deployments actually fail.

> **`get pods/exec`, not `create`.** The python client opens exec with `connect_get_namespaced_pod_exec` — a websocket-upgrading **GET** — so kube-apiserver authorizes it as verb `get`. A Role granting only `create` on `pods/exec` (the kubectl-shaped habit) passes a `create` check and then 403s on the agent's first command.

Manual equivalent:

```bash
SA=system:serviceaccount:<AGENT_NAMESPACE>:<AGENT_SA>
# provisioner: pod
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes  <- the one that matters
# provisioner: sandbox — `create pods` must be NO; the operator owns the pod
kubectl auth can-i create sandboxes.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # yes
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # no
kubectl auth can-i get    pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
# both
kubectl auth can-i create deployments --as=$SA -n <AGENT_NAMESPACE>   # no
kubectl auth can-i create secrets     --as=$SA -n <AGENT_NAMESPACE>   # no
```

`hermes doctor` runs exactly these checks per provisioner (and flags `create pods` being *allowed* under `provisioner: sandbox` as broader than needed).

## Agent Deployment requirements

The Hermes pod itself needs:

* the ServiceAccount bound in `rbac.yaml`;
* the `kubernetes` python client — `pip install 'hermes-agent[kubernetes]'`. There is **no lazy install** for this backend: `check_terminal_requirements()` gates the whole terminal tool on the client being importable, so the tool stays disabled until it is installed.

**Downward API is optional.** Session pods carry an `ownerReference` to the agent pod, so they are garbage-collected if the agent crashes. Hermes resolves its own pod identity by looking itself up on the pod hostname, which needs no extra env. If you prefer to inject it explicitly, these three are honoured when present (they are runtime identity, not user configuration — do not put them in `.env.example`):

```yaml
env:
  - name: HERMES_POD_NAME
    valueFrom: {fieldRef: {fieldPath: metadata.name}}
  - name: HERMES_POD_UID
    valueFrom: {fieldRef: {fieldPath: metadata.uid}}
```

(The namespace is never taken from the environment: in-cluster the kubelet already projects it, and out-of-cluster `terminal.kubernetes.namespace` covers it.) When identity cannot be resolved, Hermes logs a WARNING — session pods then carry no `ownerReference` and are not garbage-collected, so a persistent pod also gets the `active_deadline_seconds` backstop in that case.

Set `terminal.kubernetes.owner_reference: off` to skip ownerReferences entirely (out-of-cluster dev, or a topology where the agent is not a pod). Ephemeral session pods are still bounded by `terminal.kubernetes.active_deadline_seconds`.

## OpenShift 4.21 notes

* **Do not pin `runAsUser`.** `restricted-v2` uses `runAsUser: MustRunAsRange` with the range from the namespace's `openshift.io/sa.scc.uid-range` annotation, so a hard-coded `1000` is rejected outright (`must be in the ranges: [1000700000, 1000709999]`). The hardened base leaves `runAsUser`/`fsGroup` unset so SCC assigns both. Set `pod_template.spec.securityContext.runAsUser` only on vanilla Kubernetes, where `runAsNonRoot` needs a concrete UID to schedule a root-default image.
* **Set resource limits.** A namespace `ResourceQuota` covering `limits.cpu`/`limits.memory` rejects a requests-only pod. Set them on the `workspace` container in `terminal.kubernetes.pod_template` (it merges onto the base by `name`).
* **Sandboxed containers (kata).** Set `terminal.kubernetes.pod_template.spec.runtimeClassName: kata` and raise `ready_timeout_seconds` — kata cold starts routinely exceed the 120s default.
* **SCC RBAC is usually unnecessary.** With the shipped defaults the session SA satisfies `restricted-v2`, which every authenticated SA already has. The commented block at the bottom of `rbac.yaml` covers the case where you pin a UID or need a custom SCC.

## Provisioners

`terminal.kubernetes.provisioner` selects which Kubernetes API creates the workspace. Both exec into a pod, and both consume the **identical** rendered pod template — the `Sandbox` CRD is itself `spec.podTemplate.spec` — so switching is a one-line change that cannot alter the workload shape.

* **`pod`** (default) — a raw `Pod` (plus a `PersistentVolumeClaim` when `persistent: true`) via the core API.
* **`sandbox`** — a `Sandbox` custom resource (`agents.x-k8s.io/v1beta1`) reconciled by [agent-sandbox-operator](https://github.com/kubernetes-sigs/agent-sandbox) v0.9.0+.

  Security upside: the agent SA needs `sandboxes` create/delete but **not** bare `pods` create/delete.

  `terminal.kubernetes.sandbox.spec` is the `Sandbox` **spec** (`ttlSeconds`, `networkPolicy`, …). Two keys in it are **rejected** by config validation:

  * `podTemplate` — the provisioner assigns the one rendered template here. A second source is precisely how the object that was security-checked comes to differ from the object that was submitted.
  * `sandboxTemplateRef` — a `SandboxTemplate` makes the operator author a pod this backend never renders, so its hardening cannot be established and the managed-by label the NetworkPolicy selects on would be present only if the template happened to set it. There is deliberately no config key for it.

  Scope of that claim, precisely: it covers the pod shape **this backend renders**, which under this schema is every pod it creates. It does not cover anything a compromised agent does by calling the Kubernetes API directly with its own credentials. That is bounded by RBAC, the ValidatingAdmissionPolicy and NetworkPolicy — not by this backend.

## Pod shape

`terminal.kubernetes.pod_template` is the ONE user layer: a `PodTemplateSpec` merged over a hardened base by a documented Hermes merge rule (mappings merge; lists replace, except `spec.containers` / `spec.initContainers` / `spec.volumes` keyed by `name` and their `volumeMounts` keyed by `mountPath` — the keys the API server itself uses). `render_pod_template()` produces exactly one artifact, nothing runs after it, and `unhardened_reasons()` judges that same call.

Hermes owns the fields that make exec possible and **rejects** a template that sets them, with the exact dotted path — it does not silently overwrite them:

| Reserved | Why |
| --- | --- |
| `metadata.labels['app.kubernetes.io/managed-by']` | the selector `networkpolicy.yaml`, `validatingadmissionpolicy.yaml` and session-pod adoption all match on |
| `spec.restartPolicy` | pinned `Never`; a restart swaps the container out from under an open exec session |
| a `spec.containers` list omitting `container_name` | Hermes execs into that container |
| that container's `command` | pinned `["sleep","infinity"]` so the pod outlives the session |
| that container's `volumeMounts[mountPath=<mount_path>]` | the workspace mount `terminal.cwd` resolves against |
| `spec.volumes[name=workspace]` | built from `persistent` and `volume.*` |

Everything else in the `PodSpec` is yours. Every create this backend issues passes `fieldValidation=Strict`, so an unknown or duplicated field is a `400` naming the path rather than a silent drop (the python client discards the API server's `Warning: 299 - unknown field` header, which makes the default `Warn` behaviour indistinguishable from success). `hermes doctor` submits your rendered pod as a `dry_run=All` create for the same reason.

## Workspace persistence

`terminal.kubernetes.persistent` is deliberately **independent of** the shared `terminal.container_persistent` (which defaults `true` for docker/daytona): a cluster sandbox defaults to ephemeral.

When enabled, a PVC named `hermes-ws-<task>` is created and **never deleted by Hermes** — it must outlive the agent pod for the workspace to resume, so it carries no `ownerReference`. Persistent workspaces therefore accumulate. Reap them yourself:

```bash
kubectl -n <AGENT_NAMESPACE> get pvc \
  -l app.kubernetes.io/managed-by=hermes-agent,app.kubernetes.io/component=hermes-workspace
```

The claim name is **task-scoped, not instance-scoped**: two Hermes instances in one namespace running the same task id (and `_resolve_container_task_id` collapses nearly every session to `default`) target the same PVC, and with `ReadWriteOnce` the second session pod stays `Pending`. Set `terminal.kubernetes.volume.claim_name` to give an instance its own workspace.

> **A persistent workspace holds the agent's credential files at rest.** The PVC is mounted at `mount_path`, which is the agent's cwd, and the session-start file sync writes the registered credential files into `<cwd>/.hermes` — i.e. onto this volume, which Hermes never deletes. Consequences to accept before enabling `persistent: true`:
>
> * any pod in the namespace that can mount a PVC by name can read those files (this is the co-tenancy warning below, made concrete);
> * Hermes refuses to adopt an existing claim that does not carry `app.kubernetes.io/managed-by: hermes-agent`, but it *will* share a claim with another Hermes instance running the same task id — that is the documented task-scoped behaviour, not an accident;
> * the reaper above deletes those credentials along with the workspace. Run it.

Persistent sessions also keep the dangerous-command approval prompts on (see `tools/approval.py`): `rm -rf /workspace` against a retained PVC destroys durable state, so it is not treated as a throwaway sandbox.

## What this does NOT protect against

Stated plainly, because the upstream sample overclaimed here:

* The ValidatingAdmissionPolicy hooks on a label the pod creator chooses. Hermes *configuration* cannot strip it — the label is on THE rendered template, setting the key in `pod_template.metadata.labels` is a rejected config error, and there is no second override layer nor any operator-authored-pod mode left — but a fully compromised agent talking to the API server directly could omit it. The containment boundary is the RBAC grant (and SCC on OpenShift), not the policy.
* The policy also denies secret-backed env (`envFrom.secretRef`, `valueFrom.secretKeyRef`), not only secret volumes — so injecting provider API keys into the session pod is denied wherever it is bound. Deliberate; see the file header if you need to relax it.
* `create pods` in a namespace remains a powerful verb. The policy narrows *shape*; it does not make the grant harmless. Run Hermes in a dedicated namespace with nothing else in it.
* Session pods share the cluster network unless `networkpolicy.yaml` is applied.
* **Exec requests are recorded in the API-server audit log.** The kubernetes client puts every `command` element of an exec into the request URL, and kube-apiserver records `requestURI` at Metadata level and above. The file-sync transport therefore streams its payload over the exec **stdin** channel and never through argv — but a command the *agent* runs still appears in the audit log verbatim, including anything it pipes in through the heredoc stdin mode. Do not treat the audit log as a place secrets cannot reach.
