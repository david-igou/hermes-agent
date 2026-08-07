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
#    It contains BOTH Role variants — apply it, then delete the one your
#    provisioner does not use. (Keeping both would hand a sandbox deployment
#    the pod-authoring surface that provisioner exists to remove.)
kubectl apply -f rbac.yaml
#      provisioner: pod
kubectl delete role,rolebinding hermes-session-sandbox -n <AGENT_NAMESPACE> --ignore-not-found
#      provisioner: sandbox
# kubectl delete role,rolebinding hermes-session-exec -n <AGENT_NAMESPACE> --ignore-not-found

# 2. Network isolation for session pods (edit <AGENT_NAMESPACE> first).
kubectl apply -f networkpolicy.yaml

# 3. Vanilla Kubernetes only — on OpenShift, SCC already covers most of this.
kubectl label namespace <AGENT_NAMESPACE> hermes-agent/session-pods=enforce
kubectl apply -f validatingadmissionpolicy.yaml
```

Then verify with `hermes doctor`, which runs `SelfSubjectAccessReview` for `create pods`, `get pods/exec`, and (in sandbox mode) `create sandboxclaims.extensions.agents.x-k8s.io` plus a read of the configured `SandboxWarmPool` — RBAC is where in-cluster deployments actually fail.

> **`get pods/exec`, not `create`.** The python client opens exec with `connect_get_namespaced_pod_exec` — a websocket-upgrading **GET** — so kube-apiserver authorizes it as verb `get`. A Role granting only `create` on `pods/exec` (the kubectl-shaped habit) passes a `create` check and then 403s on the agent's first command.

Manual equivalent:

```bash
SA=system:serviceaccount:<AGENT_NAMESPACE>:<AGENT_SA>
# provisioner: pod
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods        --as=$SA -n <AGENT_NAMESPACE>   # yes  <- readiness, 409 ownership, ownerRef lookup
kubectl auth can-i delete pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes  <- the one that matters
kubectl auth can-i list   pods        --as=$SA -n <AGENT_NAMESPACE>   # optional (startup orphan sweep)
# provisioner: sandbox — `create pods` must be NO; the claim controller owns the pod
kubectl auth can-i create sandboxclaims.extensions.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # yes
kubectl auth can-i get    sandboxclaims.extensions.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # yes
kubectl auth can-i delete sandboxclaims.extensions.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # yes
kubectl auth can-i list   sandboxclaims.extensions.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # optional (sweep)
kubectl auth can-i get    sandboxes.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # yes
kubectl auth can-i get    pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i create sandboxes.agents.x-k8s.io --as=$SA -n <AGENT_NAMESPACE>  # no
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # no
# both
kubectl auth can-i create deployments --as=$SA -n <AGENT_NAMESPACE>   # no
kubectl auth can-i create secrets     --as=$SA -n <AGENT_NAMESPACE>   # no
```

`hermes doctor` runs these same checks per provisioner — the `# optional` ones as warnings, not failures — plus a `SandboxWarmPool` read on the sandbox path, and it flags `create pods` being *allowed* under `provisioner: sandbox` as broader than needed. The two `deployments`/`secrets` probes below are yours, not doctor's.

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

(The namespace is never taken from the environment: in-cluster the kubelet already projects it, and out-of-cluster `terminal.kubernetes.namespace` covers it.) When identity cannot be resolved, Hermes logs a WARNING — session pods then carry no `ownerReference` and are not garbage-collected until the `active_deadline_seconds` backstop fires.

Set `terminal.kubernetes.owner_reference: off` to skip ownerReferences entirely (out-of-cluster dev, or a topology where the agent is not a pod). Session pods are still bounded by `terminal.kubernetes.active_deadline_seconds` — but note what that bound does on each path: `spec.activeDeadlineSeconds` **stops** the pod (phase `Failed`) and leaves the object present for you or Hermes to delete, whereas the claim's `lifecycle.shutdownTime` **deletes** the claim and cascades. Hermes deletes a stopped pod when it next tries to use it, and the startup sweep collects ones left by a previous process; neither is Kubernetes GC.

## OpenShift 4.21 notes

* **Do not pin `runAsUser`.** `restricted-v2` uses `runAsUser: MustRunAsRange` with the range from the namespace's `openshift.io/sa.scc.uid-range` annotation, so a hard-coded `1000` is rejected outright (`must be in the ranges: [1000700000, 1000709999]`). The default base leaves `runAsUser`/`fsGroup` unset so SCC assigns both. Set `pod_template.spec.securityContext.runAsUser` only on vanilla Kubernetes, where `runAsNonRoot` needs a concrete UID to schedule a root-default image.
* **Set resource limits.** A namespace `ResourceQuota` covering `limits.cpu`/`limits.memory` rejects a requests-only pod. Set them on the `workspace` container in `terminal.kubernetes.pod_template` (it merges onto the base by `name`) — and include `ephemeral-storage` there too, since the workspace emptyDir is otherwise unbounded.
* **Sandboxed containers (kata).** On `provisioner: pod`, set `terminal.kubernetes.pod_template.spec.runtimeClassName: kata` and raise `ready_timeout_seconds` — kata cold starts routinely exceed the 120s default. On `provisioner: sandbox`, put `runtimeClassName: kata` in the `SandboxTemplate` instead: the warm pool eats the cold start and claims bind in milliseconds.
* **SCC RBAC is usually unnecessary.** With the shipped defaults the session SA satisfies `restricted-v2`, which every authenticated SA already has. The commented block at the bottom of `rbac.yaml` covers the case where you pin a UID or need a custom SCC.

## Provisioners

`terminal.kubernetes.provisioner` selects which Kubernetes API creates the workspace. Both exec into a pod; **who authors the pod differs**, and that is the entire trade:

* **`pod`** (default) — a raw `Pod` via the core API. *You* author the pod in `terminal.kubernetes.pod_template`; your cluster's admission stack (SCC / PSA / the VAP here) judges it, because it is submitted under the agent's own ServiceAccount.
* **`sandbox`** — a `SandboxClaim` (`extensions.agents.x-k8s.io/v1beta1`) checked out of a **`SandboxWarmPool`**, per the [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) operating model (also shipped as the Red Hat build of Agent Sandbox). *The cluster admin* authors the pod, once, in a **`SandboxTemplate`**; the pool keeps N sandboxes pre-provisioned from it, and Hermes' claim binds to one in milliseconds — which is also what absorbs kata cold starts. `pod_template` is **ignored** on this path.

  Security upside: the agent SA needs `sandboxclaims` create/get/delete and read-only `sandboxes` — **no** pod-authoring surface at all. The `SandboxTemplate` is the enforcement point: keep write access to `sandboxtemplates`/`sandboxwarmpools` away from the agent SA (see `rbac.yaml`), and the agent cannot influence session-pod shape by construction.

  Lifecycle: the claim is created with `lifecycle.shutdownPolicy: Delete` plus a `shutdownTime` backstop derived from `terminal.kubernetes.active_deadline_seconds`, and carries an `ownerReference` to the agent pod — so teardown cascades claim → sandbox → pod whether the session ends cleanly, the deadline fires, or the agent dies. A checked-out sandbox is never returned to the pool.

  Admin-side objects (this is what you deploy; adjust image/hardening to taste — Hermes has no opinion beyond the exec contract below):

  ```yaml
  apiVersion: extensions.agents.x-k8s.io/v1beta1
  kind: SandboxTemplate
  metadata:
    name: hermes-session
    namespace: <AGENT_NAMESPACE>
  spec:
    podTemplate:
      metadata:
        # YOUR responsibility on this path: Hermes sets no pod metadata at
        # all (the claim controller's label allowlist would reject it), so
        # this is the only place the label networkpolicy.yaml selects on can
        # come from.
        labels: {app.kubernetes.io/managed-by: hermes-agent}
      spec:
        # runtimeClassName: kata          # per-session kernel isolation
        serviceAccountName: hermes-session-noperms
        automountServiceAccountToken: false
        restartPolicy: Never
        terminationGracePeriodSeconds: 1
        # PID 1 must REAP: `sleep` never does, so without this a backgrounded
        # command's wrapper zombifies and completion is never detected.
        shareProcessNamespace: true
        containers:
          - name: workspace               # = terminal.kubernetes.container_name
            image: nikolaik/python-nodejs:python3.11-nodejs20
            command: ["sleep", "infinity"]
            workingDir: /workspace        # = terminal.kubernetes.mount_path
            volumeMounts:
              - {name: workspace, mountPath: /workspace}
              - {name: tmp, mountPath: /tmp}
            securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false
              capabilities: {drop: [ALL]}
        volumes:
          - {name: workspace, emptyDir: {}}
          - {name: tmp, emptyDir: {}}
  ---
  apiVersion: extensions.agents.x-k8s.io/v1beta1
  kind: SandboxWarmPool
  metadata:
    name: hermes-session-pool             # = terminal.kubernetes.sandbox.warm_pool
    namespace: <AGENT_NAMESPACE>
  spec:
    replicas: 2
    sandboxTemplateRef: {name: hermes-session}
  ```

  **The exec contract** — what the template must satisfy for Hermes to be able to use the pod: a container named `terminal.kubernetes.container_name` running something long-lived (`sleep infinity`), with a writable `terminal.kubernetes.mount_path` (the session cwd), a writable `/tmp`, **a PID 1 that reaps orphans** (`shareProcessNamespace: true`, or an init as the container command — otherwise background commands zombify and completion is never detected), and the `app.kubernetes.io/managed-by: hermes-agent` label in `podTemplate.metadata` if you use `networkpolicy.yaml`. `hermes doctor` verifies the pool exists and reports ready capacity, and dry-runs the claim; a template that breaks the contract fails visibly at the first session with the container/cwd named.

### Choosing a provisioner

**Use `provisioner: pod` when:** you are on OpenShift with `restricted-v2` (or any cluster without an agent-sandbox install), you want the pod shape and resource limits to live in your Hermes config, and a normal image pull's worth of session-start latency is acceptable. This is the default and the better-tested path.

**Use `provisioner: sandbox` when:** you run a slow-boot runtime (kata) and want the warm pool to absorb the cold start, you have a cluster admin who owns the `SandboxTemplate` and keeps it in sync with the exec contract above, and you want the agent ServiceAccount to have no pod-authoring surface at all.

Sandbox-path sizing and policy facts the manifests cannot check for you:

1. **Pool sizing is a ceiling on creations, not concurrent sessions.** A checked-out sandbox is never returned to the pool, and Hermes creates a claim on every environment (re-)creation — including after `terminal.lifetime_seconds` (default **300 s**) of tool inactivity. Size `spec.replicas` for creation rate × provisioning time, and raise `lifetime_seconds` (e.g. to match `active_deadline_seconds`) so an idle user does not burn a slot every five minutes.
2. **Exhausted pool = cold start.** The claim then boots a fresh sandbox from the template; under kata that easily exceeds the 120 s `ready_timeout_seconds` default, so raise it. A binding that times out leaves the claim in place on purpose — the next attempt adopts it and resumes the same boot rather than restarting it.
3. **The ValidatingAdmissionPolicy is not inert on this path.** If the namespace is labeled for enforcement, the policy adjudicates warm-pool and cold-start pods too (they carry the same `managed-by` label from your template). Your `SandboxTemplate` must satisfy the same floors, or the pool never fills and claims time out blaming `replicas` — see the policy header.

## Pod shape

`terminal.kubernetes.pod_template` is the ONE user layer: a `PodTemplateSpec` merged over a **default** base. The base is defaults — the image, the exec container and its `sleep infinity` command, `restartPolicy: Never`, the workspace and `/tmp` volumes, a conservative `securityContext` — chosen so the out-of-box config produces a pod that starts and can be exec'd into. **It is not a constraint. Nothing is reserved**: a `pod_template` may override any field in it, including the exec container's `command`, `args`, `restartPolicy`, `volumeMounts` and `securityContext`. If the result cannot serve exec, that surfaces as an error from the API server or from the first command — visibly, which is the point.

### Merge rule

**JSON merge patch ([RFC 7386](https://www.rfc-editor.org/rfc/rfc7386)), plus one exception.** Mappings merge recursively; a `null` **removes** the key it names (so any base default can be dropped); every list **replaces** the base's wholesale — `volumes`, `volumeMounts`, `env`, `tolerations`, `imagePullSecrets`, `ports`, all of them. The exception: `spec.containers` and `spec.initContainers` merge **element-wise on `name`**, because without it the most common override there — setting `resources` on the workspace container — would force you to restate its image, command and mounts. A container the base does not declare is appended.

```yaml
pod_template:
  spec:
    nodeSelector: {disktype: ssd}      # map: merges into the base's spec
    tolerations: [{key: gpu, operator: Exists}]   # list: replaces (base has none)
    volumes:                           # list: REPLACES — the base's `workspace`
      - name: scratch                  # and `tmp` volumes are GONE. Restate them
        emptyDir: {}                   # if you still want them.
    containers:                        # exception: merged by `name`
      - name: workspace                # image/command/volumeMounts are kept
        resources:
          limits: {cpu: "2", memory: 4Gi}
```

The one thing Hermes stamps **after** the merge is `metadata.labels['app.kubernetes.io/managed-by': hermes-agent]`. That is not a security control — it is how Hermes finds and adopts its own session pods, and what `networkpolicy.yaml` and `validatingadmissionpolicy.yaml` select on. Set the key if you like; the stamp wins.

### Validation is the cluster's job

Hermes validates **nothing** about the config in-process, on purpose — the only Hermes-side check is the `provisioner` enum, because it selects which API to call. Everything else is delegated:

* **Well-formedness** — every create this backend issues passes `fieldValidation=Strict`, so an unknown, misspelled or duplicated field is a `400` naming the exact JSON path. (The python client discards the API server's `Warning: 299 - unknown field` header, which makes the default `Warn` behaviour indistinguishable from success, so Strict is not optional here.) `hermes doctor` submits your rendered pod as a `dry_run=All` create for the same reason: you see the server's verdict at config time.
* **What the pod may be** — SCC, Pod Security Admission, the `ValidatingAdmissionPolicy` in this directory, NetworkPolicy and RBAC. These are the cluster administrator's tools, they are authoritative, and an in-process approximation of them would be redundant where it agreed and wrong where it did not.

## Workspaces are stateless

The workspace is an `emptyDir` that dies with the session pod — there is deliberately no persistence surface (no PVCs, no `persistentvolumeclaims` RBAC, nothing for a reaper to reap). A dead pod (deadline, eviction, OOMKill) is deleted and re-provisioned empty on the next command, Hermes re-syncs skills and credential files into it automatically, and the first tool result after the reset says so to the model.

Two lifetime knobs bound every session pod, and both are worth setting deliberately:

* **`terminal.lifetime_seconds` (default 300)** — the shared idle reaper destroys the environment (pod or claim) after this much tool-call inactivity. This backend has no persist exemption, so 300 s of idleness costs the workspace; raise it (e.g. to match `active_deadline_seconds`) if you want session-length workspaces, and size warm pools with it in mind.
* **`terminal.kubernetes.active_deadline_seconds` (default 14400)** — the hard per-session ceiling. On the pod path it is `spec.activeDeadlineSeconds`, which stops the pod but does **not** delete it; on the claim path it is `lifecycle.shutdownTime`, which deletes the claim and cascades. Unlike the pod path, `0` is not honoured on the claim path — it would leave a checked-out warm-pool sandbox with no reaper at all, so it falls back to the default.

The emptyDir is unbounded by default: set an `ephemeral-storage` request/limit on the `workspace` container (three lines via the containers-merge-by-name rule, or in the SandboxTemplate) so a runaway download hits a clean limit instead of node-pressure eviction.

## The approval-prompt skip is declared, not inferred

Hermes' dangerous-command approval prompts stay **on** for this backend unless you set `terminal.kubernetes.trusted_sandbox: true`. That key is a statement by the operator, not a verdict Hermes reaches by reading the pod back: whether a session pod is contained is decided by SCC, Pod Security Admission, your admission policy and your NetworkPolicy, none of which Hermes can see. Set it only once the namespace is locked down.

## What this does NOT protect against

Stated plainly, because the upstream sample overclaimed here:

* The ValidatingAdmissionPolicy hooks on a label the pod creator chooses. Hermes *configuration* cannot strip it — the label is stamped onto the rendered template after the merge, so a `pod_template` that sets or deletes the key does not win — but a fully compromised agent talking to the API server directly could omit it. The containment boundary is the RBAC grant (and SCC on OpenShift), not the policy.
* The policy also denies secret-backed env (`envFrom.secretRef`, `valueFrom.secretKeyRef`), not only secret volumes — so injecting provider API keys into the session pod is denied wherever it is bound. Deliberate; see the file header if you need to relax it.
* `create pods` in a namespace remains a powerful verb. The policy narrows *shape*; it does not make the grant harmless. Run Hermes in a dedicated namespace with nothing else in it.
* Session pods share the cluster network unless `networkpolicy.yaml` is applied.
* **Exec requests are recorded in the API-server audit log.** The kubernetes client puts every `command` element of an exec into the request URL, and kube-apiserver records `requestURI` at Metadata level and above. The file-sync transport therefore streams its payload over the exec **stdin** channel and never through argv — but a command the *agent* runs still appears in the audit log verbatim, including anything it pipes in through the heredoc stdin mode. Do not treat the audit log as a place secrets cannot reach.
