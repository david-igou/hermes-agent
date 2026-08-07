# Kubernetes terminal backend — deployment manifests

Manifests for running Hermes' [`kubernetes` terminal backend](../tools/environments/kubernetes.py) on a real cluster. The backend runs each agent shell command in a **session pod** instead of in the agent's own container, isolating commands from the Hermes process, its ServiceAccount token, and the agent container's filesystem.

> **The session pod is an execution boundary, not a secrets boundary.** Registered credential files and skills ARE synced into it on session start (same as the Modal/Daytona backends), because skills need them. Only the ServiceAccount-token isolation is absolute.
>
> **It is also not a per-user boundary.** One Hermes process uses ONE session pod for every conversation it serves — browser, cron, and each chat-platform user alike (see [Session scope](#session-scope)). Anything synced into the workspace, credential files included, is readable by every session that process serves.

| File | What it is | Why |
|---|---|---|
| [`rbac.yaml`](./rbac.yaml) | A `Role`/`RoleBinding` for the agent SA, plus an optional no-perms session `ServiceAccount` | Give the agent SA only the verbs it needs, in its own namespace. |
| [`networkpolicy.yaml`](./networkpolicy.yaml) | Default-deny egress + optional internet allowance | Without it a session pod reaches the Kubernetes API and every ClusterIP Service in the cluster. |
| [`validatingadmissionpolicy.yaml`](./validatingadmissionpolicy.yaml) | Namespace-scoped `ValidatingAdmissionPolicy` | Constrains session-pod shape on vanilla Kubernetes. **Largely redundant on OpenShift** — read the header before applying. |
| [`session-pod-template.yaml`](./session-pod-template.yaml) | The pod you copy into `config.yaml` | `spec` is required and there is no default pod. This is a working object — apiVersion, kind, metadata and spec — annotated with which fields Hermes depends on and what breaks without them. |

## Configuration lives in config.yaml, not .env

Every setting for this backend is a `config.yaml` key under `terminal.kubernetes.*`. There are **no `TERMINAL_KUBERNETES_*` environment variables**, and none should be added: `.env` is for secrets, and this backend has no credential of its own — in-cluster auth is the projected ServiceAccount token the kubelet mounts, which Hermes never reads or stores.

Minimum config to select it:

```yaml
terminal:
  backend: kubernetes
  cwd: /workspace
  kubernetes:
    namespace: hermes-agents     # optional in-cluster; resolved from the SA otherwise
    apiVersion: v1               # `kind` selects the provisioner
    kind: Pod
    metadata: {}
    spec:                        # REQUIRED
      ...
```

`k8s/session-pod-template.yaml` is exactly this block: paste it under `terminal.kubernetes` and edit.

See `cli-config.yaml.example` (OPTION 7) for the full annotated block, or run `hermes setup` and pick *Kubernetes* — it writes a working object into your `config.yaml` for you.

## What Hermes needs from your spec

**The config block is shaped like the manifest it creates.** `apiVersion`, `kind`, `metadata` and `spec` mean exactly what they mean in any manifest, so a pod you already have is a copy-paste away and `kubectl explain pod.spec` documents most of this schema.

`spec` is **required** and is posted to the API server verbatim. There is no default base underneath it and no merge rule, so the pod you get is the pod you can read in your own `config.yaml`.

`kind` also **selects the provisioner**. There was a `provisioner: pod` key; it named the same thing twice, since writing `kind: Pod` already says which provisioner you want. Dispatch is on `(apiVersion, kind)`, so a second kind — a sandbox CRD, say — is a dispatch entry and no new config key. An unsupported pair fails in-process naming what *is* supported: nothing downstream could tell you which kinds your build implements, and posting it blindly returns a 404 on a REST path you never wrote.

`owned_selector` is **what marks an object as this backend's** — stamped into `metadata.labels` when absent, and matched before a 409 is treated as "resume". It was a hardcoded constant, so an operator relabelling their pods for chargeback fell out of the ownership check against their own objects. The ownerReference UID is still the actual proof; this is the cheap filter, and it is what `networkpolicy.yaml` and `validatingadmissionpolicy.yaml` select on.

> An earlier revision merged your `PodTemplateSpec` over a hidden default base using RFC 7386, with an exception that merged `spec.containers` element-wise on `name`. The rule was sound and it still meant predicting your own pod required knowing a base you could not see and simulating a merge in your head. Requiring the full spec costs more typing once and removes that class of surprise entirely.

**`metadata` is yours too**, with two exceptions. Write `annotations`, `labels`, `finalizers` or anything else under `metadata` and it is posted as you wrote it. Hermes only fills in what you left out:

| Field | Hermes' behaviour |
|---|---|
| `metadata.name` | **Always Hermes'.** Computed per process; it is how the pod is found again on the next command, so a template-supplied name would simply be lost. |
| `metadata.namespace` | **Always Hermes'.** From `terminal.kubernetes.namespace`, or the projected ServiceAccount namespace. |
| `metadata.ownerReferences` | Added **only when you set none** — the agent pod, so session pods are GC'd when it dies. Name an owner of your own and it is kept; you then own the GC story. `owner_reference: off` skips Hermes' entirely. |
| `metadata.labels` | `app.kubernetes.io/managed-by` and the instance label, added **only when absent**. Set them yourself and yours win — at the cost of falling out of `networkpolicy.yaml` and `validatingadmissionpolicy.yaml`, which select on `managed-by`. |
| everything else | Untouched. |

Everything else is yours, and these are the parts this backend actually depends on. Each fails a specific way, at a specific moment:

| Your `spec` must have | Or else |
|---|---|
| a container named `exec_container_name` (default `workspace`) | every command fails with `session pod has no container 'workspace'` |
| a command that keeps it running (`sleep infinity`) | the image entrypoint exits, and under `restartPolicy: Never` the pod reaches phase `Succeeded`: `session pod ... entered phase Succeeded` |
| a writable volume mounted at the exec container's `workingDir` | `builtin cd -- <workingDir>` fails on every command. `workingDir` is also where Hermes reads the session's cwd from, so omitting it starts sessions in `/workspace` no matter where you mounted things |
| a writable `/tmp` | `init_session()` cannot snapshot the environment, so cwd and env silently stop persisting between commands |
| `shareProcessNamespace: true` | `sleep` as PID 1 never reaps, so a backgrounded command's wrapper zombifies and `kill -0` reports it alive forever — background completion is never detected |
| `terminationGracePeriodSeconds: 1` | teardown waits the default 30s, on the interrupt path, because `sleep infinity` ignores SIGTERM |
| `automountServiceAccountToken: false` | the namespace default ServiceAccount's token is projected into the agent's shell. Nothing rejects it — a live sweep found this passes `fieldValidation=Strict` and a green `hermes doctor` |
| `activeDeadlineSeconds` | nothing bounds a session pod whose agent died without an ownerReference |

Nothing here is enforced in-process. A template missing any of it is a valid pod that the API server will happily create; you find out at the moment named above. What the pod is *allowed* to be is your cluster's decision (SCC, Pod Security Admission, `ValidatingAdmissionPolicy`, NetworkPolicy), and whether it is well-formed is the API server's — every create passes `fieldValidation=Strict`, so a typo comes back as a 400 naming the exact JSON path, and `hermes doctor` submits your rendered pod as a `dry_run=All` create so you see it before the first session.

## Apply

```bash
# 1. Edit rbac.yaml: replace <AGENT_NAMESPACE> and <AGENT_SA>.
kubectl apply -f rbac.yaml

# 2. Network isolation for session pods (edit <AGENT_NAMESPACE> first).
kubectl apply -f networkpolicy.yaml

# 3. Vanilla Kubernetes only — on OpenShift, SCC already covers most of this.
#    REQUIRES config.yaml to name the session SA (see the note below).
kubectl label namespace <AGENT_NAMESPACE> hermes-agent/session-pods=enforce
kubectl apply -f validatingadmissionpolicy.yaml
```

> **The session ServiceAccount is opt-in, not the default.** `session-pod-template.yaml` omits `serviceAccountName`, so a session pod runs as the namespace's `default` SA — that is what works on a cluster where none of this directory has been applied, and the pod holds no credentials either way because the template sets `automountServiceAccountToken: false`. `rbac.yaml` still ships `hermes-session-noperms` for operators who want the belt-and-braces version, and the ValidatingAdmissionPolicy in step 3 *requires* it. To use either, name it yourself:
>
> ```yaml
> terminal:
>   kubernetes:
>     spec:
>       serviceAccountName: hermes-session-noperms
> ```
>
> Applying the policy without that config key denies every session pod.

Then verify with `hermes doctor`, which runs a `SelfSubjectAccessReview` for each of `create`, `get` and `delete` on `pods`, for `get` **and** `create` on `pods/exec`, and for `list` on `pods` as a warning — RBAC is where in-cluster deployments actually fail.

> **`pods/exec` needs BOTH `get` and `create`.** It is tempting to grant only `get`, since the python client opens exec with `connect_get_namespaced_pod_exec` — a websocket-upgrading GET. Verified against Kubernetes 1.36: a Role with `get` alone is refused with `403 Forbidden`, and exec succeeds only once `create` is added. Grant both, or every command fails after an otherwise healthy startup.

Manual equivalent:

```bash
SA=system:serviceaccount:<AGENT_NAMESPACE>:<AGENT_SA>
kubectl auth can-i create pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods        --as=$SA -n <AGENT_NAMESPACE>   # yes  <- readiness, 409 ownership, ownerRef lookup
kubectl auth can-i delete pods        --as=$SA -n <AGENT_NAMESPACE>   # yes
kubectl auth can-i get    pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes  <- BOTH of these
kubectl auth can-i create pods/exec   --as=$SA -n <AGENT_NAMESPACE>   # yes  <- are required
kubectl auth can-i create deployments --as=$SA -n <AGENT_NAMESPACE>   # no
kubectl auth can-i create secrets     --as=$SA -n <AGENT_NAMESPACE>   # no
```

`hermes doctor` runs these same checks. The two `deployments`/`secrets` probes are yours, not doctor's — they are there to confirm the grant is narrow.

## Agent Deployment requirements

The Hermes pod itself needs:

* the ServiceAccount bound in `rbac.yaml`;
* the `kubernetes` python client — `pip install 'hermes-agent[kubernetes]'`. There is **no lazy install** for this backend: `check_terminal_requirements()` gates the whole terminal tool on the client being importable, so the tool stays disabled until it is installed.

**Downward API is optional.** Session pods carry an `ownerReference` to the agent pod, so they are garbage-collected if the agent crashes. Hermes resolves its own pod identity by looking itself up on the pod hostname, which needs no extra env. If you prefer to inject it explicitly, these two are honoured when present (they are runtime identity, not user configuration — do not put them in `.env.example`):

```yaml
env:
  - name: HERMES_POD_NAME
    valueFrom: {fieldRef: {fieldPath: metadata.name}}
  - name: HERMES_POD_UID
    valueFrom: {fieldRef: {fieldPath: metadata.uid}}
```

(The namespace is never taken from the environment: in-cluster the kubelet already projects it, and out-of-cluster `terminal.kubernetes.namespace` covers it.) When identity cannot be resolved, Hermes logs a WARNING — session pods then carry no `ownerReference` and are not garbage-collected until the `spec.activeDeadlineSeconds` backstop in your own spec fires — if you set one.

Set `terminal.kubernetes.owner_reference: off` to skip ownerReferences entirely (out-of-cluster dev, or a topology where the agent is not a pod). Session pods are then bounded only by the `spec.activeDeadlineSeconds` you wrote — note what that bound does: `spec.activeDeadlineSeconds` **stops** the pod (phase `Failed`) and leaves the object present for you or Hermes to delete. Hermes deletes a stopped pod when it next tries to use it; that is not Kubernetes GC. Nothing sweeps pods a crashed process left behind — with `owner_reference: off` and no deadline, they are yours to collect (`kubectl delete pod -l app.kubernetes.io/managed-by=hermes-agent`).

## OpenShift 4.21 notes

* **Session pods inherit the AGENT's SCC, not `restricted-v2`.** This is the most important thing on this page, and an earlier revision of it was wrong. SCC admission evaluates the SCCs available to the identity that *creates* the pod — always the agent's ServiceAccount — and that SA typically needs a `runAsUser: RunAsAny` SCC of its own, because the Hermes image starts as container-root under s6. Verified on a live 4.21 cluster: a session pod with `spec.securityContext.runAsUser: 0` was **admitted** (`openshift.io/scc: hermes-agent-root`) with `preflight_spec`, `fieldValidation=Strict` and `hermes doctor` all green.

  So do not assume `restricted-v2` confines your session pods. If you want them confined, that is a `ValidatingAdmissionPolicy` (this directory ships one) or a dedicated SCC bound to a session ServiceAccount you name in `spec.serviceAccountName` — not something you get for free.

* **Leave `runAsUser` unset when you DO want SCC to assign it.** Where the agent SA is confined to `restricted-v2`, that SCC uses `runAsUser: MustRunAsRange` from the namespace's `openshift.io/sa.scc.uid-range` annotation, and a hard-coded `1000` is then rejected (`must be in the ranges: [1000700000, 1000709999]`). `session-pod-template.yaml` leaves `runAsUser`/`fsGroup` unset for that case. Set `spec.securityContext.runAsUser` on vanilla Kubernetes, where nothing assigns one and `runAsNonRoot` needs a concrete UID to schedule a root-default image.
* **Set resource limits.** A namespace `ResourceQuota` covering `limits.cpu`/`limits.memory` rejects a requests-only pod. Set them on the `workspace` container in `terminal.kubernetes.spec` — and include `ephemeral-storage` there too, since the workspace emptyDir is otherwise unbounded.
* **Sandboxed containers (kata).** Set `terminal.kubernetes.spec.runtimeClassName: kata` and raise `ready_timeout_seconds` — kata cold starts routinely exceed the 120s default.
* **SCC RBAC is usually unnecessary — but read the first bullet.** The shipped template satisfies `restricted-v2`, which every authenticated SA already has, so nothing extra is needed to *schedule*. That is not the same as being *confined* by it: what a session pod may request is bounded by the agent SA's SCCs. The commented block at the bottom of `rbac.yaml` covers pinning a UID or binding a custom SCC.

## Pod shape

Your `spec` is the pod, in full. The table above lists what this backend depends on; everything else is between you and your cluster's admission stack. Start from [`session-pod-template.yaml`](./session-pod-template.yaml) — it is a working pod with each field explained, and `hermes setup` writes a copy of it into your `config.yaml`.

Two consequences of "verbatim" worth stating plainly, because both were free under the old merge:

* **Nothing is filled in.** Omit `securityContext` and your pod has none; omit `volumes` and the `volumeMounts` you wrote dangle (`spec.containers[0].volumeMounts[0].name: Not found: "workspace"` at create time). There is no layer underneath supplying the parts you skipped.
* **Nothing is protected either.** You can set `hostPID: true`, mount the host filesystem, or point `command` at something that exits immediately. Hermes will post it. What a session pod is *allowed* to be is decided by SCC, Pod Security Admission, the `ValidatingAdmissionPolicy` in this directory, NetworkPolicy and RBAC — the cluster administrator's tools, which are authoritative and which an in-process approximation would only duplicate or contradict.

### Validation is the cluster's job

Hermes validates **nothing about the pod's content** in-process, on purpose. It makes exactly two checks of its own, and both are questions the API server has no opinion on:

* **`resolve_provisioner_kind()`** — is there a provisioner for this `apiVersion`/`kind`? Nothing downstream could tell you which kinds your build implements, and posting an unknown one returns a 404 on a REST path you never wrote. Fails with the supported list.
* **`preflight_spec()`** — can Hermes *use* this pod? A pod whose containers are all named `sidecar` is perfectly legal Kubernetes and useless as an exec target. It errors on a missing exec container and on `readOnlyRootFilesystem` without a `/tmp` mount, and warns on an unset `workingDir`, a missing `shareProcessNamespace`, a projected ServiceAccount token, an unbounded pod, and an `owned_selector` that has fallen out of the shipped policies. A live sweep found five realistic omissions that passed `fieldValidation=Strict` **and** produced a green `hermes doctor` before this existed.

Everything else is delegated:

* **Well-formedness** — every create this backend issues passes `fieldValidation=Strict`, so an unknown, misspelled or duplicated field is a `400` naming the exact JSON path. (The python client discards the API server's `Warning: 299 - unknown field` header, which makes the default `Warn` behaviour indistinguishable from success, so Strict is not optional here.) `hermes doctor` submits your rendered pod as a `dry_run=All` create for the same reason: you see the server's verdict at config time.
* **What the pod may be** — SCC, Pod Security Admission, the `ValidatingAdmissionPolicy` in this directory, NetworkPolicy and RBAC. These are the cluster administrator's tools, they are authoritative, and an in-process approximation of them would be redundant where it agreed and wrong where it did not.

## Vanilla Kubernetes: set a UID

The shipped template sets `runAsNonRoot: true` and deliberately leaves `runAsUser` unset, because OpenShift's `restricted-v2` SCC assigns one from the namespace range. On a cluster with no such admission controller nothing assigns it, so a root-default image fails to start with `container has runAsNonRoot and image will run as root`. Set one:

```yaml
spec:
  securityContext:
    runAsUser: 1000
```

No `fsGroup` is needed: the kubelet creates `emptyDir` directories world-writable, so any non-root UID can write the workspace. Add one only if you mount something that needs group ownership (a PVC from a CSI driver that honours it).

This is the single most likely reason a first session fails outside OpenShift. `hermes doctor` dry-runs the rendered pod, but admission-time UID assignment is not something a dry-run reveals.

## Storage

Session workspaces are **stateless by default**: the workspace is an `emptyDir` that dies with the session pod, and there is deliberately no persistence *config key* — storage is plain `PodSpec`, so it belongs in `spec` like every other pod concern. Three shapes, all supported today:

| You want | Write this in `spec.volumes` |
|---|---|
| Ephemeral | the shipped template's `emptyDir` |
| Dynamically provisioned, per session | `ephemeral.volumeClaimTemplate` — Kubernetes creates a PVC named `<pod>-workspace`, owns it, and deletes it with the pod |
| Pre-provisioned / shared | `persistentVolumeClaim: {claimName: …}` — you own the claim's lifecycle; Hermes never creates, adopts or deletes it |

```yaml
spec:
  volumes:
    - name: workspace                 # instead of the emptyDir
      ephemeral:
        volumeClaimTemplate:
          spec:
            accessModes: [ReadWriteOnce]
            storageClassName: fast-nvme
            resources: {requests: {storage: 10Gi}}
    - name: tmp                       # still needed
      emptyDir: {}
```

The dynamic form also bounds the workspace, which an `emptyDir` does not: without it, size is limited only by node ephemeral storage. No RBAC change is needed — the PVC is created by the controller manager on the pod's behalf, so the agent ServiceAccount still needs nothing on `persistentvolumeclaims`. (Cluster admins should know that this means anyone who can create pods can indirectly create PVCs.)

Two cautions for a **shared** claim. `ReadWriteOnce` is node-scoped, not pod-scoped: co-scheduled pods will both mount it and race on the same files, while pods on different nodes leave the second stuck `FailedAttachVolume` — use `ReadWriteMany` if you mean sharing. And the credential sync follows the workspace (`.hermes` lives under the session cwd), so sharing `/workspace` across sessions shares credential files at rest. Prefer mounting the shared volume at a *second* path and leaving the workspace per-session.

### Lifecycle

There is nothing for a reaper to reap in the default shape (no PVCs, no `persistentvolumeclaims` RBAC). A dead pod (deadline, eviction, OOMKill) is deleted and re-provisioned empty on the next command, Hermes re-syncs skills and credential files into it automatically, and the first tool result after the reset says so to the model.

Two lifetime knobs bound every session pod, and both are worth setting deliberately:

* **`terminal.lifetime_seconds` (default 300)** — the shared idle reaper destroys the environment after this much tool-call inactivity. This backend has no persist exemption, so 300 s of idleness costs the workspace; raise it (e.g. to match your `spec.activeDeadlineSeconds`) if you want session-length workspaces.
* **`spec.activeDeadlineSeconds`** — the hard per-session ceiling. Not a config key: it is PodSpec, so it lives in your `spec` (the shipped template sets `14400`). It **stops** the pod but does not delete it, and omitting it leaves a `sleep infinity` pod unbounded whenever no ownerReference collects it.

The emptyDir is unbounded by default: set an `ephemeral-storage` request/limit on the `workspace` container in your `spec` so a runaway download hits a clean limit instead of node-pressure eviction.

## Session scope

**A "session pod" is one pod per Hermes PROCESS, not one per conversation.** The name is a
historical shorthand and it misleads; this is what actually happens.

Every caller's `task_id` is passed through `_resolve_container_task_id`, which deliberately
collapses it to the single key `"default"`. Measured on a live cluster, four callers in one
gateway process:

| Caller | session id | pod |
|---|---|---|
| Browser/dashboard | `sess-web-a1b2c3` | `hermes-ws-85198361-default` |
| Cron (nightly) | `sess-cron-nightly-0300` | `hermes-ws-85198361-default` |
| Slack user A | `sess-slack-U01ALICE` | `hermes-ws-85198361-default` |
| Slack user B | `sess-slack-U02BOB` | `hermes-ws-85198361-default` |

The same run confirmed the consequences: user B read a file user A had just written, a cron
job saw it too, and the synced provider credential files (`~/.codex/auth.json` and friends) were
readable from every session.

This is deliberate for subagents — `delegate_task` children share the parent's container so
there is "one bash, one /workspace, one set of installed packages" — and it is inherited
behaviour shared with the docker backend, not something this backend introduces. But note what
it means operationally:

* **The filesystem is shared.** A cron writing `/workspace/out.json` and a human editing the
  same path are the same file. So is anything installed — one session's `pip install` changes
  the interpreter every other session runs.
* **Shell environment is shared, `cd` is not.** An `export` in one session is visible to the
  next command of every other session (they share one session snapshot), but each session keeps
  its own cwd record (`get_session_cwd`), so a `cd` does *not* move anyone else.
* **The idle reaper is shared.** `terminal.lifetime_seconds` counts inactivity across ALL of
  them; when it fires everyone's workspace is destroyed at once. So is an
  `activeDeadlineSeconds` expiry, an eviction, or an OOM caused by any one of them.
* **Credentials are shared.** Whatever is synced in is readable by every session that process
  serves. If a gateway is exposed to several people, a shell obtained by any one of them reads
  the tokens of the account the agent runs as.

**A separate pod is created only when** a distinct Hermes process serves the session (the
discriminator mixes in the PID), or an RL/benchmark harness registers an isolation override via
`register_task_env_overrides`, which makes the task id survive the collapse.

**If you need per-user isolation, do not rely on the session pod for it** — run a Hermes
process per trust domain, or keep the gateway single-tenant.

## The approval-prompt skip is declared, not inferred

Hermes' dangerous-command approval prompts are **skipped** for this backend, exactly as they are for docker, singularity, modal, daytona and vercel_sandbox: commands run in a session pod, not on the host, so the layer that exists to protect the host has nothing to protect.

There was briefly a `trusted_sandbox` key that kept the prompts on until an operator opted out. It made this the only config-gated approval bypass in the codebase while every peer backend bypassed unconditionally, which amounted to asking operators to opt in to the default behaviour of everything else. What a session pod may actually DO is decided by SCC, Pod Security Admission, your `ValidatingAdmissionPolicy` and your NetworkPolicy — none of which Hermes can see, and all of which are the real control.

## What this does NOT protect against

Stated plainly, because the upstream sample overclaimed here:

* The ValidatingAdmissionPolicy hooks on a label the pod creator chooses, and `owned_selector` makes that label configuration — so a config that changes it falls out of the policy, and a fully compromised agent talking to the API server directly could omit it entirely. The containment boundary is the RBAC grant (and SCC on OpenShift), not the policy.
* The policy also denies secret-backed env (`envFrom.secretRef`, `valueFrom.secretKeyRef`), not only secret volumes — so injecting provider API keys into the session pod is denied wherever it is bound. Deliberate; see the file header if you need to relax it.
* `create pods` in a namespace remains a powerful verb. The policy narrows *shape*; it does not make the grant harmless. Run Hermes in a dedicated namespace with nothing else in it.
* Session pods share the cluster network unless `networkpolicy.yaml` is applied.
* **Sessions are not isolated from each other.** The pod is per Hermes *process*, not per conversation ([Session scope](#session-scope)), so everything a session writes to `/workspace` — and every credential file synced in — is readable by every other session that process serves. Nothing in these manifests changes that; it is a property of the shared terminal environment.
* **Exec requests are recorded in the API-server audit log.** The kubernetes client puts every `command` element of an exec into the request URL, and kube-apiserver records `requestURI` at Metadata level and above. The file-sync transport therefore streams its payload over the exec **stdin** channel and never through argv — but a command the *agent* runs still appears in the audit log verbatim, including anything it pipes in through the heredoc stdin mode. Do not treat the audit log as a place secrets cannot reach.
