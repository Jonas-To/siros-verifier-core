---
name: vc-layout-migration
description: 'Migrate a vc-stack verifier deployment''s config.yaml to siros-verifier-core. Use when: a deployment runs the SUNET/vc verifier and must move to siros-verifier-core, someone asks to translate/convert/adopt a vc config.yaml, a k8s or helm deployment needs the vc verifier replaced, or the vc-layout tool''s report needs interpreting. Runs the vc-layout tool, reads the three-bucket report, resolves the refusals, and produces the deployable proxy.toml plus the migration checklist.'
argument-hint: 'Path to the vc verifier config.yaml (e.g. "fixtures/rendered/fly-gdc/vc-verifier.yaml")'
---

# vc-layout migration

Migrate a vc-stack verifier (SUNET/vc) deployment to siros-verifier-core by
translating its `config.yaml` — the `common:` + `verifier:` YAML layout — into
this service's proxy.toml. The tool is a **migration aid**, run once: the
report it prints is the migration checklist, and the emitted proxy.toml is
the starting point the deployment's own config management then adopts.

## When to use

- A deployment runs the vc verifier and is moving to siros-verifier-core
- "Translate/convert this vc config.yaml"
- A helm chart or kustomize overlay needs the vc verifier replaced
- Interpreting a vc-layout report (mapped / known-unsupported / unknown)

## The tool

The `vc-layout` binary ships in the siros-verifier-core image alongside the
service. On a workstation, use the release image:

```sh
docker run --rm \
  --entrypoint /usr/local/bin/vc-layout \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" ghcr.io/sirosfoundation/siros-verifier-core:<tag> \
  /work/config.yaml -o /work/proxy.toml
```

On the source checkout: `cargo run -p siros-verifier-service --bin vc-layout --`.

## The procedure

### 1. Run the translation

```sh
vc-layout <config.yaml> -o <proxy.toml> \
  --allow-insecure-pdp \
  --subject-pointer /personal_administrative_number \
  --subject-scope pid_eudi
```

- The report goes to **stderr** — capture it; it is a deliverable.
- The proxy.toml goes to `-o` (owner-only mode) or stdout.
- The source's file paths (signing keys, chains, circuit artifacts) carry
  over **verbatim**: the same volume mounts serve the translated deployment.
  Relative paths absolutize against the source yaml's own directory.

### 2. Read the report before anything else

Every source member lands in exactly one of three buckets:

| Bucket | Meaning | Action |
|---|---|---|
| **mapped** | Translated to its equivalent | None — verify the important ones below |
| **known-unsupported** | A recognized vc capability this service does not have (ldp_vc, OTLP, the sidecar secrets file, TS12, pairwise subjects, the Vega `mso_mdoc_zk` profile, dynamic registration…) | Confirm the deployment can run without it; surface it to the operator |
| **unknown** | A typo, or a NEW vc-stack feature that would silently vanish | **The tool refuses.** Never paper over it: either fix the typo, or decide and extend the adapter (see `service/src/vc_layout.rs`) — never delete the member |

The **notes** section is the checklist of decisions the deployment's
templating must state: the OP moving from the verifier root to
`<base_url>/OIDC` (the RPs' discovery URLs must follow), the go-trust role
name, the flow store's database/collection names, the bind
(`TUNNELBANA_BIND`).

### 3. The two policy edges — flags, never silent defaults

- **`--allow-insecure-pdp`**: the vc layouts commonly speak plain HTTP to a
  private-network PDP (fly's 6PN among them). The tool refuses the URL
  without this opt-in; with it the emitted config states
  `allow_insecure_http = true` as loudly as a hand-written one.
- **`--subject-pointer <claim>`**: required when the layout enables the OP
  (`verifier.outbound.oidc_provider`). A holder's *name* is not a unique
  identifier — two holders sharing a family name would share a subject —
  so the tool never defaults the OP's subject. Use a genuinely unique
  claim (a PAN, a national identifier).
- **`--subject-scope <credential>`**: required when the layout supports
  more than one credential. The claim must ride a query the credential can
  FULFILL — a PAN belongs on a PID query, not a diploma's (an unfulfillable
  claim breaks every OP login). The named scope's query is moved to the
  FRONT of the emitted fallback (the runtime takes the first credential
  carrying the claim).

### 4. Move the credentials out of the artifact

The vc config commonly embeds credentials (the mongo URI carries its
password inline). Before committing or templating the emitted proxy.toml:

- `storage.uri` → `storage.uri_env = "VC_MONGODB_URI"` wired from a
  Kubernetes Secret (`secretKeyRef`) or the platform's env channel
- any client secret → `client_secret_env` (same channel; the runtime
  resolves both through its secret provider)
- the signing private keys never enter the committed base — volume-mount
  them at the same paths the config names

The emitted file is mode 0600, but no mode protects a secret in Git.

### 5. Choose the integration shape

See `docs/examples/vc-layout/` in the siros-verifier-core repo for the
worked examples:

- **helm / initContainer**: the vc config.yaml stays the live source of
  truth in a ConfigMap; an initContainer (the same image) runs the tool at
  pod start and writes the proxy.toml into an emptyDir the service reads.
  Set `fsGroup` on the pod (a fresh emptyDir is root-owned; the image runs
  as UID 10001) and keep both containers on the same UID (the output is
  0600).
- **kustomize / git-ops**: run the tool once, commit the proxy.toml as a
  reviewable artifact (`configMapGenerator`), credentials moved out per
  step 4.
- **rewrite natively**: the end state for most deployments — the report
  tells you what the native helm values must state; the vc config is
  retired.

### 6. Verify

Boot the service from the emitted config before declaring success:

```sh
SIROS_VERIFIER_STATE_KEY=<32+ bytes> TUNNELBANA_BIND=127.0.0.1:9001 \
  siros-verifier-service <proxy.toml>   # then GET /health
```

A translation the service refuses to boot is not done — read the refusal,
it names the member and the reason.

## Pitfalls

- **Never ignore an `unknown` refusal** — it is the tool working as
  designed: a new vc feature would otherwise silently vanish from the
  translated deployment.
- **The OP's issuer URL moves** (`<base_url>/OIDC`) — the relying parties'
  discovery and token URLs must follow. This is the one wire-visible delta.
- **`--subject-scope` must resolve to an emitted query** — a scope not
  among `supported_credentials`, or dropped for its format, refuses.
- **The artifact is 0600, owner-only from creation** — a stale temp from an
  interrupted run never blocks a retry (the tool retries with fresh
  names), but the output can still carry credentials: step 4 stands.
- **Only the first registry mirror migrates**; fallback mirrors and custom
  mirror timeouts do not (the report says so).
