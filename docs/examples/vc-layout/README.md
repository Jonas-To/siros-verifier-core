# Migrating a vc-stack verifier deployment

The `vc-layout` tool translates the vc-stack verifier's `config.yaml`
into this service's proxy.toml. It is a **migration aid**: run it once
against the deployment's existing configuration, read the report (the
migration checklist — what maps, what this service does not support,
what the operator must decide), and take the emitted proxy.toml as the
starting point for the deployment's own config management.

```sh
# --entrypoint overrides the image's service entrypoint (without it the
# tool's path would become the service's config filename); --user gives
# the container write access to the bind-mounted working directory.
docker run --rm \
  --entrypoint /usr/local/bin/vc-layout \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" ghcr.io/sirosfoundation/siros-verifier-core \
  /work/config.yaml -o /work/proxy.toml \
  --allow-insecure-pdp \
  --subject-pointer /personal_administrative_number \
  --subject-scope pid_eudi
```

The report goes to stderr; the proxy.toml to `-o` (owner-only mode) or
stdout.

From there, three integration shapes cover the common config management
solutions:

| Shape | Where it fits | See |
|---|---|---|
| **Run once, commit the output** | Kustomize, plain manifests, any git-ops flow — the emitted proxy.toml is a reviewable artifact | [`kustomize/`](kustomize/) |
| **Translate at pod start** | Helm charts and environments where the vc config.yaml is the live source of truth — an initContainer runs the tool, the main container boots from the output | [`helm/`](helm/) |
| **Rewrite natively** | The end state for most deployments — the report tells you what the native helm values must state; the vc config is retired | the notes in the report |

In every shape the runtime is the same: the service boots from a
proxy.toml, the secrets ride env vars (`SIROS_VERIFIER_STATE_KEY`, and
the mongo URI's own credentials inside the translated config), and the
vc layout's file paths carry over verbatim — the same volume mounts for
the signing keys and chains serve the translated deployment.

**As a skill**: an agent-executable runbook for the whole migration
(running the tool, reading the three-bucket report, resolving the
refusals, moving the credentials, choosing the integration shape,
verifying the boot) lives at
[`.github/skills/vc-layout-migration/SKILL.md`](../../.github/skills/vc-layout-migration/SKILL.md).
