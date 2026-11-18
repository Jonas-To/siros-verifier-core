# Pluggable configuration architecture

## Design

The verifier's boot resolves each configuration category through a
**provider trait**, with a default implementation that preserves the
current file/env behavior. A deployment selects alternative providers
without forking the boot code.

### Key principle: env vars are the platform-native secret channel

Following SUNET/vc #935: a container platform hands a process a
credential as an **environment variable backed by a Secret** — not as a
sidecar-rendered secrets file. The config names the source of each
secret, the provider resolves it at boot, and the platform (a k8s
Secret's `secretKeyRef`, a Fly secret, a compose `environment:` entry)
owns the Secret itself.

Per-field explicit references, not derived names — derived names collide
on opaque identifiers. Two sources named for one value are refused at
boot.

### The traits

```rust
/// Where one secret value comes from.
pub enum SecretSource {
    Env(String),   // a k8s secretKeyRef, a Fly secret, compose environment
    File(String),  // a Secret volume mount (external-secrets.io, Vault
                   // Agent and the CSI driver all materialize files)
}

/// Resolves one secret value at boot. Fail-fast: a missing or empty
/// value is an error naming the entry and the source.
pub trait SecretProvider: Send + Sync {
    fn resolve(&self, source: &SecretSource) -> Result<String>;
}

/// Produces an OIDC frontend's client roster. The default reads the
/// config block with `_env` credential overrides; a database or an
/// external registration API are further implementations.
pub trait ClientRegistrationProvider: Send + Sync {
    fn clients(&self) -> Result<Vec<serde_json::Value>>;
}
```

### The providers

| Provider | Channel | The deployment model it serves |
|---|---|---|
| `EnvVarSecretProvider` | env vars | k8s `secretKeyRef`, Fly, compose |
| `FileSecretProvider` | files under a base dir | k8s Secret volume mounts, external-secrets.io |
| `PlatformSecretProvider` | both | a config mixing the two reference styles |
| `ConfigClientRegistration` | config block + a secret provider | the default client roster |

Anything a deployment platform can hand a process materializes into an
env var or a file, so the two channels cover the common k8s models; a
future provider (a direct k8s API watch, a Vault client) implements the
same trait without touching the boot.

### Per-field explicit references

Each secret-bearing field takes at most one of an inline value, an
`_env` name, and a `_file` name:

```toml
[backend.config]
pdp_bearer_token = "inline"                    # or:
pdp_bearer_token_env = "VC_PDP_TOKEN"          # or:
pdp_bearer_token_file = "secrets/pdp-token"    # relative to the config file
```

Resolution replaces the reference with the value at boot; a later
reader cannot mistake a reference for a value. The same pattern applies
to the MongoDB URI (`storage.uri` / `uri_env` / `uri_file`) — a
connection string carries credentials.

For the OIDC frontend's client roster (an array of tables), the per-entry
shape:

```toml
[[frontend.config.clients]]
client_id = "rp.example"
client_secret_env = "VC_RP_EXAMPLE_SECRET"    # or client_secret = "..."
redirect_uris = ["https://rp.example.org/callback"]
```

The `_env` field is resolved and stripped before the strict downstream
client parser runs — a misspelled field still fails the boot, and the
downstream client model never learns about `_env` fields.

### Client registration

`ClientRegistrationProvider` is the general trait for client
configuration. The default implementation is config+secret management
(the `[[frontend.config.clients]]` block with `_env` overrides); the
trait serves the same surface for:

- **A database backend** — clients in the flow-storage database,
  managed through an admin API
- **An external registration API** — RFC 7591 against an authorization
  server's registration endpoint

Real dynamic client registration is a property of the backend
implementation, not the trait: a database roster may accept runtime
registration, the config roster cannot, and the trait's shape is
identical for both.

### Secret rotation

The request-signing key rotates through the previous-key pattern (the
same shape as `previous_state_encryption_keys`):

```toml
request_signing_key_path = "keys/new.key"             # signs new flows
request_certificate_chain_path = "keys/new.chain"
previous_request_signing_key_path = "keys/old.key"          # both together
previous_request_certificate_chain_path = "keys/old.chain"  # or neither
```

An in-flight flow is re-signed (`request_uri_method = "post"`) by the
pair it was created under — matched by its stored request object's
`x5c` leaf — so the re-issued request carries the chain its `client_id`
hashes from. New flows always use the current pair. The retention
window is bounded by `request_ttl_secs`.

## The deployment models

### Docker compose / local

The config file mounted as a file, secrets as inline values or env vars
from an `.env` file:

```yaml
services:
  verifier:
    environment:
      VC_PDP_TOKEN: "${VC_PDP_TOKEN}"
      VC_RP_EXAMPLE_SECRET: "${VC_RP_EXAMPLE_SECRET}"
```

### Kubernetes (helm)

The siros-id-stack shape, with the vc-stack secrets.yaml sidecar model
replaced by the env-var channel:

```yaml
# ConfigMap verifier-main: the proxy.toml, one key per concern — the
# frontend and backend blocks compose through tunnelbana's `include`
apiVersion: v1
kind: ConfigMap
metadata:
  name: verifier-main
data:
  proxy.toml: |
    [[backend]]
    type = "openid4vp"
    name = "VP"
      [backend.config]
      pdp_bearer_token_env = "VC_PDP_TOKEN"
      request_signing_key_path = "/pki/wrpac.key"
      request_certificate_chain_path = "/pki/wrpac.chain"
---
# The Secrets the config references
apiVersion: v1
kind: Secret
metadata:
  name: verifier-secrets
stringData:
  pdp-token: "..."
---
# The deployment wires them
env:
  - name: VC_PDP_TOKEN
    valueFrom:
      secretKeyRef: { name: verifier-secrets, key: pdp-token }
volumeMounts:
  - name: pki
    mountPath: /pki        # the key PEMs — a Secret volume mount
```

Key PEMs are files (volume mounts); small credentials are env vars; a
config mixing both reference styles resolves through the platform
provider. `external-secrets.io`, the Vault Agent and the CSI driver all
materialize into one of the two channels and need no special support.

### Fly.io

The current WRPAC drill model: `--file-local` mounts for the config and
chains, `fly secrets set VC_PDP_TOKEN=...` for the credentials. Secret
rotation on Fly means `fly secrets set` (a new value) plus a machine
restart — the boot resolves fresh values.

## Implementation map

| Piece | Where |
|---|---|
| The traits + the three secret providers | `src/config/mod.rs` (`siros_verifier_core::config`) |
| The default client roster (`_env` resolution) | `src/config/mod.rs` (`ConfigClientRegistration`) |
| The deployment fields (`_env`/`_file`, the previous pair) | `service/src/config.rs` |
| Boot resolution (secrets, the previous pair, the roster) | `service/src/main.rs` |
| Generation-matched re-signing | `tunnelbana-plugin/src/lib.rs` (`with_previous_request_signers`) |
| The user-facing reference | `docs/CONFIGURATION.md` — "Secrets and rotation" |

The fail-fast rules are unit-tested at each layer: both sources for one
value, a missing source, an empty source, a duplicate `client_id`, a
previous chain that duplicates a leaf, and the generation matching for
in-flight flows.
