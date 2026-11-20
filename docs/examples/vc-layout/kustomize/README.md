# The run-once shape (kustomize, git-ops, plain manifests)

The translation is a reviewable artifact: run the tool once, commit the
output, and the deployment consumes it like any hand-written config.
The vc `config.yaml` is then retired — the emitted proxy.toml IS the
config, and the report (checked in beside it) documents every decision
it embodies.

**Before committing: move the credentials out of the artifact.** The
vc config commonly embeds them (the mongo URI carries its password
inline) and mode 0600 does not protect a secret in Git. Replace the
inline values with this service's `_env` references before staging —
the emitted `storage.uri` becomes `storage.uri_env = "VC_MONGODB_URI"`
wired from a Kubernetes Secret, and any client secret becomes
`client_secret_env` — then commit the reference-bearing config and keep
the signing private keys out of the committed base entirely (the
secretGenerator below mounts them at runtime).

```sh
# Once, at migration time:
vc-layout config.yaml -o base/siros-verifier/proxy.toml \
  --allow-insecure-pdp \
  --subject-pointer /personal_administrative_number \
  --subject-scope pid_eudi \
  2> base/siros-verifier/migration-report.txt
git add base/siros-verifier
```

```yaml
# base/siros-verifier/kustomization.yaml
resources:
  - deployment.yaml
configMapGenerator:
  - name: siros-verifier-config
    files:
      - proxy.toml
secretGenerator:
  # The signing keys at the SAME paths the translated config names.
  - name: siros-verifier-pki
    files:
      - signing_ec_private.pem
      - signing_ec_chain.pem
  - name: siros-verifier-state
    literals:
      - state-key=replace-me
```

```yaml
# base/siros-verifier/deployment.yaml (excerpt)
spec:
  template:
    spec:
      containers:
        - name: verifier
          image: ghcr.io/sirosfoundation/siros-verifier-core:v0.1.9
          args: ["/etc/siros-verifier/proxy.toml"]
          env:
            - name: SIROS_VERIFIER_STATE_KEY
              valueFrom:
                secretKeyRef: { name: siros-verifier-state, key: state-key }
          volumeMounts:
            - { name: config, mountPath: /etc/siros-verifier }
            - { name: pki, mountPath: /pki, readOnly: true }
      volumes:
        - name: config
          configMap: { name: siros-verifier-config }
        - name: pki
          secret: { secretName: siros-verifier-pki }
```

Overlays patch it like any other config: `patches` for the image, the
replicas, the env — the translated proxy.toml itself is diffed and
reviewed in git like the rest of the base (the credentials having been
moved to Secret-wired `_env` references, the diff carries none).

**Regenerating:** a vc config change means re-running the tool and
reviewing the diff — including any NEW member the tool refuses (an
upstream vc feature) and any newly-reported known-unsupported entry.
The refusal is the safety net: nothing migrates silently.
