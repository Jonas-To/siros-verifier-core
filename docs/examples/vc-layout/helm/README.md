# The initContainer shape (helm, or any k8s deployment)

The deployment's existing vc `config.yaml` stays where it is — a
ConfigMap — and the translation runs at pod start: an initContainer
(the same image, whose `vc-layout` binary installs alongside the
service) writes the proxy.toml into an emptyDir the main container
boots from. The vc config stays the live source of truth; the runtime
never learns about it.

```yaml
# The deployment's EXISTING vc verifier config — unchanged.
apiVersion: v1
kind: ConfigMap
metadata:
  name: vc-verifier-config
data:
  config.yaml: |
    common: { ... }
    verifier: { ... }
---
# The signing keys, at the SAME paths the vc layout names — the
# translated config's paths carry over verbatim.
apiVersion: v1
kind: Secret
metadata:
  name: siros-verifier-pki
stringData:
  signing_ec_private.pem: |
    -----BEGIN PRIVATE KEY-----
    ...
  signing_ec_chain.pem: |
    -----BEGIN CERTIFICATE-----
    ...
---
# The state secret through the env channel.
apiVersion: v1
kind: Secret
metadata:
  name: siros-verifier-state
stringData:
  state-key: "..."
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siros-verifier
spec:
  template:
    spec:
      # The translation step: one container's work, before the service.
      initContainers:
        - name: translate-vc-layout
          image: ghcr.io/sirosfoundation/siros-verifier-core:v0.1.9
          command: ["/usr/local/bin/vc-layout"]
          args:
            - /vc/config.yaml
            - -o
            - /etc/siros-verifier/proxy.toml
            # The policy edges the report demands stated explicitly:
            - --allow-insecure-pdp          # the vc layouts' private-network PDP posture
            - --subject-pointer
            - /personal_administrative_number
            - --subject-scope
            - pid_eudi                      # the PAN rides the PID query, not the diploma's
          volumeMounts:
            - { name: vc-config, mountPath: /vc }
            - { name: config, mountPath: /etc/siros-verifier }
      containers:
        - name: verifier
          image: ghcr.io/sirosfoundation/siros-verifier-core:v0.1.9
          args: ["/etc/siros-verifier/proxy.toml"]
          ports: [{ containerPort: 9001 }]
          env:
            - name: SIROS_VERIFIER_STATE_KEY
              valueFrom:
                secretKeyRef: { name: siros-verifier-state, key: state-key }
          volumeMounts:
            - { name: config, mountPath: /etc/siros-verifier }
            - { name: pki, mountPath: /pki, readOnly: true }
      volumes:
        - name: vc-config
          configMap: { name: vc-verifier-config }
        - name: config
          emptyDir: {}
        - name: pki
          secret: { secretName: siros-verifier-pki }
```

The report prints to the initContainer's logs — `kubectl logs
<pod> -c translate-vc-layout` is the migration checklist, per pod start.

**In a chart:** wrap the args as values (`vcLayout.pdp.insecure:
true`, `vcLayout.subjectPointer`, `vcLayout.subjectScope`) and the
ConfigMap reference as a value — the translation step is one
initContainer block; everything else is the chart's existing
deployment template.

**The one wire-visible delta** the report always states: the OIDC OP
moves from the verifier's root to `<base_url>/OIDC` — the RPs'
discovery and token URLs must follow.
