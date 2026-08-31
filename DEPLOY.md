# Deploy

The webhook runs **in your cluster**. You pin the keyring. Admission never calls CodeRifts over the network.

## 1. Namespace, TLS, keyring

```bash
kubectl apply -f deploy/validating-webhook-configuration.yaml
# that file also creates namespace coderifts-system (apply the Namespace first if you split it)

# TLS for the webhook Service (example: a self-signed cert whose CA you put in caBundle)
# The API server must trust this cert.

kubectl -n coderifts-system create secret tls coderifts-admission-tls \
  --cert=tls.crt --key=tls.key

# Customer-pinned keyring: { "keys": [{ "kid", "public_key_pem", "status", ... }] }
# Same shape as .well-known/coderifts-keys.json. Local Secret only.
kubectl -n coderifts-system create secret generic coderifts-admission-keyring \
  --from-file=keyring.json=./your-pinned-keys.json
```

Set `caBundle` in `deploy/validating-webhook-configuration.yaml` to the base64-encoded CA PEM (the CA that signed `tls.crt`).

## 2. Workload + webhook

Build and load the image, then:

```bash
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/validating-webhook-configuration.yaml
```

`failurePolicy: Fail` means if the webhook is unreachable, **CREATE/UPDATE of Pods and Deployments is denied**. That is the fail-closed setting.

## 3. Annotate objects

On each Pod or Deployment you admit:

| Annotation | Value |
|------------|--------|
| `coderifts.com/receipt` | Compact chain-receipt token, **or** a DSSE/in-toto envelope (JSON) wrapping that token |
| `coderifts.com/envelope` | `decision_result` JSON the receipt is bound to (v4 body hash + scope) |

The envelope must include:

- `preflight_mode`: `authorize`
- `operation`: `deploy` (or `EXPECTED_OPERATION`)
- `target_id`: `k8s:{kind}:{namespace}/{name}` (example: `k8s:deployment:prod/orders`)
- `execution_action`: `CONTINUE` or `CONTINUE_WITH_MONITORING`

A receipt in the annotation is not sufficient. The signature must verify over the compact bytes against the **pinned** keyring, and `operation` / `target_id` must match this object. A DSSE envelope is unwrapped, then the compact token is verified; the envelope is not itself a pass.

DELETE is not gated.

## Deny reasons

`receipt_missing` · `receipt_invalid` · `scope_mismatch` · `dsse_malformed`
