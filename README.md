# CodeRifts Kubernetes admission webhook

Validating admission webhook for Kubernetes. It **denies** Pod and Deployment CREATE/UPDATE unless a signed CodeRifts chain-receipt verifies **offline** against a **customer-pinned** keyring and the receipt’s scope matches the admitted object (`operation=deploy`, `target_id=k8s:{kind}:{namespace}/{name}`).

This is the same verify path as the GitHub Contract Gate: unwrap a DSSE envelope if present, then `verifyReceipt` on the compact token. Presence of a receipt or of a DSSE envelope is not a pass.

## Properties

- **Customer-hosted.** Runs in your cluster. You pin `KEYRING_PATH`. No CodeRifts-operated service is called at admit time.
- **Zero runtime dependencies.** `verify.js`, `arity.js`, and `to-dsse.js` are vendored from [receipt-verifier](https://github.com/coderifts/receipt-verifier). See `VENDOR.md`.
- **Fail-closed.** Named deny reasons: `receipt_missing`, `receipt_invalid`, `scope_mismatch`, `dsse_malformed`.

Install: [DEPLOY.md](./DEPLOY.md).

## Develop

```bash
node --test test/*.test.js
```

Node >= 20. `package.json` has no `dependencies`.
