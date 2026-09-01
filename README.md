# CodeRifts Kubernetes admission webhook

Validating admission webhook for Kubernetes. It **denies** Pod and Deployment CREATE/UPDATE unless a signed CodeRifts chain-receipt verifies **offline** against a **customer-pinned** keyring and the receipt’s scope matches the admitted object (`operation=deploy`, `target_id=k8s:{kind}:{namespace}/{name}`).

This is the same verify path as the GitHub Contract Gate: unwrap a DSSE envelope if present, then `verifyReceipt` on the compact token. Presence of a receipt or of a DSSE envelope is not a pass.

## Properties

- **Customer-hosted.** Runs in your cluster. You pin `KEYRING_PATH`. No CodeRifts-operated service is called at admit time.
- **Zero runtime dependencies.** `verify.js`, `arity.js`, and `to-dsse.js` are vendored from [receipt-verifier](https://github.com/coderifts/receipt-verifier). See `VENDOR.md`.
- **Fail-closed.** Named deny reasons: `receipt_missing`, `receipt_invalid`, `scope_mismatch`, `dsse_malformed`.

### What a refusal carries

A denied AdmissionReview keeps `status.code` and `status.message` exactly as before; anything
structured rides in `status.details.causes[]`, whose `message` is a serialised JSON string
(the Kubernetes API contract makes that field a string).

| cause `reason` | what it is |
|---|---|
| `CodeRiftsDenyRemedy` | **this gate's** refusal class — the grant is missing, invalid, or scoped elsewhere, and how to obtain one |
| `CodeRiftsNextStep` | **the decision's** own `next_agent_step`, read from the `decision_result` envelope after this webhook verified it |

`CodeRiftsNextStep` appears only when the receipt verified and the signed envelope carried a
step: the field lives inside `decision_result`, so `decision_body_hash` covers it and the
receipt signs it. A refusal reached before verification (missing receipt, missing envelope,
bad signature) never carries one — an unsigned step is not guidance.

This is the decision's remediation suggestion, not permission; branch on `execution_action`.

Install: [DEPLOY.md](./DEPLOY.md).

## Develop

```bash
node --test test/*.test.js
```

Node >= 20. `package.json` has no `dependencies`.
