# Vendored verify core

This webhook copies the public verifier. It does not `npm install` a CodeRifts-operated package and it does not fetch keys at verify time.

| File | Source | Revision |
|------|--------|----------|
| `src/verify.js` | `receipt-verifier/verify.js` | `ccc53f9a592aaa7f6072d5c80d724f36de30a8ab` |
| `src/arity.js` | `receipt-verifier/arity.js` | same |
| `src/to-dsse.js` | `receipt-verifier/to-dsse.js` | same |

SHA-256 of those copies at vendor time is in `src/VENDOR.sha256`. Do not edit the copied files in this tree; recopy from receipt-verifier.

`src/unwrap.js` is the Contract Gate `unwrapReceiptInput` boundary over that `fromDSSE`. Unpacking is not verification.
