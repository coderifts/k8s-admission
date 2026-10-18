'use strict';

/**
 * Only a v4 receipt bound to the envelope annotation is authorization (P66; receipt-verifier 1.1.4 moves
 * the rule into the core verifyReceipt, this repo's call site has carried it since 2026-10-17).
 *
 * MEASURED 2026-10-17 (org audit, CC 17b block C): with the v1.0.3 core vendored and no call-site check,
 * a real production-signed v2 receipt (no `bh`, `caller: anon`) beside a FORGED ALLOW/CONTINUE envelope
 * annotation was admitted (`signed_allow_for_workload`). These cases keep that from coming back.
 *
 * Fixtures are PUBLIC test fixtures copied from receipt-verifier: test/fixtures-receipt.txt (a v2 receipt
 * signed by the production key 2026-07-k1), test/fixtures-keys.json (that key's PUBLIC half), and the
 * `valid_v4` vector of test/vectors.json (a test key). No private key is involved.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { evaluateAdmission, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, REASON } = require('../src/admit');
const { loadKeyring, verifyReceipt } = require('../src/verify');
const { newSigner, mintV4, writeKeyringFile, envelope } = require('./mint');

const FIX = path.join(__dirname, 'fixtures');
const V2 = fs.readFileSync(path.join(FIX, 'rv-v2-production-receipt.txt'), 'utf8').trim();
const V4 = JSON.parse(fs.readFileSync(path.join(FIX, 'rv-valid-v4-vector.json'), 'utf8'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-v4only-'));
const V4_KEYS = path.join(tmp, 'v4-keys.json');
fs.writeFileSync(V4_KEYS, JSON.stringify({ keys: [{ kid: V4.kid, alg: 'Ed25519', status: 'active', public_key_pem: V4.public_key_pem }] }));

const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;
/** An envelope anyone can write: ALLOW / CONTINUE for exactly this workload. */
const FORGED = envelope({
  execution_action: 'CONTINUE', decision: 'ALLOW',
  extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET },
});
const object = (token, env) => ({
  kind: 'Deployment',
  metadata: { name: NAME, namespace: NS, annotations: { [ANNOTATION_RECEIPT]: token, [ANNOTATION_ENVELOPE]: JSON.stringify(env) } },
});

describe('v4-only — a v<4 receipt beside an envelope annotation is never admission', () => {
  it('control: the production v2 receipt itself verifies (signature) with the pinned public key', async () => {
    const r = verifyReceipt(V2, { ctx: { keyring: await loadKeyring(path.join(FIX, 'rv-v2-production-keys.json')), expectedKid: null } });
    assert.equal(r.valid, true, JSON.stringify(r));
    assert.equal(r.payload.v, 2);
  });

  it('⚠⚠ production v2 receipt + forged ALLOW envelope → denied, RECEIPT_VERSION_UNSUPPORTED', async () => {
    const d = await evaluateAdmission({ object: object(V2, FORGED), keyring: await loadKeyring(path.join(FIX, 'rv-v2-production-keys.json')) });
    assert.equal(d.allowed, false, JSON.stringify(d));
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    // Before the 1.1.4 re-vendor the call site sets it; after it the core's own status carries it.
    assert.equal(d.receiptStatus, 'RECEIPT_VERSION_UNSUPPORTED');
  });

  it('the valid_v4 vector beside an envelope it does not bind → the verdict it had (INVALID_SIGNATURE)', async () => {
    const d = await evaluateAdmission({ object: object(V4.token, FORGED), keyring: await loadKeyring(V4_KEYS) });
    assert.equal(d.allowed, false, JSON.stringify(d));
    assert.equal(d.receiptStatus, 'INVALID_SIGNATURE');
  });

  it('control: a v4 receipt bound to its envelope is still admitted', async () => {
    const signer = newSigner('k8s-v4only');
    const env = envelope({
      execution_action: 'CONTINUE', decision: 'ALLOW',
      extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET },
    });
    const d = await evaluateAdmission({ object: object(mintV4(signer, env), env), keyring: await loadKeyring(writeKeyringFile(tmp, signer)) });
    assert.equal(d.allowed, true, JSON.stringify(d));
  });
});
