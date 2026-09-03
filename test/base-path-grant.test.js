'use strict';

/**
 * 1307 — the BASE path verifies an execution grant, not only a receipt.
 *
 * MEASURED before this: this webhook read `coderifts.com/receipt` and `coderifts.com/envelope` and
 * nothing else. A receipt records that a decision was issued; a grant is the permission to act on
 * it, bound to one executor, one target and one use. The bundle annotation added grant checking,
 * but only for holders who assemble a bundle — a strictly smaller set than holders who have a grant.
 *
 * THE WORST CASE these tests are written against: an attacker who holds ANY verified receipt and
 * ANY verified grant pairs them and the pair looks complete. That is why the binding test matters
 * more than the happy path.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  evaluateAdmission, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, ANNOTATION_GRANT, REASON,
} = require('../src/admit');
const { loadKeyring } = require('../src/verify');
const { receiptDigest, reconstructSignedInput } = require('../src/verify-grant.js');
const { newSigner, mintV4, writeKeyringFile, envelope } = require('./mint');

const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;

const signer = newSigner('k8s-k1');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-basegrant-'));
const keyringFile = writeKeyringFile(tmp, signer);
const keyring = () => loadKeyring(keyringFile);

function boundEnvelope() {
  return envelope({
    execution_action: 'CONTINUE',
    decision: 'ALLOW',
    extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET },
  });
}

function mintGrant(receiptToken, over = {}) {
  const now = Date.now();
  const body = {
    v: 'cr.exec.v1',
    kid: signer.kid,
    receipt_digest: receiptDigest(receiptToken),
    scope_hash: `sha256:${crypto.createHash('sha256').update('scope').digest('hex')}`,
    audience: TARGET,
    operation: 'deploy',
    target_id: TARGET,
    jti: 'jti-base-1',
    iat: new Date(now - 1000).toISOString(),
    exp: new Date(now + 300000).toISOString(),
    ...over,
  };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(body), 'utf8'), signer.privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
}

function deployment(ann) {
  return { kind: 'Deployment', metadata: { name: NAME, namespace: NS, annotations: ann } };
}

function annotated(extra = {}) {
  const env = boundEnvelope();
  const receipt = mintV4(signer, env);
  return {
    receipt,
    object: deployment({
      [ANNOTATION_RECEIPT]: receipt,
      [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      ...extra,
    }),
  };
}

describe('1307 — additive: nothing changes without the annotation', () => {
  it('an object with no grant annotation is admitted exactly as before', async () => {
    const { object } = annotated();
    const d = await evaluateAdmission({ object, keyring: await keyring() });
    assert.equal(d.allowed, true);
    assert.equal(d.reason, 'signed_allow_for_workload');
    assert.equal(d.grant, undefined, 'an admission with no grant grew a grant field');
  });
});

describe('1307 — a grant on the base path is verified', () => {
  it('a real grant bound to the receipt is admitted, and reported', async () => {
    const { receipt, object } = annotated();
    const withGrant = deployment({
      ...object.metadata.annotations, [ANNOTATION_GRANT]: mintGrant(receipt),
    });
    const d = await evaluateAdmission({ object: withGrant, keyring: await keyring() });
    assert.equal(d.allowed, true, d.detail);
    assert.equal(d.grant.jti, 'jti-base-1');
    assert.equal(d.grant.operation, 'deploy');
  });

  it('a FORGED grant is denied', async () => {
    const { receipt, object } = annotated();
    const [body, sig] = mintGrant(receipt).split('.');
    const raw = Buffer.from(sig, 'base64url');
    raw[0] ^= 0xff;
    const withGrant = deployment({
      ...object.metadata.annotations,
      [ANNOTATION_GRANT]: `${body}.${raw.toString('base64url')}`,
    });
    const d = await evaluateAdmission({ object: withGrant, keyring: await keyring() });
    assert.equal(d.allowed, false, 'a forged grant was admitted');
    assert.equal(d.reason, REASON.GRANT_INVALID);
  });

  it('WORST CASE: a VALID grant for a DIFFERENT receipt is denied', async () => {
    // The attack the binding exists for. Both documents verify; they are about different things.
    // MEASURED: mintV4 over an identical envelope produces an identical token, so the first
    // attempt at this test compared a receipt with itself and the binding correctly accepted it.
    // The other receipt has to actually differ.
    const otherEnv = envelope({
      execution_action: 'CONTINUE',
      decision: 'ALLOW',
      extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: `${TARGET}-other` },
    });
    const other = mintV4(signer, otherEnv);
    assert.notEqual(other, mintV4(signer, boundEnvelope()), 'the two receipts are not different');
    const { object } = annotated();
    const withGrant = deployment({
      ...object.metadata.annotations, [ANNOTATION_GRANT]: mintGrant(other),
    });
    const d = await evaluateAdmission({ object: withGrant, keyring: await keyring() });
    assert.equal(d.allowed, false, 'a grant bound to another receipt was accepted');
    assert.equal(d.reason, REASON.GRANT_NOT_BOUND);
    assert.match(d.detail, /different things/);
  });

  it('an EXPIRED grant is denied', async () => {
    const { receipt, object } = annotated();
    const past = Date.now() - 600000;
    const expired = mintGrant(receipt, {
      iat: new Date(past - 1000).toISOString(), exp: new Date(past).toISOString(),
    });
    const d = await evaluateAdmission({
      object: deployment({ ...object.metadata.annotations, [ANNOTATION_GRANT]: expired }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.GRANT_INVALID);
  });
});

describe('1307 — requireGrant makes absence a refusal', () => {
  it('no grant + requireGrant → denied with a named reason', async () => {
    const { object } = annotated();
    const d = await evaluateAdmission({ object, keyring: await keyring(), requireGrant: true });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.GRANT_MISSING);
    assert.match(d.detail, /a grant is the permission to act on it/);
  });

  it('a grant + requireGrant → admitted', async () => {
    const { receipt, object } = annotated();
    const d = await evaluateAdmission({
      object: deployment({ ...object.metadata.annotations, [ANNOTATION_GRANT]: mintGrant(receipt) }),
      keyring: await keyring(),
      requireGrant: true,
    });
    assert.equal(d.allowed, true, d.detail);
  });
});

describe('1307 — the grant never becomes a second door', () => {
  it('a perfect grant does not rescue a receipt that fails', async () => {
    const env = boundEnvelope();
    const receipt = mintV4(signer, env);
    const parts = receipt.split('.');
    const raw = Buffer.from(parts[parts.length - 1], 'base64url');
    raw[0] ^= 0xff;
    parts[parts.length - 1] = raw.toString('base64url');

    const d = await evaluateAdmission({
      object: deployment({
        [ANNOTATION_RECEIPT]: parts.join('.'),
        [ANNOTATION_ENVELOPE]: JSON.stringify(env),
        [ANNOTATION_GRANT]: mintGrant(receipt),
      }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID, 'the grant masked a failing receipt');
  });

  it('verification is OFFLINE — the same pinned keyring, no fetch', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'admit.js'), 'utf8');
    assert.doesNotMatch(src, /fetch\(|https?\.request|axios/,
      'the admission path acquired a network call');
  });
});
