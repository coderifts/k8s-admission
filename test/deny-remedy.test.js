'use strict';

/**
 * The admission refusal carries a next step.
 *
 * The load-bearing assertion is that the DECISION is unchanged: `allowed`,
 * `reason`, `receiptStatus` and `detail` are compared against the values this
 * surface produced before the remedy existed. A remedy that moved a verdict
 * would be a governance change wearing an ergonomics label.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  evaluateAdmission, workloadIdentity, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, REASON,
} = require('../src/admit.js');
const { denyErrorForReason, DENY_ERROR } = require('../src/deny-remedy.js');
const { assertValidRemedy } = require('./remedy-shape.js');
const { newSigner, mintV4, envelope } = require('./mint.js');

const KID = 'k8-remedy-k1';
const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);
const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;

const bound = (extra = {}) => envelope({
  execution_action: 'CONTINUE',
  decision: 'ALLOW',
  extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET, ...extra },
});
const env = bound();
const token = mintV4(signer, env);
const deployment = (ann = {}) => ({
  kind: 'Deployment', metadata: { name: NAME, namespace: NS, annotations: ann },
});
const withEnv = (e, tok) => deployment({
  [ANNOTATION_RECEIPT]: tok, [ANNOTATION_ENVELOPE]: JSON.stringify(e),
});
const signed = (over = {}) => deployment({
  [ANNOTATION_RECEIPT]: token, [ANNOTATION_ENVELOPE]: JSON.stringify(env), ...over,
});
const badSig = `${token.split('.')[0]}.${Buffer.from('not-a-signature').toString('base64url')}`;

/** denyStatus is the server's renderer; loaded from source so the test uses the shipped one. */
function loadDenyStatus() {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  const m = src.match(/function denyStatus[\s\S]*?\n\}/);
  assert.ok(m, 'denyStatus not found in server.js');
  // eslint-disable-next-line no-eval
  return eval(`(${m[0].replace('function denyStatus', 'function')})`);
}

describe('deny-remedy — the admission refusal names the next step', () => {
  it('GRANT_REQUIRED: no receipt annotation', async () => {
    const d = await evaluateAdmission({ object: deployment(), keyring });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_MISSING);
    assertValidRemedy(d.remedy, 'receipt_missing');
    assert.equal(d.remedy.error, DENY_ERROR.GRANT_REQUIRED);
    assert.equal(d.remedy.target, workloadIdentity(deployment()));
    assert.equal(d.remedy.fingerprint, null);
  });

  it('GRANT_INVALID: a receipt that does not verify', async () => {
    const d = await evaluateAdmission({ object: signed({ [ANNOTATION_RECEIPT]: badSig }), keyring });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assertValidRemedy(d.remedy, 'receipt_invalid');
    assert.equal(d.remedy.error, DENY_ERROR.GRANT_INVALID);
  });

  it('GRANT_MISMATCH: a valid receipt bound to another workload', async () => {
    const other = bound({ target_id: `k8s:deployment:${NS}/other` });
    const d = await evaluateAdmission({ object: withEnv(other, mintV4(signer, other)), keyring });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.SCOPE_MISMATCH);
    assertValidRemedy(d.remedy, 'scope_mismatch');
    assert.equal(d.remedy.error, DENY_ERROR.GRANT_MISMATCH);
  });
});

describe('deny-remedy — the decision is unchanged', () => {
  const verdictOf = (d) => ({
    allowed: d.allowed, reason: d.reason, receiptStatus: d.receiptStatus, detail: d.detail,
  });

  it('the four decision fields match the pre-remedy values', async () => {
    assert.deepEqual(verdictOf(await evaluateAdmission({ object: deployment(), keyring })),
      { allowed: false, reason: 'receipt_missing', receiptStatus: null, detail: null });
    assert.deepEqual(
      verdictOf(await evaluateAdmission({ object: signed({ [ANNOTATION_RECEIPT]: badSig }), keyring })),
      { allowed: false, reason: 'receipt_invalid', receiptStatus: 'INVALID_SIGNATURE', detail: null },
    );
  });

  it('an admitted workload carries NO remedy key', async () => {
    const d = await evaluateAdmission({ object: signed(), keyring });
    assert.equal(d.allowed, true, JSON.stringify(d));
    assert.ok(!('remedy' in d), 'an admitted workload must not carry a refusal remedy');
  });
});

describe('deny-remedy — the Status carries it without breaking the API shape', () => {
  const denyStatus = loadDenyStatus();

  it('code and message are unchanged; the remedy rides in details.causes[]', async () => {
    const d = await evaluateAdmission({ object: deployment(), keyring });
    const status = denyStatus(d);
    assert.equal(status.code, 403);
    // What kubectl prints, byte-identical to the pre-remedy message.
    assert.equal(status.message, 'receipt_missing');
    assert.equal(status.details.causes.length, 1);
    assert.equal(status.details.causes[0].reason, 'CodeRiftsDenyRemedy');
  });

  it('the cause message is a STRING — the Kubernetes API contract for that field', () => {
    const status = denyStatus({ reason: 'receipt_missing', detail: null, remedy: { error: 'x' } });
    assert.equal(typeof status.details.causes[0].message, 'string');
    assert.deepEqual(JSON.parse(status.details.causes[0].message), { error: 'x' });
  });

  it('a decision with no remedy emits NO details key at all', () => {
    const status = denyStatus({ reason: 'verifier_threw', detail: 'boom' });
    assert.equal(status.message, 'verifier_threw: boom');
    assert.ok(!('details' in status), 'an unmapped refusal must not carry an empty details block');
    assert.equal(denyErrorForReason('verifier_threw'), null);
  });
});
