'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  evaluateAdmission, workloadIdentity, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, REASON,
} = require('../src/admit');
const { loadKeyring } = require('../src/verify');
const { fromDSSE, PAYLOAD_TYPE, PREDICATE_TYPE, FORM } = require('../src/to-dsse');
const { unwrapReceiptInput } = require('../src/unwrap');
const { newSigner, mintV4, tamperSignature, writeKeyringFile, envelope } = require('./mint');

const signer = newSigner('k8s-k1');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-admit-'));
const keyringFile = writeKeyringFile(tmp, signer);

async function keyring() { return loadKeyring(keyringFile); }

const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;

function boundEnvelope(extra = {}) {
  return envelope({
    execution_action: extra.execution_action || 'CONTINUE',
    decision: extra.decision || 'ALLOW',
    extra: {
      preflight_mode: 'authorize',
      operation: 'deploy',
      target_id: TARGET,
      ...extra,
    },
  });
}

function deployment(ann = {}) {
  return {
    kind: 'Deployment',
    metadata: {
      name: NAME,
      namespace: NS,
      annotations: ann,
    },
  };
}

function withReceipt(env, token) {
  return deployment({
    [ANNOTATION_RECEIPT]: token,
    [ANNOTATION_ENVELOPE]: JSON.stringify(env),
  });
}

function wrap(token) {
  const dot = token.split('.');
  const fields = JSON.parse(Buffer.from(dot[0], 'base64url').toString('utf8'));
  const compact = { form: FORM.RECEIPT, encoded_payload: dot[0] };
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: compact.form, digest: { sha256: crypto.createHash('sha256').update(token, 'utf8').digest('hex') } }],
    predicateType: PREDICATE_TYPE,
    predicate: { compact, fields },
  };
  return {
    payloadType: PAYLOAD_TYPE,
    payload: Buffer.from(JSON.stringify(statement), 'utf8').toString('base64'),
    signatures: [{ keyid: fields.kid || '', sig: dot[1] }],
  };
}

describe('workload identity', () => {
  it('is k8s:{kind}:{namespace}/{name}', () => {
    assert.equal(workloadIdentity(deployment()), TARGET);
  });
});

describe('evaluateAdmission — deny unless valid', () => {
  it('missing receipt annotation → receipt_missing', async () => {
    const d = await evaluateAdmission({ object: deployment(), keyring: await keyring() });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_MISSING);
  });

  it('empty receipt annotation → receipt_missing', async () => {
    const d = await evaluateAdmission({
      object: deployment({ [ANNOTATION_RECEIPT]: '  ' }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_MISSING);
  });

  it('presence of a tampered receipt is not a pass → receipt_invalid', async () => {
    const env = boundEnvelope();
    const token = tamperSignature(mintV4(signer, env));
    const d = await evaluateAdmission({ object: withReceipt(env, token), keyring: await keyring() });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assert.equal(d.receiptStatus, 'INVALID_SIGNATURE');
  });

  it('unknown kid → receipt_invalid', async () => {
    const env = boundEnvelope();
    const token = mintV4(signer, env, { kid: 'rogue' });
    const d = await evaluateAdmission({ object: withReceipt(env, token), keyring: await keyring() });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assert.equal(d.receiptStatus, 'UNKNOWN_KEY');
  });

  it('STOP even with a valid signature → receipt_invalid', async () => {
    const env = boundEnvelope({ execution_action: 'STOP', decision: 'BLOCK' });
    const d = await evaluateAdmission({
      object: withReceipt(env, mintV4(signer, env)),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
  });

  it('operation=merge on a deploy admission → scope_mismatch', async () => {
    const env = boundEnvelope({ operation: 'merge' });
    const d = await evaluateAdmission({
      object: withReceipt(env, mintV4(signer, env)),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.SCOPE_MISMATCH);
  });

  it('target_id for a different workload → scope_mismatch', async () => {
    const env = boundEnvelope({ target_id: 'k8s:deployment:prod/other' });
    const d = await evaluateAdmission({
      object: withReceipt(env, mintV4(signer, env)),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.SCOPE_MISMATCH);
  });

  it('malformed DSSE envelope → dsse_malformed', async () => {
    const env = boundEnvelope();
    const bad = {
      payloadType: PAYLOAD_TYPE,
      payload: Buffer.from('not-json', 'utf8').toString('base64'),
      signatures: [{ sig: 'x' }],
    };
    const d = await evaluateAdmission({
      object: deployment({
        [ANNOTATION_RECEIPT]: JSON.stringify(bad),
        [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.DSSE_MALFORMED);
  });

  it('valid compact receipt + matching deploy scope → allowed', async () => {
    const env = boundEnvelope();
    const d = await evaluateAdmission({
      object: withReceipt(env, mintV4(signer, env)),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, true);
    assert.equal(d.reason, 'signed_allow_for_workload');
    assert.equal(d.receiptStatus, 'VERIFIED_CURRENT');
  });

  it('valid DSSE-wrapped receipt + matching scope → allowed (unwrap, then verify compact bytes)', async () => {
    const env = boundEnvelope();
    const token = mintV4(signer, env);
    const dsse = wrap(token);
    assert.equal(fromDSSE(dsse), token);
    const d = await evaluateAdmission({
      object: deployment({
        [ANNOTATION_RECEIPT]: JSON.stringify(dsse),
        [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, true);
    assert.equal(d.receiptStatus, 'VERIFIED_CURRENT');
  });

  it('DSSE wrapping a tampered token still denies (envelope is not a pass)', async () => {
    const env = boundEnvelope();
    const token = tamperSignature(mintV4(signer, env));
    const d = await evaluateAdmission({
      object: deployment({
        [ANNOTATION_RECEIPT]: JSON.stringify(wrap(token)),
        [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      }),
      keyring: await keyring(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
  });
});

describe('C-route — vendored, zero dependencies', () => {
  it('package.json has no runtime dependencies', () => {
    const pkg = require('../package.json');
    assert.deepEqual(pkg.dependencies || {}, {});
  });

  it('unwrap of compact token is identity', () => {
    const env = boundEnvelope();
    const token = mintV4(signer, env);
    assert.deepEqual(unwrapReceiptInput(token), { ok: true, token, form: 'compact' });
  });
});
