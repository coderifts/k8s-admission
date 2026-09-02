'use strict';
/**
 * crbundle.v1 acceptance in the deploy admission webhook (1261).
 *
 * WHAT A BUNDLE ADDS HERE, and it is not decoration. MEASURED: admit.js verifies the RECEIPT
 * annotation and nothing else — there is no execution-grant verification on the annotation path at
 * all. An object that also carries a bundle gets the grant verified AND gets the library's
 * `grant_binds_receipt` linkage check, so the bundle path is strictly stronger than the path it
 * sits beside, never a parallel way in.
 *
 * WHY IT TRAVELS IN AN ANNOTATION RATHER THAN BY REFERENCE. Measured: a two-slot bundle is ~1.4 KB
 * of JSON against Kubernetes' 256 KB annotation budget. A reference would mean this webhook
 * fetching something at admission time, and this webhook never fetches anything.
 *
 * The trap these tests exist for is the same one the Contract Gate has: `SLOT.VERIFIED` is not
 * "proven". An unsigned PROVIDER_READBACK grades VERIFIED in the library, and must never stand in
 * for a slot the deploy actually needs.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  evaluateAdmission, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, ANNOTATION_BUNDLE, REASON,
} = require('../src/admit');
const { loadKeyring } = require('../src/verify');
const { receiptDigest, reconstructSignedInput } = require('../src/verify-grant.js');
const { classOf } = require('../src/bundle-gate');
const { newSigner, mintV4, writeKeyringFile, envelope } = require('./mint');

const signer = newSigner('k8s-k1');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-bundle-'));
const keyringFile = writeKeyringFile(tmp, signer);

const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;

async function keyring() { return loadKeyring(keyringFile); }
async function slotOpts() {
  const kr = await keyring();
  return {
    perSlot: {
      receipt: { ctx: { keyring: kr, expectedKid: null } },
      execution_grant: { ctx: { keyring: kr, expectedKid: null } },
    },
  };
}

function boundEnvelope() {
  return envelope({
    execution_action: 'CONTINUE',
    decision: 'ALLOW',
    extra: { preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET },
  });
}

/**
 * A real cr.exec.v1 grant. `receipt_digest` binds the ACTUAL receipt in the bundle: the library
 * runs a `grant_binds_receipt` linkage check, so a grant bound to a placeholder would make an
 * otherwise-valid bundle INVALID.
 */
function mintGrant(receiptToken, now = Date.now()) {
  const body = {
    v: 'cr.exec.v1',
    kid: signer.kid,
    receipt_digest: receiptDigest(receiptToken),
    scope_hash: `sha256:${crypto.createHash('sha256').update('scope').digest('hex')}`,
    audience: TARGET,
    operation: 'deploy',
    target_id: TARGET,
    jti: 'jti-k8s-1',
    iat: new Date(now - 1000).toISOString(),
    exp: new Date(now + 300000).toISOString(),
  };
  // The signing input comes from the VENDORED verifier, not a hand-written field join here. A
  // local copy of the field order drifts from the verifier the moment either changes, and a test
  // that signs over the wrong preimage proves only that its own two halves agree with each other.
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
    env,
    object: deployment({
      [ANNOTATION_RECEIPT]: receipt,
      [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      ...extra,
    }),
  };
}

function bundleAnnotation(slots) {
  return { [ANNOTATION_BUNDLE]: JSON.stringify({ v: 'cr.bundle.v1', slots }) };
}

describe('bundle admission — additive', () => {
  it('REGRESSION: an object with NO bundle annotation is admitted exactly as before', async () => {
    const { object } = annotated();
    const d = await evaluateAdmission({ object, keyring: await keyring() });
    assert.equal(d.allowed, true);
    assert.equal(d.reason, 'signed_allow_for_workload');
    assert.equal(d.bundle, undefined, 'an admission without a bundle grew a bundle field');
  });

  it('REGRESSION: the existing deny reasons are untouched by the new branch', async () => {
    const d = await evaluateAdmission({ object: deployment({}), keyring: await keyring() });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_MISSING);
  });
});

describe('bundle admission — a real bundle', () => {
  it('a real bundle is admitted and the classes are named', async () => {
    const { receipt, object } = annotated();
    const withBundle = deployment({
      ...object.metadata.annotations,
      ...bundleAnnotation({ receipt, execution_grant: mintGrant(receipt) }),
    });
    const d = await evaluateAdmission({
      object: withBundle, keyring: await keyring(), bundleSlotOpts: await slotOpts(),
    });
    assert.equal(d.allowed, true, d.detail);
    assert.equal(d.bundle.classes.receipt, 'PROVEN');
    assert.equal(d.bundle.classes.execution_grant, 'PROVEN');
  });

  it('a bundle with a FORGED grant slot is DENIED', async () => {
    const { receipt, object } = annotated();
    const grant = mintGrant(receipt);
    const [body, sig] = grant.split('.');
    const raw = Buffer.from(sig, 'base64url');
    raw[0] ^= 0xff;
    const withBundle = deployment({
      ...object.metadata.annotations,
      ...bundleAnnotation({ receipt, execution_grant: `${body}.${raw.toString('base64url')}` }),
    });
    const d = await evaluateAdmission({
      object: withBundle, keyring: await keyring(), bundleSlotOpts: await slotOpts(),
    });
    assert.equal(d.allowed, false, 'a forged bundle slot was admitted');
    assert.equal(d.reason, REASON.BUNDLE_NOT_PROVEN);
    assert.equal(d.bundle.classes.execution_grant, 'INVALID');
    assert.match(d.detail, /invalid slots: execution_grant/);
  });

  it('an UNSIGNED readback cannot stand in for the missing grant', async () => {
    const { receipt, object } = annotated();
    const readback = JSON.stringify({
      provider: 'github',
      required_check: 'CodeRifts / contract-gate',
      integration_id: 12345,
      rollup_state: 'success',
      observed_at: new Date().toISOString(),
      bound_to_source: true,
    });
    const withBundle = deployment({
      ...object.metadata.annotations,
      ...bundleAnnotation({ receipt, merge_evidence: readback }),
    });
    const d = await evaluateAdmission({
      object: withBundle, keyring: await keyring(), bundleSlotOpts: await slotOpts(),
    });
    assert.equal(d.bundle.classes.merge_evidence, 'PROVIDER_READBACK');
    assert.equal(d.allowed, false, 'an unsigned provider statement was accepted as the grant');
    assert.match(d.detail, /execution_grant/);
  });

  it('a malformed bundle annotation is a REFUSAL, not a skip', async () => {
    const { object } = annotated();
    const withBundle = deployment({
      ...object.metadata.annotations, [ANNOTATION_BUNDLE]: '{ not json',
    });
    const d = await evaluateAdmission({
      object: withBundle, keyring: await keyring(), bundleSlotOpts: await slotOpts(),
    });
    assert.equal(d.allowed, false, 'an unparseable bundle was silently ignored');
    assert.equal(d.reason, REASON.BUNDLE_MALFORMED);
  });

  it('the bundle is checked AFTER the receipt and scope, never instead of them', async () => {
    // A perfect bundle on an object whose receipt annotation does not verify must still be denied
    // on the receipt: the bundle is additional evidence, not a second door.
    const env = boundEnvelope();
    const receipt = mintV4(signer, env);
    const parts = receipt.split('.');
    const raw = Buffer.from(parts[parts.length - 1], 'base64url');
    raw[0] ^= 0xff;
    parts[parts.length - 1] = raw.toString('base64url');

    const object = deployment({
      [ANNOTATION_RECEIPT]: parts.join('.'),
      [ANNOTATION_ENVELOPE]: JSON.stringify(env),
      ...bundleAnnotation({ receipt, execution_grant: mintGrant(receipt) }),
    });
    const d = await evaluateAdmission({
      object, keyring: await keyring(), bundleSlotOpts: await slotOpts(),
    });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID, 'the bundle masked a failing receipt annotation');
  });

  it('keys come from the webhook, never from the annotation', async () => {
    // With no slot material supplied, the slots cannot verify and the bundle is refused. A bundle
    // that could carry its own key would be self-certifying.
    const { receipt, object } = annotated();
    const withBundle = deployment({
      ...object.metadata.annotations,
      ...bundleAnnotation({ receipt, execution_grant: mintGrant(receipt) }),
    });
    const d = await evaluateAdmission({ object: withBundle, keyring: await keyring() });
    assert.equal(d.allowed, false, 'a bundle verified itself without operator-supplied keys');
  });
});

describe('the class contract is the same one the Contract Gate uses', () => {
  it('PROVIDER_READBACK is VERIFIED to the library and NOT proof here', () => {
    assert.equal(
      classOf({ slot: 'merge_evidence', state: 'VERIFIED', status: 'PROVIDER_READBACK' }),
      'PROVIDER_READBACK',
    );
  });
  it('an unclassified VERIFIED status is not silently proof', () => {
    assert.equal(classOf({ slot: 'receipt', state: 'VERIFIED', status: 'FUTURE' }), 'UNCLASSIFIED');
  });
});
