'use strict';

/**
 * I-1288f — the DECISION's own next step, rendered from the SIGNED envelope.
 *
 * The step lives inside decision_result, so decision_body_hash covers it and the
 * receipt signs it. That is the only reason this webhook may render it at all:
 * it needs no second call to the issuer, and it cannot be rewritten in transit.
 *
 * The load-bearing assertions are the two that could go wrong:
 *   1. THE VERDICT NEVER MOVES. Every field an operator or controller branches on
 *      is deep-equal to the same run with no step in the envelope.
 *   2. AN UNSIGNED STEP IS NEVER SHOWN. A refusal reached before verification —
 *      no receipt, no envelope, a tampered signature — renders nothing, even when
 *      the attacker put a perfectly well-formed step in the annotation.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  evaluateAdmission, readNextAgentStep, ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, REASON,
} = require('../src/admit.js');
const { newSigner, mintV4, envelope, NEXT_STEP } = require('./mint.js');

const KID = 'k8-nextstep-k1';
const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);
const NS = 'prod';
const NAME = 'orders';
const TARGET = `k8s:deployment:${NS}/${NAME}`;

/** A non-allow decision that still VERIFIES — the reachable case for this surface. */
const blockEnv = (extra = {}) => envelope({
  execution_action: 'STOP',
  decision: 'BLOCK',
  extra: {
    preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET, ...extra,
  },
});

const deployment = (ann = {}) => ({
  kind: 'Deployment', metadata: { name: NAME, namespace: NS, annotations: ann },
});
const admitted = (env, tok) => deployment({
  [ANNOTATION_RECEIPT]: tok || mintV4(signer, env),
  [ANNOTATION_ENVELOPE]: JSON.stringify(env),
});

function loadDenyStatus() {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  const m = src.match(/function denyStatus[\s\S]*?\n\}/);
  assert.ok(m, 'denyStatus not found in server.js');
  // eslint-disable-next-line no-eval
  return eval(`(${m[0].replace('function denyStatus', 'function')})`);
}
const denyStatus = loadDenyStatus();

describe('next_agent_step — reachability', () => {
  it('a non-allow decision DOES reach this surface: it verifies, then is refused', async () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    assert.equal(d.allowed, false);
    // Verification succeeded — the refusal is about the DECISION, not the receipt.
    assert.equal(d.receiptStatus, 'VERIFIED_CURRENT');
    assert.match(d.detail, /execution_action STOP is not CONTINUE/);
  });
});

describe('next_agent_step — rendered from a verified envelope', () => {
  it('the step is carried verbatim onto the decision', async () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    assert.deepEqual(d.nextStep, NEXT_STEP);
  });

  it('it rides in status.details.causes[] as CodeRiftsNextStep, message a JSON STRING', async () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    const status = denyStatus(d);
    const cause = status.details.causes.find((c) => c.reason === 'CodeRiftsNextStep');
    assert.ok(cause, 'no CodeRiftsNextStep cause');
    assert.equal(typeof cause.message, 'string', 'kube requires causes[].message to be a string');
    assert.deepEqual(JSON.parse(cause.message), NEXT_STEP);
  });

  it('status.code and status.message are untouched by the step', async () => {
    const withStep = await evaluateAdmission({
      object: admitted(blockEnv({ next_agent_step: NEXT_STEP })), keyring,
    });
    const without = await evaluateAdmission({ object: admitted(blockEnv()), keyring });
    const a = denyStatus(withStep);
    const b = denyStatus(without);
    assert.equal(a.code, b.code);
    assert.equal(a.message, b.message);
  });

  it('THE VERDICT NEVER MOVES: every branchable field is deep-equal to the no-step run', async () => {
    const withStep = await evaluateAdmission({
      object: admitted(blockEnv({ next_agent_step: NEXT_STEP })), keyring,
    });
    const without = await evaluateAdmission({ object: admitted(blockEnv()), keyring });
    for (const k of ['allowed', 'reason', 'receiptStatus', 'detail']) {
      assert.deepEqual(withStep[k], without[k], `${k} moved`);
    }
    assert.deepEqual(withStep.remedy, without.remedy);
    // The step is the ONLY difference between the two outcomes.
    const strip = (o) => { const c = { ...o }; delete c.nextStep; return c; };
    assert.deepEqual(strip(withStep), strip(without));
  });

  it('the two next steps CO-OCCUR: the gate\'s remedy and the decision\'s step, side by side', async () => {
    // MEASURED SEMANTICS. The execution_action check runs before every scope check, so a
    // non-allow envelope always refuses as receipt_invalid — which maps to GRANT_INVALID and
    // therefore carries this gate\'s own remedy. The decision\'s step rides beside it. They
    // answer different questions: the remedy is "your grant is not usable here", the step is
    // "this is what the decision says to do about the change".
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assert.ok(d.remedy, 'the gate\'s own remedy');
    assert.deepEqual(d.nextStep, NEXT_STEP);
    const causes = denyStatus(d).details.causes.map((c) => c.reason);
    assert.deepEqual(causes, ['CodeRiftsDenyRemedy', 'CodeRiftsNextStep']);
  });

  it('a scope mismatch on an ALLOW envelope renders the remedy and NO step (issuer sends null)', async () => {
    const env = envelope({
      execution_action: 'CONTINUE',
      decision: 'ALLOW',
      extra: {
        preflight_mode: 'authorize',
        operation: 'deploy',
        target_id: `k8s:deployment:${NS}/other`,
        next_agent_step: null,
      },
    });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    assert.equal(d.reason, REASON.SCOPE_MISMATCH);
    assert.ok(d.remedy);
    assert.ok(!('nextStep' in d));
  });
});

describe('next_agent_step — an unsigned step is never shown as guidance', () => {
  it('a TAMPERED signature renders no step, even though the annotation carries one', async () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const good = mintV4(signer, env);
    const badSig = `${good.split('.')[0]}.${Buffer.from('not-a-signature').toString('base64url')}`;
    const d = await evaluateAdmission({ object: admitted(env, badSig), keyring });
    assert.equal(d.allowed, false);
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assert.ok(!('nextStep' in d), 'an unverified envelope must never yield a step');
    const causes = denyStatus(d).details.causes.map((c) => c.reason);
    assert.ok(!causes.includes('CodeRiftsNextStep'));
  });

  it('an envelope signed by an UNKNOWN key renders no step', async () => {
    const stranger = newSigner('not-in-the-keyring');
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({ object: admitted(env, mintV4(stranger, env)), keyring });
    assert.equal(d.allowed, false);
    assert.ok(!('nextStep' in d));
  });

  it('a missing receipt has NO envelope at all — no step, only the gate\'s remedy', async () => {
    const d = await evaluateAdmission({ object: deployment(), keyring });
    assert.equal(d.reason, REASON.RECEIPT_MISSING);
    assert.ok(!('nextStep' in d));
    assert.ok(d.remedy, 'the gate\'s own remedy is unaffected');
  });

  it('a receipt with no envelope annotation renders no step', async () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const d = await evaluateAdmission({
      object: deployment({ [ANNOTATION_RECEIPT]: mintV4(signer, env) }), keyring,
    });
    assert.equal(d.reason, REASON.RECEIPT_INVALID);
    assert.ok(!('nextStep' in d));
  });
});

describe('next_agent_step — absent, allow, and malformed', () => {
  it('an ALLOW that admits renders nothing', async () => {
    const env = envelope({
      execution_action: 'CONTINUE',
      decision: 'ALLOW',
      extra: {
        preflight_mode: 'authorize', operation: 'deploy', target_id: TARGET, next_agent_step: null,
      },
    });
    const d = await evaluateAdmission({ object: admitted(env), keyring });
    assert.equal(d.allowed, true);
    assert.ok(!('nextStep' in d));
  });

  it('an absent step is not invented', async () => {
    for (const step of [null, undefined]) {
      const env = blockEnv(step === undefined ? {} : { next_agent_step: step });
      // eslint-disable-next-line no-await-in-loop
      const d = await evaluateAdmission({ object: admitted(env), keyring });
      assert.ok(!('nextStep' in d), `unexpected step for ${String(step)}`);
      assert.ok(!denyStatus(d).details.causes.some((c) => c.reason === 'CodeRiftsNextStep'));
    }
  });

  it('a step without an action is not a step', () => {
    assert.equal(readNextAgentStep({ next_agent_step: { reason: 'x', then_call: 'y' } }), null);
    assert.equal(readNextAgentStep({ next_agent_step: 'revert' }), null);
    assert.equal(readNextAgentStep({ next_agent_step: ['revert'] }), null);
    assert.equal(readNextAgentStep({ next_agent_step: { action: '' } }), null);
    assert.equal(readNextAgentStep(null), null);
  });
});
