'use strict';

/**
 * Admission decision — PURE (no I/O), same shape as contract-gate/src/gate.js.
 *
 * Flow: read annotation → unwrap DSSE if present → verifyReceipt (offline,
 * pinned keyring) → deny unless valid AND scope matches the admitted object.
 *
 * A receipt PRESENCE is not a pass. A DSSE envelope unwraps but does not
 * self-authorize. The signature is over the compact bytes.
 *
 * Named reasons (operator-facing, closed set):
 *   receipt_missing | receipt_invalid | scope_mismatch | dsse_malformed
 */

const { verifyReceipt } = require('./verify');
const { unwrapReceiptInput } = require('./unwrap');
const { buildDenyRemedy, denyErrorForReason } = require('./deny-remedy.js');

const ANNOTATION_RECEIPT = 'coderifts.com/receipt';
const ANNOTATION_ENVELOPE = 'coderifts.com/envelope';

const PASSING_ACTIONS = new Set(['CONTINUE', 'CONTINUE_WITH_MONITORING']);

const REASON = Object.freeze({
  RECEIPT_MISSING: 'receipt_missing',
  RECEIPT_INVALID: 'receipt_invalid',
  SCOPE_MISMATCH: 'scope_mismatch',
  DSSE_MALFORMED: 'dsse_malformed',
});

function boundSlot(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

/** k8s:{kind}:{namespace}/{name} — the target the receipt must name. */
function workloadIdentity(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const kind = obj.kind ? String(obj.kind).toLowerCase() : 'unknown';
  const md = obj.metadata && typeof obj.metadata === 'object' ? obj.metadata : {};
  const ns = md.namespace != null && String(md.namespace) !== '' ? String(md.namespace) : 'default';
  const name = md.name != null ? String(md.name) : '';
  if (!name) return null;
  return `k8s:${kind}:${ns}/${name}`;
}

function annotationsOf(obj) {
  const md = obj && obj.metadata;
  const a = md && md.annotations;
  return a && typeof a === 'object' ? a : {};
}

function parseEnvelope(raw) {
  if (raw == null || raw === '') return null;
  if (typeof raw === 'object' && !Array.isArray(raw)) return raw;
  if (typeof raw !== 'string') return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch (_) {
    return null;
  }
}

/**
 * The decision's own remediation SUGGESTION, read from an envelope this process
 * has ALREADY VERIFIED (I-1288f).
 *
 * The step lives inside decision_result, so decision_body_hash covers it and the
 * receipt signs it: reading it here needs no second call to the issuer. That is
 * the whole reason it is safe to render, and it is also the reason this function
 * must never be called before verifyReceipt returned valid — an unsigned step is
 * an attacker-supplied instruction wearing the issuer's voice.
 *
 * Shape and closed action set: coderifts-app schemas/decision-result.v1.producer.json
 * properties.next_agent_step. A step without an action is not a step (same rule as
 * contract-gate readNextAgentStep).
 */
function readNextAgentStep(envelope) {
  const step = envelope && typeof envelope === 'object' ? envelope.next_agent_step : null;
  if (!step || typeof step !== 'object' || Array.isArray(step)) return null;
  if (typeof step.action !== 'string' || step.action.length === 0) return null;
  return step;
}

/**
 * A refusal, plus the next step when this refusal has one.
 *
 * ADDITIVE: `allowed`, `reason`, `receiptStatus` and `detail` are byte-identical
 * to what this returned before the remedy existed, so a controller branching on
 * them is unaffected. A reason that maps to no error class carries no remedy
 * rather than a guessed one.
 */
function deny(reason, extra = {}) {
  const out = {
    allowed: false,
    reason,
    receiptStatus: extra.receiptStatus ?? null,
    detail: extra.detail ?? null,
  };
  const error = denyErrorForReason(reason);
  if (error) {
    const remedy = buildDenyRemedy({
      error,
      // The workload this admission was about — the cluster's own addressing.
      target: extra.target ?? null,
      fingerprint: extra.fingerprint ?? null,
      observed: extra.receiptStatus ? { receipt_status: extra.receiptStatus } : undefined,
    });
    if (remedy) out.remedy = remedy;
  }
  // TWO DIFFERENT NEXT STEPS, and they can co-occur. `remedy` is THIS GATE's refusal
  // class (the grant is missing / invalid / scoped elsewhere). `nextStep` is the
  // DECISION's, signed by the issuer. Only callers that already hold a verified
  // envelope pass `verifiedEnvelope`; every pre-verification refusal passes nothing,
  // so an unverified envelope can never reach this field.
  const nextStep = readNextAgentStep(extra.verifiedEnvelope);
  if (nextStep) out.nextStep = nextStep;
  return out;
}

function allow(extra = {}) {
  return {
    allowed: true,
    reason: 'signed_allow_for_workload',
    receiptStatus: extra.receiptStatus ?? null,
    detail: null,
  };
}

/**
 * @param {object} o
 * @param {object} o.object           admitted Kubernetes object (Pod or Deployment)
 * @param {Map}    o.keyring          pinned keyring (kid → { publicKey, status, … })
 * @param {string} [o.expectedOperation='deploy']
 * @param {number} [o.now]
 * @returns {{ allowed:boolean, reason:string, receiptStatus:(string|null), detail:(string|null) }}
 */
function evaluateAdmission({ object, keyring, expectedOperation = 'deploy', now } = {}) {
  if (!object || typeof object !== 'object') {
    return deny(REASON.RECEIPT_MISSING, { detail: 'no admitted object' });
  }

  const ann = annotationsOf(object);
  const rawReceipt = ann[ANNOTATION_RECEIPT];
  if (rawReceipt == null || String(rawReceipt).trim() === '') {
    return deny(REASON.RECEIPT_MISSING, { target: workloadIdentity(object) });
  }

  let receiptInput = String(rawReceipt).trim();
  try {
    const parsed = JSON.parse(receiptInput);
    if (parsed && typeof parsed === 'object') receiptInput = parsed;
  } catch (_) {
    // compact token — not JSON
  }

  const unwrapped = unwrapReceiptInput(receiptInput);
  if (!unwrapped.ok) {
    if (unwrapped.reason === 'missing_receipt') return deny(REASON.RECEIPT_MISSING, { target: workloadIdentity(object) });
    if (String(unwrapped.reason).startsWith('dsse_')) {
      return deny(REASON.DSSE_MALFORMED, { detail: unwrapped.detail || unwrapped.reason, target: workloadIdentity(object) });
    }
    return deny(REASON.RECEIPT_INVALID, { detail: unwrapped.reason, target: workloadIdentity(object) });
  }
  const token = unwrapped.token;
  if (typeof token !== 'string' || token.length === 0) {
    return deny(REASON.RECEIPT_MISSING, { target: workloadIdentity(object) });
  }

  const envelope = parseEnvelope(ann[ANNOTATION_ENVELOPE]);
  if (!envelope) {
    return deny(REASON.RECEIPT_INVALID, { detail: 'missing decision_result envelope annotation', target: workloadIdentity(object) });
  }

  let result;
  try {
    result = verifyReceipt(token, { ctx: { keyring, expectedKid: null }, envelope, now });
  } catch (err) {
    return deny(REASON.RECEIPT_INVALID, {
      target: workloadIdentity(object),
      detail: `verify_threw:${err && err.message ? err.message : 'unknown'}`,
    });
  }
  if (!result || result.valid !== true) {
    return deny(REASON.RECEIPT_INVALID, { receiptStatus: result ? result.status : null, target: workloadIdentity(object) });
  }

  const executionAction = boundSlot(envelope.execution_action);
  if (!executionAction || !PASSING_ACTIONS.has(executionAction)) {
    return deny(REASON.RECEIPT_INVALID, {
      target: workloadIdentity(object),
      receiptStatus: result.status,
      verifiedEnvelope: envelope,
      detail: `execution_action ${executionAction || 'missing'} is not CONTINUE/CONTINUE_WITH_MONITORING`,
    });
  }

  const wantOp = boundSlot(expectedOperation) || 'deploy';
  const gotOp = boundSlot(envelope.operation);
  const wantTarget = workloadIdentity(object);
  const gotTarget = boundSlot(envelope.target_id);
  const mode = boundSlot(envelope.preflight_mode);
  if (mode !== 'authorize') {
    return deny(REASON.SCOPE_MISMATCH, {
      target: workloadIdentity(object),
      receiptStatus: result.status,
      verifiedEnvelope: envelope,
      detail: `preflight_mode ${mode || 'missing'} is not authorize`,
    });
  }
  if (gotOp == null || gotOp !== wantOp) {
    return deny(REASON.SCOPE_MISMATCH, {
      target: workloadIdentity(object),
      receiptStatus: result.status,
      verifiedEnvelope: envelope,
      detail: `operation ${gotOp || 'missing'} does not match ${wantOp}`,
    });
  }
  if (wantTarget == null || gotTarget == null || gotTarget !== wantTarget) {
    return deny(REASON.SCOPE_MISMATCH, {
      target: workloadIdentity(object),
      receiptStatus: result.status,
      verifiedEnvelope: envelope,
      detail: `target_id ${gotTarget || 'missing'} does not match ${wantTarget || 'unbound-object'}`,
    });
  }

  return allow({ receiptStatus: result.status });
}

module.exports = {
  evaluateAdmission,
  readNextAgentStep,
  workloadIdentity,
  ANNOTATION_RECEIPT,
  ANNOTATION_ENVELOPE,
  PASSING_ACTIONS,
  REASON,
};
