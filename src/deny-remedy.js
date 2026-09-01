/**
 * deny-remedy.v1 — the machine-readable next step attached to a refusal.
 *
 * CANONICAL SCHEMA: capability-demo/docs/deny-remedy.v1.json
 *   sha256 3f51c5afd1708a9185075a4f19f6386ea7d63ad39b0104e31f0e4e887b6e167f
 *
 * This builder is copied byte-for-byte into every repo that emits a deny, and
 * must stay equivalent to that schema. It is a copy rather than a shared
 * package on purpose: these repos are installed independently and a shared
 * dependency would make one of them unable to refuse a request because another
 * failed to resolve.
 *
 * WHERE IT SITS IN THE FLOW. The remedy is attached AFTER a verdict is reached,
 * never inside verification. Nothing here reads a key, checks a signature, or
 * can change allow into deny. A surface that emits a remedy has already refused.
 *
 * WHAT IT REFUSES TO EMIT. Three error classes exist and no more. A refusal
 * whose reason does not map to one of them gets NO remedy — an unmapped reason
 * is a refusal we cannot yet describe as a next step, and inventing a fourth
 * class, or defaulting to the nearest one, would send a caller to a step that
 * does not address why they were refused.
 */
'use strict';

/** The closed set from the schema. */
const DENY_ERROR = Object.freeze({
  GRANT_REQUIRED: 'CODERIFTS_GRANT_REQUIRED',
  GRANT_INVALID: 'CODERIFTS_GRANT_INVALID',
  GRANT_MISMATCH: 'CODERIFTS_GRANT_MISMATCH',
});

/** Carried verbatim from the schema so it cannot be softened in rendering. */
const DOES_NOT_PROMISE = 'a grant does not guarantee execution (CAS may still fail)';

const ARGS_SHAPE = Object.freeze({
  artifacts: 'Array<{ id, type, before, after }> — the change set being authorized',
  context: '{ operation, environment?, repository?, branch?, pull_request? } — operation is required for authorize',
});

const FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * Build the remedy object, or return null when this refusal has no remedy.
 *
 * @param {string}  o.error        one of DENY_ERROR; anything else returns null
 * @param {string}  [o.target]     the surface's own addressing for what was refused
 * @param {string}  [o.fingerprint] the change-set fingerprint the deny was evaluated
 *                                 against, when the surface has one
 * @param {object}  [o.observed]   free-form, for an operator reading a log
 * @returns {object|null}
 */
function buildDenyRemedy({ error, target = null, fingerprint = null, observed = null } = {}) {
  if (!Object.values(DENY_ERROR).includes(error)) return null;

  const remedy = {
    error,
    // Null, never a wildcard: a surface that cannot name what it refused must
    // not emit a value a reader could take for "everything".
    target: typeof target === 'string' && target.length > 0 ? target : null,
    // Only a well-formed fingerprint. A malformed one is dropped rather than
    // passed through, because a caller comparing it would get a false mismatch.
    fingerprint: typeof fingerprint === 'string' && FINGERPRINT_RE.test(fingerprint)
      ? fingerprint
      : null,
    action_required: {
      tool: 'preflight_change_set',
      mode: 'authorize',
      args_shape: { ...ARGS_SHAPE },
    },
    does_not_promise: DOES_NOT_PROMISE,
  };
  if (observed && typeof observed === 'object') remedy.observed = observed;
  return remedy;
}

/**
 * Map a surface's own refusal reason to an error class.
 *
 * The mapping is explicit and closed. An unlisted reason returns null, which
 * means no remedy — see the note at the top of this file.
 */
function denyErrorForReason(reason) {
  switch (String(reason || '').toLowerCase()) {
    // Nothing was presented.
    case 'receipt_missing':
    case 'missing_receipt':
    case 'missing_grant_header':
    case 'decision_missing':
    case 'missing_decision_result':
    case 'no_preflight_response':
    case 'grant_not_supplied':
      return DENY_ERROR.GRANT_REQUIRED;

    // Something was presented and did not hold up.
    case 'receipt_invalid':
    case 'receipt_unverified':
    case 'invalid_signature':
    case 'unknown_key':
    case 'unknown_kid':
    case 'dsse_malformed':
    case 'dsse_unsupported':
    case 'dsse_predicate_mismatch':
    case 'malformed':
    case 'grant_malformed':
    case 'grant_unverified':
    case 'grant_expired':
      return DENY_ERROR.GRANT_INVALID;

    // It held up, but it is not about this request.
    case 'scope_mismatch':
    case 'target_mismatch':
    case 'operation_mismatch':
    case 'grant_scope_mismatch':
    case 'mode_mismatch':
    case 'repo_mismatch':
    case 'base_mismatch':
    case 'head_mismatch':
    case 'grant_does_not_cover_path':
    case 'grant_bound_elsewhere':
    case 'receipt_envelope_mismatch':
    case 'artifact_mismatch':
    case 'grant_unbound':
    case 'grant_wrong_audience':
      return DENY_ERROR.GRANT_MISMATCH;

    default:
      return null;
  }
}

module.exports = { buildDenyRemedy, denyErrorForReason, DENY_ERROR, DOES_NOT_PROMISE, ARGS_SHAPE };
