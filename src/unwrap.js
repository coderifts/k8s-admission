'use strict';

/**
 * Receipt-input boundary — MIRRORED from coderifts-contract-gate/src/from-dsse.js
 * unwrapReceiptInput. Unpacking uses the vendored receipt-verifier to-dsse.js
 * fromDSSE (byte-exact). Nothing here verifies a signature.
 */

const { fromDSSE, PAYLOAD_TYPE } = require('./to-dsse');

function looksLikeDSSE(input) {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    return input.payloadType === PAYLOAD_TYPE;
  }
  if (typeof input === 'string') {
    const t = input.trim();
    if (!t.startsWith('{')) return false;
    try {
      const parsed = JSON.parse(t);
      return !!parsed && typeof parsed === 'object' && parsed.payloadType === PAYLOAD_TYPE;
    } catch (_) {
      return false;
    }
  }
  return false;
}

/**
 * Accept a compact token OR a DSSE envelope (object or JSON text).
 * @returns {{ ok: true, token: string, form: 'compact'|'dsse' }
 *          |{ ok: false, reason: string, code: string, detail?: string }}
 */
function unwrapReceiptInput(input) {
  if (!looksLikeDSSE(input)) {
    if (typeof input === 'string' && input.length > 0) {
      return { ok: true, token: input, form: 'compact' };
    }
    return { ok: false, reason: 'missing_receipt', code: 'MALFORMED' };
  }
  const envelope = typeof input === 'string' ? JSON.parse(input) : input;
  try {
    return { ok: true, token: fromDSSE(envelope), form: 'dsse' };
  } catch (err) {
    return {
      ok: false,
      reason: `dsse_${String(err && err.code ? err.code : 'ERROR').toLowerCase()}`,
      code: (err && err.code) || 'ERROR',
      detail: err && err.message,
    };
  }
}

module.exports = { unwrapReceiptInput, looksLikeDSSE };
