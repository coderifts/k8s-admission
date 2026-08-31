'use strict';

/**
 * DSSE / in-toto EXPORT for a compact CodeRifts artifact (roadmap 1224, Phase 1).
 *
 * WHAT THIS IS. A packaging function. `toDSSE` wraps an already-signed compact
 * token in a DSSE envelope carrying an in-toto Statement, so a system that
 * speaks in-toto natively (SLSA tooling, policy engines, admission controllers)
 * can accept a CodeRifts attestation without learning our compact format.
 *
 * WHAT THIS IS NOT, and the distinction is the whole point:
 *   · NOT a second verification path. The signature in the envelope IS the
 *     compact token's signature, over the compact token's exact bytes. Nothing
 *     here re-signs, and nothing here validates a signature.
 *   · NOT a stronger claim. The envelope proves exactly what the compact
 *     receipt proves — the same checks, run by the same verifier, on the same
 *     bytes. A DSSE wrapper around a weak claim is a weak claim in a standard
 *     container.
 *   · NOT a replacement. The compact form stays primary; this is an export.
 *
 * ── HOW THE ROUND-TRIP STAYS BYTE-EXACT ─────────────────────────────────────
 * The predicate carries the ORIGINAL base64url payload segment verbatim, not a
 * re-serialisation of the decoded fields. Re-encoding JSON is not byte-stable
 * (key order, spacing), and a signature is over bytes rather than over meaning,
 * so a rebuilt payload would fail to verify for a reason that has nothing to do
 * with authenticity. `fromDSSE` reassembles the token from that preserved
 * segment and the signature, which is why verify() is unchanged by the trip.
 *
 * ── WHY THE DECODED FIELDS ARE ALSO CARRIED, AND WHAT GUARDS THEM ───────────
 * An in-toto consumer reads the predicate, not our base64. So the decoded
 * fields are included for it — and that creates a second copy of one fact.
 * `fromDSSE` therefore REFUSES an envelope whose decoded fields disagree with
 * the preserved segment. Without that check the readable half could say one
 * thing while the verifiable half said another, and the reader with no CodeRifts
 * verifier would believe the readable half.
 *
 * ── THE FIELDS ARE THE TOKEN'S OWN ──────────────────────────────────────────
 * The predicate carries the payload's fields VERBATIM, whatever the artifact
 * signed. It does not select from a curated list: a curated list is a place for
 * a field to be silently dropped, and for the export to describe an artifact
 * that is not the one in the envelope.
 *
 * MEASURED, and worth stating because the two are easy to confuse: for an
 * execution attestation the token's OWN signed fields are verify-attest.js
 * REQUIRED_FIELDS + OPTIONAL_STRINGS (executor_kid, grant_jti, receipt_digest,
 * scope_hash, committed_at, state_nonce?, result_digest?).  GRANT_SIGNED_FIELDS
 * (:43-45) is a different list — the fields of the GRANT the attestation
 * cross-checks — and putting it on an attestation's predicate would describe a
 * document the envelope does not contain.
 *
 * Phase 1 is this module. Publishing the predicate as an open spec, and the
 * multi-language verifiers for it, are later phases of 1224.
 */

const crypto = require('node:crypto');

const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const PREDICATE_TYPE = 'https://coderifts.com/attestations/agent-action-authorization/v1';

/** The compact forms this module can wrap, measured from their verifiers. */
const FORM = Object.freeze({
  /** verify.js — `<payload_b64url>.<sig_b64url>` (2 dot segments). */
  RECEIPT: 'crchain.v1',
  /** verify-attest.js — `<tag>|<kid>|<payload_b64url>|<sig_b64url>` (4 pipe segments). */
  ATTESTATION: 'cr.exec.attest.v1',
});

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const unb64 = (s) => Buffer.from(String(s), 'base64').toString('utf8');
const sha256hex = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

class DsseError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

/**
 * Split a compact token into its parts WITHOUT verifying it.
 *
 * Deliberately no verification: this module packages, and a packaging function
 * that also validated would invite a caller to treat `toDSSE` succeeding as
 * evidence the artifact is good. Verify with verify.js / verify-attest.js.
 */
function parseCompact(token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new DsseError('toDSSE: token must be a non-empty string', 'MALFORMED');
  }
  const pipe = token.split('|');
  if (pipe.length === 4 && pipe.every(Boolean)) {
    if (pipe[0] !== FORM.ATTESTATION) {
      throw new DsseError(`toDSSE: unsupported envelope tag ${JSON.stringify(pipe[0])}`, 'UNSUPPORTED');
    }
    return { form: FORM.ATTESTATION, tag: pipe[0], kid: pipe[1], encoded: pipe[2], sig: pipe[3] };
  }
  const dot = token.split('.');
  if (dot.length === 2 && dot.every(Boolean)) {
    return { form: FORM.RECEIPT, tag: null, kid: null, encoded: dot[0], sig: dot[1] };
  }
  throw new DsseError('toDSSE: not a compact CodeRifts receipt or attestation', 'MALFORMED');
}

function decodePayload(encoded) {
  let obj;
  try {
    obj = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch (_) {
    throw new DsseError('toDSSE: payload segment is not base64url JSON', 'MALFORMED');
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DsseError('toDSSE: payload is not a JSON object', 'MALFORMED');
  }
  return obj;
}

/**
 * Wrap a compact token in a DSSE envelope.
 *
 * @param {string} token   a compact CodeRifts receipt or execution attestation
 * @param {object} [opts]
 * @param {string} [opts.subjectName]  in-toto subject name; defaults to the form
 * @returns {object} a DSSE envelope
 */
function toDSSE(token, opts = {}) {
  const parts = parseCompact(token);
  const fields = decodePayload(parts.encoded);

  // The keyid is the artifact's own kid. For the receipt form it lives in the
  // payload; for the attestation form the envelope carries it in segment 2 and
  // the payload repeats it. Preferring the envelope's copy for the attestation
  // matches what its verifier resolves the key by.
  const keyid = parts.kid || (typeof fields.kid === 'string' ? fields.kid : '')
    || (typeof fields.executor_kid === 'string' ? fields.executor_kid : '');

  const statement = {
    _type: STATEMENT_TYPE,
    subject: [{
      name: opts.subjectName || parts.form,
      // The subject is the COMPACT TOKEN itself: that is the artifact this
      // envelope is about, and its digest is what a consumer can pin.
      digest: { sha256: sha256hex(token) },
    }],
    predicateType: PREDICATE_TYPE,
    predicate: {
      // Everything needed to reassemble the exact signed bytes.
      compact: {
        form: parts.form,
        ...(parts.tag ? { tag: parts.tag } : {}),
        ...(parts.kid ? { kid: parts.kid } : {}),
        encoded_payload: parts.encoded,
      },
      // The payload's own fields, verbatim. Not a curated list.
      fields,
      proves: 'exactly what the compact CodeRifts artifact proves — this envelope '
        + 'is packaging, and the signature below is the artifact\'s own, over its own bytes.',
      does_not_prove: [
        'that anything was re-verified: no signature is checked while building or reading this envelope',
        'anything the compact artifact does not already establish — a standard container does not strengthen a claim',
      ],
      verify_with: 'reassemble the compact token (fromDSSE) and run the CodeRifts verifier '
        + '(verify.js verifyReceipt / verify-attest.js verifyExecutionAttestation).',
    },
  };

  return {
    payloadType: PAYLOAD_TYPE,
    payload: b64(JSON.stringify(statement)),
    signatures: [{ keyid, sig: parts.sig }],
  };
}

/**
 * Reassemble the compact token from a DSSE envelope.
 *
 * REFUSES rather than guesses. Every refusal below is a case where returning a
 * token anyway would hand the caller bytes that do not correspond to the
 * envelope they read.
 */
function fromDSSE(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw new DsseError('fromDSSE: envelope must be an object', 'MALFORMED');
  }
  if (envelope.payloadType !== PAYLOAD_TYPE) {
    throw new DsseError(
      `fromDSSE: unsupported payloadType ${JSON.stringify(envelope.payloadType)}`, 'UNSUPPORTED',
    );
  }
  let statement;
  try {
    statement = JSON.parse(unb64(envelope.payload));
  } catch (_) {
    throw new DsseError('fromDSSE: payload is not base64 JSON', 'MALFORMED');
  }
  if (!statement || statement.predicateType !== PREDICATE_TYPE) {
    throw new DsseError(
      `fromDSSE: unsupported predicateType ${JSON.stringify(statement && statement.predicateType)}`,
      'UNSUPPORTED',
    );
  }
  const p = statement.predicate || {};
  const c = p.compact || {};
  const sigs = Array.isArray(envelope.signatures) ? envelope.signatures : [];
  if (sigs.length !== 1 || !sigs[0] || typeof sigs[0].sig !== 'string' || !sigs[0].sig) {
    throw new DsseError('fromDSSE: exactly one signature with a sig is required', 'MALFORMED');
  }
  if (typeof c.encoded_payload !== 'string' || !c.encoded_payload) {
    throw new DsseError('fromDSSE: predicate.compact.encoded_payload missing', 'MALFORMED');
  }

  // THE INTERNAL-CONSISTENCY CHECK. The predicate carries the payload twice —
  // once as the preserved bytes, once decoded for an in-toto reader. If they
  // disagree, the readable half is describing something the verifiable half
  // does not contain, and a consumer without a CodeRifts verifier would believe
  // the readable half. Refuse instead.
  let decoded;
  try {
    decoded = decodePayload(c.encoded_payload);
  } catch (err) {
    throw new DsseError(`fromDSSE: ${err.message}`, 'MALFORMED');
  }
  if (JSON.stringify(sortDeep(decoded)) !== JSON.stringify(sortDeep(p.fields || {}))) {
    throw new DsseError(
      'fromDSSE: predicate.fields does not match predicate.compact.encoded_payload — '
      + 'the readable half of this envelope disagrees with the signed half',
      'PREDICATE_MISMATCH',
    );
  }

  const sig = sigs[0].sig;
  if (c.form === FORM.ATTESTATION) {
    if (!c.tag || !c.kid) {
      throw new DsseError('fromDSSE: attestation form needs compact.tag and compact.kid', 'MALFORMED');
    }
    return [c.tag, c.kid, c.encoded_payload, sig].join('|');
  }
  if (c.form === FORM.RECEIPT) {
    return `${c.encoded_payload}.${sig}`;
  }
  throw new DsseError(`fromDSSE: unknown compact form ${JSON.stringify(c.form)}`, 'UNSUPPORTED');
}

/** Stable key order for the consistency comparison. Arrays keep their order. */
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortDeep(v[k]); return acc; }, {});
  }
  return v;
}

module.exports = {
  toDSSE,
  fromDSSE,
  DsseError,
  PAYLOAD_TYPE,
  STATEMENT_TYPE,
  PREDICATE_TYPE,
  FORM,
};
