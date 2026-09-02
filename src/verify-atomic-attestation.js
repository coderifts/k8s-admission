#!/usr/bin/env node
'use strict';

/**
 * Public verifier for `cr.atomic.execution.attestation.v1` — the executor's seal.
 *
 * WHAT IT IS. An executor that mutates inside a transaction signs the exact canonical gate
 * preimage the gate returned, and seals that signature beside the ledger row. This library checks
 * that seal offline, against a key the CALLER pins. It never fetches anything.
 *
 * WHY IT IS A SEPARATE FILE. `verify-attest.js` speaks `cr.exec.attest.v1` — a different envelope
 * with a different signing input. A token of one kind handed to the other must not verify, so they
 * stay separate rather than growing a mode flag. `verify.js` (the vendored core) is untouched.
 *
 * ── ENVELOPE, measured from capability-demo demo/src/atomic.js:45-52 ─────────────────────────
 *
 *   cr.atomic.execution.attestation.v1|<executor_kid>|<base64url(preimage)>|<base64url(signature)>
 *
 * Four pipe segments, none empty. The signature is raw Ed25519 over the preimage's UTF-8 BYTES —
 * there is no signing prefix on this envelope, unlike `crexecattest.v1|…`. Reproducing that
 * exactly is the whole job: a verifier that hashed or prefixed the message would refuse every
 * genuine seal.
 *
 * ── PREIMAGE, measured from capability-demo demo/sql/gate.sql:146-148 ────────────────────────
 *
 *   cr.gate.preimage.v1|<jti>|<deployment_id>|sha256:<mutation_digest>|<target_id>
 *
 * The producer always emits all five fields; `deployment_id` is the empty string when absent, so
 * an empty field is a real value and not a missing one.
 *
 * ── WHAT A VALID SEAL PROVES, AND WHAT IT DOES NOT ──────────────────────────────────────────
 *
 * Proves: the holder of the named key signed THESE preimage bytes, and those bytes name this
 * grant, this deployment, this mutation digest and this target.
 *
 * Does NOT prove that the transaction committed. The seal is made inside the transaction; a crash
 * between signing and commit leaves a valid signature over a mutation that never landed. That is
 * the reconciler's question, not this library's, and no amount of signature checking answers it.
 */

const crypto = require('node:crypto');

const ATOMIC_ATTEST_V = 'cr.atomic.execution.attestation.v1';
const GATE_PREIMAGE_V = 'cr.gate.preimage.v1';

/** Field positions in the canonical gate preimage. */
const FIELD = Object.freeze({
  MAGIC: 0, JTI: 1, DEPLOYMENT_ID: 2, MUTATION_DIGEST: 3, TARGET_ID: 4,
});

/**
 * Refusal classes. Each names a DIFFERENT thing that went wrong, because collapsing them would
 * make "it did not verify" the only answer available to an operator.
 */
const STATUSES = Object.freeze({
  /** The envelope is not four non-empty segments of the right version, or the preimage is unreadable. */
  ATOMIC_ATTEST_MALFORMED: 'ATOMIC_ATTEST_MALFORMED',
  /** The named kid is not in the supplied registry, or no key was supplied at all. */
  ATOMIC_ATTEST_UNKNOWN_KEY: 'ATOMIC_ATTEST_UNKNOWN_KEY',
  /** The registry has the kid but has withdrawn it. A withdrawn key is never a pass. */
  ATOMIC_ATTEST_KEY_NOT_IN_FORCE: 'ATOMIC_ATTEST_KEY_NOT_IN_FORCE',
  /** The signature does not verify over these preimage bytes. */
  ATOMIC_ATTEST_INVALID_SIGNATURE: 'ATOMIC_ATTEST_INVALID_SIGNATURE',
  /** It verified, but the preimage describes a different grant/deployment/mutation/target. */
  ATOMIC_ATTEST_UNBOUND: 'ATOMIC_ATTEST_UNBOUND',
  /** Everything checked. */
  ATOMIC_ATTEST_VALID: 'ATOMIC_ATTEST_VALID',
});

const fail = (status, reason, extra = {}) => ({ valid: false, status, reason, ...extra });

/**
 * Resolve the executor key by kid. Same shape and same discipline as verify-attest.js:156 —
 * the real status is passed through, never normalised into 'active'.
 */
function resolveExecutorKey(registry, kid) {
  if (!registry || !Array.isArray(registry.keys) || typeof kid !== 'string' || !kid) return null;
  const matches = registry.keys.filter((k) => k && k.kid === kid && typeof k.public_key_pem === 'string');
  if (matches.length === 0) return null;
  const entry = matches.find((k) => k.status === 'active') || matches[0];
  try {
    return {
      publicKey: crypto.createPublicKey(entry.public_key_pem),
      status: entry.status || 'active',
      retired_at: entry.retired_at || null,
      revoked_at: entry.revoked_at || null,
    };
  } catch (_) {
    return null;
  }
}

/** Split the envelope. Returns { ok, ... } rather than throwing. */
function parseAtomicAttestToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: STATUSES.ATOMIC_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg[0] !== ATOMIC_ATTEST_V || seg.some((s) => !s)) {
    return { ok: false, status: STATUSES.ATOMIC_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  let preimage;
  try {
    preimage = Buffer.from(seg[2], 'base64url').toString('utf8');
  } catch (_) {
    return { ok: false, status: STATUSES.ATOMIC_ATTEST_MALFORMED, reason: 'bad_preimage' };
  }
  if (!preimage || preimage.split('|')[FIELD.MAGIC] !== GATE_PREIMAGE_V) {
    return { ok: false, status: STATUSES.ATOMIC_ATTEST_MALFORMED, reason: 'not_a_gate_preimage' };
  }
  return { ok: true, executor_kid: seg[1], preimage, signature: seg[3] };
}

/**
 * Verify a sealed execution attestation.
 *
 * @param {string} token
 * @param {object} opts
 * @param {object} [opts.registry]      customer-pinned { keys: [{ kid, public_key_pem, status }] }
 * @param {string} [opts.pinnedKeyPem]  air-gap single PEM; kid is then not resolved
 * @param {object} [opts.intended]      { jti, deployment_id, mutation_digest, target_id } — each
 *                                      checked ONLY when supplied. An absent expectation is not a
 *                                      silent pass of that field; it is a field nobody claimed.
 */
function verifyAtomicExecutionAttestation(token, opts = {}) {
  const parsed = parseAtomicAttestToken(token);
  if (!parsed.ok) return fail(parsed.status, parsed.reason);

  let publicKey = null;
  if (typeof opts.pinnedKeyPem === 'string' && opts.pinnedKeyPem.trim().length > 0) {
    try {
      publicKey = crypto.createPublicKey(opts.pinnedKeyPem);
    } catch (_) {
      return fail(STATUSES.ATOMIC_ATTEST_UNKNOWN_KEY, 'unusable_pinned_key');
    }
  } else {
    const entry = resolveExecutorKey(opts.registry, parsed.executor_kid);
    if (!entry) {
      return fail(STATUSES.ATOMIC_ATTEST_UNKNOWN_KEY, 'unknown_kid', { executor_kid: parsed.executor_kid });
    }
    // A withdrawn key never produces a pass, whatever the signature says.
    if (entry.revoked_at || entry.status === 'revoked') {
      return fail(STATUSES.ATOMIC_ATTEST_KEY_NOT_IN_FORCE, 'key_revoked', { executor_kid: parsed.executor_kid });
    }
    if (entry.status !== 'active' && entry.status !== 'retired') {
      return fail(STATUSES.ATOMIC_ATTEST_KEY_NOT_IN_FORCE, 'key_status_not_in_force', { key_status: entry.status });
    }
    publicKey = entry.publicKey;
  }

  let ok = false;
  try {
    // Raw Ed25519 over the preimage BYTES. No prefix, no hash — atomic.js:41-43.
    ok = crypto.verify(null, Buffer.from(parsed.preimage, 'utf8'), publicKey, Buffer.from(parsed.signature, 'base64url'));
  } catch (_) {
    return fail(STATUSES.ATOMIC_ATTEST_INVALID_SIGNATURE, 'signature_error');
  }
  if (!ok) return fail(STATUSES.ATOMIC_ATTEST_INVALID_SIGNATURE, 'signature_mismatch');

  const fields = parsed.preimage.split('|');
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : null;
  if (intended) {
    // Full-field equality, never a prefix match: a prefix comparison would accept a jti that
    // merely STARTS with the expected one.
    const checks = [
      ['jti', FIELD.JTI, 'grant_jti_mismatch'],
      ['deployment_id', FIELD.DEPLOYMENT_ID, 'deployment_id_mismatch'],
      ['mutation_digest', FIELD.MUTATION_DIGEST, 'mutation_digest_mismatch'],
      ['target_id', FIELD.TARGET_ID, 'target_id_mismatch'],
    ];
    for (const [key, idx, reason] of checks) {
      if (intended[key] === undefined || intended[key] === null) continue;
      const want = String(intended[key]);
      const got = fields[idx] === undefined ? '' : fields[idx];
      if (got !== want) {
        return fail(STATUSES.ATOMIC_ATTEST_UNBOUND, reason, { expected: want, observed: got });
      }
    }
  }

  return {
    valid: true,
    status: STATUSES.ATOMIC_ATTEST_VALID,
    reason: null,
    payload: {
      v: ATOMIC_ATTEST_V,
      executor_kid: parsed.executor_kid,
      preimage: parsed.preimage,
      signature: parsed.signature,
      fields: {
        jti: fields[FIELD.JTI] ?? null,
        deployment_id: fields[FIELD.DEPLOYMENT_ID] ?? null,
        mutation_digest: fields[FIELD.MUTATION_DIGEST] ?? null,
        target_id: fields[FIELD.TARGET_ID] ?? null,
      },
    },
    // Carried in the result so a consumer rendering a pass cannot omit it.
    does_not_prove: 'the transaction committed — the seal is made inside it, so a crash between '
      + 'signing and commit leaves a valid signature over a mutation that never landed',
  };
}

module.exports = {
  verifyAtomicExecutionAttestation,
  parseAtomicAttestToken,
  resolveExecutorKey,
  STATUSES,
  ATOMIC_ATTEST_V,
  GATE_PREIMAGE_V,
  FIELD,
};
