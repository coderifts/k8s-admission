'use strict';
/**
 * crbundle.v1 acceptance for the deploy admission webhook (1261).
 *
 * SHARED SHAPE, NOT A VENDORED LIBRARY. This module is the same consumer contract the Contract
 * Gate uses (coderifts-contract-gate/src/bundle-gate.js), kept deliberately parallel so the two
 * verifiers grade a bundle the same way. What differs between them is REQUIRED_PROVEN_SLOTS —
 * see below — because a merge and a deploy rest on different evidence. It is NOT pinned in
 * VENDOR.sha256: the vendored files are receipt-verifier's, and this one is ours.
 *
 * ── THIS FILE GRADES NOTHING ITSELF ─────────────────────────────────────────────────────────
 *
 * Every slot verdict comes from the VENDORED `src/verify-bundle.js`, byte-identical to
 * receipt-verifier and pinned in `src/VENDOR.sha256`. Re-implementing the grading here would give
 * the gate a second opinion about what a bundle proves, and the whole value of a bundle is that
 * one library decides. What this file does is decide which slots THIS gate's operation needs, and
 * how to report the rest.
 *
 * ── THE TRAP THIS FILE EXISTS TO AVOID, MEASURED ────────────────────────────────────────────
 *
 * `SLOT.VERIFIED` does not mean "cryptographically proven". verify-bundle.js:313 sets a slot to
 * VERIFIED whenever its verifier returned `valid: true` — and `verifyProviderReadback`
 * (verify-bundle.js:129-133) returns exactly that for an UNSIGNED provider readback, with
 * `status: 'PROVIDER_READBACK'` and a `does_not_prove` line saying so. So a bundle whose
 * merge_evidence slot is a self-asserted JSON blob comes back VERIFIED.
 *
 * A gate that read `state === 'VERIFIED'` and stopped would therefore accept an unsigned claim as
 * proof. The class is carried in `status`, not in `state`, and this module keys on `status`.
 *
 * ── "MODELLED" IS NOT A CLASS HERE, AND IS NOT INVENTED ─────────────────────────────────────
 *
 * MEASURED 2026-09-02: `MODELLED` appears nowhere in receipt-verifier. It is the vocabulary of the
 * deploy-attestation end-to-end run, not of cr.bundle.v1. The classes a bundle actually returns
 * are the slot `status` values, so those are what this gate names. Reporting a class the library
 * does not produce would be a label with nothing behind it.
 */

const { verifyBundle, SLOT, BUNDLE } = require('./verify-bundle.js');

/**
 * Slot statuses that constitute CRYPTOGRAPHIC proof — a signature checked against a pinned key.
 * Deliberately an allow-list: a status this gate has not considered is not proof, and a new
 * status added upstream must be classified here on purpose rather than inherited silently.
 */
// MEASURED 2026-09-02 from the vendored verifiers, not guessed. A first draft of this list used
// plausible names (`GRANT_VALID`, `TOOLSET_VALID`) and every real bundle graded UNCLASSIFIED —
// which is the allow-list doing its job: an unrecognised status is refused, never waved through.
// The names below are the ones the five verifiers actually return alongside `valid: true`.
const PROVEN_STATUSES = Object.freeze([
  'VERIFIED_CURRENT',                          // verify.js:289
  'RETIRED_KEY_VALID_AT_ISSUE',                // verify.js:289 — signed while the key was live
  'GRANT_CURRENT',                             // verify-grant.js
  'ATTEST_VALID',                              // verify-attest.js
  'ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  'TOOLSET_ATTEST_VALID',                      // verify-toolset.js
  'TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  'ATOMIC_ATTEST_VALID',                       // verify-atomic-attestation.js
]);

/**
 * Statuses that are honest evidence and are NOT proof. Named in the output so a reader sees the
 * class rather than a bare pass.
 */
const UNPROVEN_ACCEPTED_STATUSES = Object.freeze(['PROVIDER_READBACK']);

/**
 * The slots a DEPLOY admission needs proven.
 *
 * WHY THESE TWO, AND WHY NOT deploy_attestation. Admission runs BEFORE the workload is created —
 * a deploy attestation attests to a deploy that has not happened yet, so requiring one here would
 * be requiring evidence that cannot exist at this moment. What can exist is the signed decision
 * and the permission bound to it, which is what a holder already annotates today.
 *
 * WHAT THE BUNDLE ADDS OVER THE EXISTING ANNOTATIONS, measured: admit.js verifies the RECEIPT and
 * nothing else — there is no grant verification on the annotation path at all. A bundle brings the
 * execution grant AND the library's `grant_binds_receipt` linkage check, so an operator who
 * annotates one gets a strictly stronger admission than the receipt-only path, not a parallel one.
 */
const REQUIRED_PROVEN_SLOTS = Object.freeze(['receipt', 'execution_grant']);

/** Slots this webhook reports when present but never requires and never counts as proof. */
const REPORTED_SLOTS = Object.freeze(['merge_evidence', 'commit_attestation', 'deploy_attestation']);

function classOf(slot) {
  if (!slot || slot.state === SLOT.ABSENT) return 'ABSENT';
  const status = typeof slot.status === 'string' ? slot.status : null;
  if (slot.state === SLOT.VERIFIED && status && PROVEN_STATUSES.includes(status)) return 'PROVEN';
  if (slot.state === SLOT.VERIFIED && status && UNPROVEN_ACCEPTED_STATUSES.includes(status)) return status;
  if (slot.state === SLOT.VERIFIED) {
    // VERIFIED under a status this gate does not classify. Not proof — see the allow-list note.
    return 'UNCLASSIFIED';
  }
  return 'INVALID';
}

/**
 * Grade a bundle for a merge.
 *
 * @param {object} bundle  a parsed cr.bundle.v1 document
 * @param {object} opts    forwarded UNCHANGED to verifyBundle — this module handles no key
 *                         material of its own, exactly as the library requires
 * @returns {{
 *   ok: boolean, reason: (string|null), bundleState: string,
 *   classes: Record<string,string>, proven: string[], reported: string[], summary: string
 * }}
 */
function evaluateBundle(bundle, opts = {}) {
  let graded;
  try {
    graded = verifyBundle(bundle, opts);
  } catch (err) {
    // The library throws on a green-empty result (verify-bundle.js:178). A throw is a refusal to
    // return a verdict, and it is reported as one rather than swallowed into a pass.
    return {
      ok: false,
      reason: 'bundle_verifier_threw',
      bundleState: null,
      classes: {},
      proven: [],
      reported: [],
      summary: `bundle verifier refused a verdict: ${String((err && err.message) || 'unknown').slice(0, 160)}`,
    };
  }

  const bySlot = new Map((graded.slots || []).map((s) => [s.slot, s]));
  const classes = {};
  for (const s of graded.slots || []) classes[s.slot] = classOf(s);

  if (graded.bundle === BUNDLE.INVALID) {
    // MEASURED: the library sets `reason` only for STRUCTURAL rejects (unknown_slot,
    // unsupported_version). When a slot fails to verify the bundle is INVALID with no reason at
    // all (verify-bundle.js:348, `invalid > 0`), so naming the offending slots is this module's
    // job — "INVALID (unspecified)" tells a holder nothing they can act on.
    const badSlots = (graded.slots || [])
      .filter((sl) => sl.state === SLOT.INVALID)
      .map((sl) => `${sl.slot}${sl.status ? ` (${sl.status})` : ''}`);
    const brokenLinks = (graded.linkage || [])
      .filter((l) => l.ok === false)
      .map((l) => `${l.link}: ${l.reason || 'failed'}`);
    const why = graded.reason
      ? graded.reason
      : [
        badSlots.length ? `invalid slots: ${badSlots.join(', ')}` : null,
        brokenLinks.length ? brokenLinks.join('; ') : null,
      ].filter(Boolean).join(' — ') || 'unspecified';
    return {
      ok: false,
      reason: `bundle_invalid:${graded.reason || 'slot_invalid'}`,
      bundleState: graded.bundle,
      classes,
      proven: [],
      reported: [],
      summary: `bundle is INVALID — ${why}. One failing slot invalidates the whole bundle, so `
        + 'nothing in it was accepted, including slots that verified on their own.',
    };
  }
  if (graded.bundle === BUNDLE.EMPTY) {
    return {
      ok: false,
      reason: 'bundle_empty',
      bundleState: graded.bundle,
      classes,
      proven: [],
      reported: [],
      summary: 'bundle carries no slots. An empty bundle is never green.',
    };
  }

  const missing = REQUIRED_PROVEN_SLOTS.filter((k) => classes[k] !== 'PROVEN');
  const proven = REQUIRED_PROVEN_SLOTS.filter((k) => classes[k] === 'PROVEN');
  const reported = REPORTED_SLOTS
    .filter((k) => bySlot.has(k) && classes[k] !== 'ABSENT')
    .map((k) => `${k}=${classes[k]}`);

  if (missing.length > 0) {
    const detail = missing.map((k) => {
      const s = bySlot.get(k);
      const why = classes[k] === 'ABSENT'
        ? 'absent'
        : `${classes[k]}${s && s.status ? ` (${s.status})` : ''}`;
      return `${k}: ${why}`;
    }).join('; ');
    return {
      ok: false,
      reason: 'bundle_slot_not_proven',
      bundleState: graded.bundle,
      classes,
      proven,
      reported,
      summary: `a merge needs ${REQUIRED_PROVEN_SLOTS.join(' + ')} PROVEN — ${detail}.`
        + (reported.length ? ` Other slots present: ${reported.join(', ')} (not proof).` : ''),
    };
  }

  return {
    ok: true,
    reason: null,
    bundleState: graded.bundle,
    classes,
    proven,
    reported,
    summary: `PROVEN: ${proven.join(', ')}.`
      + (reported.length
        ? ` Present but NOT proof: ${reported.join(', ')} — a PROVIDER_READBACK slot is an unsigned`
          + ' provider statement and is reported, never counted as proof.'
        : ''),
  };
}

module.exports = {
  evaluateBundle, classOf,
  PROVEN_STATUSES, UNPROVEN_ACCEPTED_STATUSES, REQUIRED_PROVEN_SLOTS, REPORTED_SLOTS,
};
