'use strict';

/**
 * cr.bundle.v1 — the end of the chain in one file, verifiable offline with one command.
 *
 * WHAT THIS IS. A container holding what a consumer already holds at the end of a run: a receipt,
 * an execution grant, and — when they exist — a commit attestation, a toolset declaration, and
 * provider evidence. It asserts what is IN it and NAMES what is not.
 *
 * COMPOSITION, NOT NEW CRYPTOGRAPHY, and this was measured rather than assumed. All four public
 * verifiers already share one contract — `(token, ctx, opts) → { valid, status, reason }`:
 *   verify.js          verifyReceipt
 *   verify-grant.js    verifyExecutionGrant
 *   verify-attest.js   verifyExecutionAttestation
 *   verify-toolset.js  verifyToolsetAttestation
 * This module calls them and checks the LINKAGE between what they returned. It defines no new
 * signing input, no new digest and no new key handling, so nothing already issued moves.
 *
 * ── HOW ABSENCE RENDERS, AND THE ALTERNATIVES REJECTED ──────────────────────────────────────
 *
 * Three slot states, never two:
 *   VERIFIED  present, and its own verifier said valid
 *   INVALID   present, and its own verifier said invalid — a real failure
 *   ABSENT    not in the bundle — a statement about SCOPE, not about validity
 *
 * REJECTED (a): absent counts as pass. Then an all-absent bundle is green, which is exactly the
 * `0/0` shape — a ratio that reads identically to a suite that ran and found nothing wrong. It is
 * the most dangerous option because it is also the most convenient one.
 *
 * REJECTED (b): absent counts as failure. Then an absent commit attestation is indistinguishable
 * from one that FAILED to verify, and a holder who never ran an executor reads a red bundle as
 * evidence something is broken. "We did not look" must never render as "we looked and it is wrong"
 * — the same rule this repository applies to a retired key and an unread registry.
 *
 * A GREEN ALL-ABSENT BUNDLE IS IMPOSSIBLE IN CODE, not by convention: `EMPTY` is a distinct
 * bundle verdict returned whenever no slot is present, and `assertNoGreenEmpty` throws rather than
 * letting a caller construct one. A convention would have been enough right up until the moment
 * it was not.
 *
 * ── THE HONEST LINE, which travels inside every result ──────────────────────────────────────
 * A complete bundle proves THE CHAIN WE MINTED IS INTERNALLY CONSISTENT AND INDEPENDENTLY
 * CHECKABLE. It does not prove the world changed, and it does not prove no other path wrote to
 * the target.
 */

const { verifyReceipt } = require('./verify.js');
const { verifyExecutionGrant, receiptDigest } = require('./verify-grant.js');
const { verifyExecutionAttestation } = require('./verify-attest.js');
const { verifyToolsetAttestation } = require('./verify-toolset.js');
const { split3ary } = require('./arity');

const BUNDLE_VERSION = 'cr.bundle.v1';

const SLOT = Object.freeze({
  VERIFIED: 'VERIFIED',
  INVALID: 'INVALID',
  ABSENT: 'ABSENT',
});

const BUNDLE = Object.freeze({
  VERIFIED: 'VERIFIED',
  INVALID: 'INVALID',
  /** Zero slots present. Never green — see the rejected alternatives above. */
  EMPTY: 'EMPTY',
});

const CEILING = 'A complete bundle proves the chain we minted is internally consistent and '
  + 'independently checkable. It does not prove the world changed, and it does not prove that no '
  + 'other path wrote to the target.';

/**
 * The slots, in chain order. Each names the verifier that owns it, so a reader can see that this
 * module decides nothing about validity itself.
 *
 * `executor: true` marks a slot no in-process holder can produce today. Its absence is EXPECTED
 * rather than a gap in the holder's setup, and the result says which kind of absence it is.
 */
const { verifyAtomicExecutionAttestation } = require('./verify-atomic-attestation.js');

/**
 * Grade a provider readback — CARRIED evidence, not a signature.
 *
 * WHAT THIS CAN HONESTLY ASSERT OFFLINE. Nothing about the provider. The document is unsigned, so
 * a holder who can write it can write any value in it, and no amount of checking here changes
 * that. What a structural check CAN do is refuse a document that does not even claim what it
 * would need to claim: a readback with no source binding, or no integration id, or no rollup
 * state, is not weak evidence — it is a document that never asserted the thing.
 *
 * The class is therefore PROVIDER_READBACK, distinct from a verified signature. A reader who sees
 * it must be able to tell, without reading this file, that nobody proved anything cryptographically.
 *
 * Shape from coderifts-app scripts/provider-readback.js:72-86.
 */
function verifyProviderReadback(evidence, opts = {}) {
  const e = typeof evidence === 'string'
    ? (() => { try { return JSON.parse(evidence); } catch (_) { return null; } })()
    : evidence;
  if (!e || typeof e !== 'object') {
    return { valid: false, status: 'READBACK_MALFORMED', reason: 'not_an_object' };
  }
  if (e.provider !== 'github') {
    return { valid: false, status: 'READBACK_MALFORMED', reason: 'unsupported_provider', observed: e.provider ?? null };
  }
  for (const field of ['required_check', 'rollup_state', 'observed_at']) {
    if (typeof e[field] !== 'string' || e[field].length === 0) {
      return { valid: false, status: 'READBACK_INCOMPLETE', reason: `missing_${field}` };
    }
  }
  // A name-only requirement is the case this evidence exists to distinguish. It is reported as
  // its own class rather than as a failure: the readback is honest, the BINDING is what is absent.
  if (e.bound_to_source !== true) {
    return {
      valid: false,
      status: 'READBACK_NOT_SOURCE_BOUND',
      reason: e.bound_to_source === false ? 'name_only_requirement' : 'binding_not_reported',
      required_check: e.required_check,
    };
  }
  if (!Number.isInteger(e.integration_id)) {
    return { valid: false, status: 'READBACK_INCOMPLETE', reason: 'missing_integration_id' };
  }
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : null;
  if (intended && intended.integration_id != null && intended.integration_id !== e.integration_id) {
    return {
      valid: false, status: 'READBACK_UNBOUND', reason: 'integration_id_mismatch',
      expected: intended.integration_id, observed: e.integration_id,
    };
  }
  return {
    valid: true,
    status: 'PROVIDER_READBACK',
    reason: null,
    payload: {
      provider: e.provider,
      required_check: e.required_check,
      integration_id: e.integration_id,
      rollup_state: e.rollup_state,
      observed_at: e.observed_at,
    },
    does_not_prove: 'anything the provider did not itself say — this document is UNSIGNED, so it '
      + 'attests that a readback was recorded, never that the recorded values are true',
  };
}

const SLOTS = Object.freeze([
  { key: 'receipt', verify: verifyReceipt, arity: 2, executor: false },
  { key: 'execution_grant', verify: verifyExecutionGrant, arity: 2, executor: false },
  { key: 'toolset_declaration', verify: verifyToolsetAttestation, arity: 2, executor: false },
  { key: 'commit_attestation', verify: verifyExecutionAttestation, arity: 2, executor: true },
  { key: 'nonce_commitment', verify: null, executor: true },
  // 1293 — PROVIDER READBACK, and it is deliberately NOT graded as a cryptographic pass.
  // The evidence is a JSON readback of what a repository host said about a required check. It
  // carries no signature: anyone able to write the file can write any value into it. Grading it
  // VERIFIED beside a checked signature would put a self-asserted document and an Ed25519 proof
  // in the same column, which is the overstatement this bundle exists to avoid.
  //
  // So it gets its own class, PROVIDER_READBACK: structurally checked, attributed to a provider
  // and a timestamp, and never counted as proof of anything the provider did not itself say.
  { key: 'merge_evidence', verify: verifyProviderReadback, arity: 2, executor: true, producer: true, carried: true },
  // 1293 — A PRODUCER EXISTS FOR THIS SLOT. capability-demo's executor mints
  // `cr.atomic.execution.attestation.v1` (demo/src/atomic.js) and binds it to the deployment id;
  // demo/e2e-chain.js verifies one against the executor key with a forgery negative control.
  // What does NOT exist is a PUBLIC verifier for that envelope — verify-attest.js speaks
  // `cr.exec.attest.v1`, a different message. Those are two different absences and this module
  // used to report them as one: `requires_executor` said "nobody can produce this", which stopped
  // being true. `producer: true` splits them, so a reader learns the gap is a verifier gap.
  // 1300 — THE VERIFIER GAP IS CLOSED. verify-atomic-attestation.js speaks
  // `cr.atomic.execution.attestation.v1` — the envelope the executor actually seals — so a token
  // placed here is now CHECKED rather than refused for want of a verifier. `executor: true`
  // stays: no in-process holder mints this, and an absent slot is still expected absence.
  { key: 'deploy_attestation', verify: verifyAtomicExecutionAttestation, arity: 2, executor: true, producer: true },
  { key: 'provider_evidence', verify: null, executor: true },
]);

const SLOT_KEYS = Object.freeze(SLOTS.map((s) => s.key));

/** Guard invoked before any result is returned. A green empty bundle is refused, not printed. */
function assertNoGreenEmpty(result) {
  const present = result.slots.filter((s) => s.state !== SLOT.ABSENT).length;
  if (present === 0 && result.bundle !== BUNDLE.EMPTY) {
    throw new Error(
      `verify-bundle: ${present} slots present but bundle is ${result.bundle} — refusing to return `
      + 'a verdict an empty bundle cannot support',
    );
  }
  if (result.bundle === BUNDLE.VERIFIED && result.verified_count === 0) {
    throw new Error('verify-bundle: VERIFIED with zero verified slots — refusing to return');
  }
  return result;
}

function slotResult(key, state, extra = {}) {
  return { slot: key, state, ...extra };
}

/**
 * @param {object} bundle  a cr.bundle.v1 document
 * @param {object} ctx     default verification context, forwarded to each slot verifier unchanged
 * @param {object} opts    default opts, forwarded unchanged — no key handling happens here
 *
 * PER-SLOT VERIFICATION MATERIAL, and this was a measurement rather than a guess. Building a
 * bundle from this repository's own vectors showed a receipt and a grant signed under DIFFERENT
 * kids with different registries — so one shared context cannot verify a real bundle. Pass
 * `opts.perSlot = { receipt: { ctx, opts }, execution_grant: { ctx, opts } }` to override per slot;
 * anything not overridden falls back to the defaults above. Per-slot ctx/opts take PRECEDENCE
 * over the base for that slot — including in the 2-ary unified form
 * `verifyBundle(bundle, { ctx, perSlot })`. The 3-ary form is a deprecated wrapper and is no
 * longer required for perSlot.
 *
 * THE KEYS NEVER COME FROM THE BUNDLE. A bundle carrying its own verification key would be
 * self-certifying, which is not verification. The caller supplies the material, exactly as every
 * other verifier in this repository requires.
 */
function verifyBundleInner(bundle, ctx = {}, opts = {}) {
  const perSlot = (opts && opts.perSlot) || {};
  if (!bundle || typeof bundle !== 'object') {
    return { bundle: BUNDLE.INVALID, reason: 'not_an_object', slots: [], verified_count: 0, ceiling: CEILING };
  }
  if (bundle.v !== BUNDLE_VERSION) {
    // Same discipline the grant verifier uses: an unknown version is UNSUPPORTED, not forged.
    return {
      bundle: BUNDLE.INVALID,
      reason: 'unsupported_version',
      declared: bundle.v == null ? null : String(bundle.v),
      slots: [],
      verified_count: 0,
      ceiling: CEILING,
    };
  }

  const given = (bundle.slots && typeof bundle.slots === 'object') ? bundle.slots : {};
  const unknown = Object.keys(given).filter((k) => !SLOT_KEYS.includes(k));
  if (unknown.length > 0) {
    // An unknown slot is a bundle we cannot fully grade. Ignoring it would let a holder attach a
    // slot this verifier never reads and present the result as complete.
    return {
      bundle: BUNDLE.INVALID,
      reason: 'unknown_slot',
      unknown,
      slots: [],
      verified_count: 0,
      ceiling: CEILING,
    };
  }

  const slots = [];
  for (const def of SLOTS) {
    const entry = given[def.key];
    const token = entry && typeof entry === 'object' ? entry.token : entry;
    if (token == null || token === '') {
      // THREE absences, not two. `requires_executor` conflated "nothing anywhere produces this"
      // with "something produces it, we just cannot check it here" — and a reader deciding
      // whether a gap is theirs to close needs to know which one they are looking at.
      const absentClass = def.producer
        ? 'no_public_verifier'
        : (def.executor ? 'requires_executor' : 'not_supplied');
      const absentNote = {
        no_public_verifier:
          'an executor CAN produce this slot, and does; what is missing is a public verifier for '
          + 'that envelope, so a token placed here would grade INVALID (NO_VERIFIER) rather than '
          + 'be checked. The gap is this repository\'s, not the holder\'s',
        requires_executor:
          'no in-process holder can produce this today; its absence is expected, not a defect',
        not_supplied: 'not supplied by the holder',
      }[absentClass];
      slots.push(slotResult(def.key, SLOT.ABSENT, {
        absent_class: absentClass,
        // Stated per slot so an absent commit attestation cannot be read as a failed one.
        note: absentNote,
      }));
      continue;
    }
    if (typeof def.verify !== 'function') {
      slots.push(slotResult(def.key, SLOT.INVALID, {
        status: 'NO_VERIFIER',
        reason: 'this slot has no public verifier yet; a token here cannot be checked offline',
      }));
      continue;
    }
    let r;
    const over = perSlot[def.key] || {};
    try {
      // ── 1128: THE VERIFIERS DO NOT SHARE AN ARITY, so the dispatch cannot either ──────────
      //
      // verifyReceipt and verifyExecutionGrant are (token, ctx, opts). verifyExecutionAttestation
      // and verifyToolsetAttestation are (token, opts). This dispatch used to pass three arguments
      // to all four; the 2-ary pair silently dropped the third, so per-slot material placed in
      // `opts` never reached them — and for the attestation that means the cross-check does not
      // run and a MISMATCHED artifact grades valid. verifyExecutionAttestation now throws on a
      // third argument, which is what surfaced this call site.
      //
      // `arity` is DECLARED rather than introspected: Function.length does not count parameters
      // with defaults, so verifyExecutionAttestation(token, opts = {}) reports 1 and
      // verifyToolsetAttestation(token, opts) reports 2 — the same shape, two different numbers.
      // Reading it would have been a guess dressed as a measurement.
      //
      // MERGE PRECEDENCE (1130-F2). The 2-ary unified form is
      //   verifyBundle(bundle, { ctx, perSlot })
      // split3ary then sets opts = that whole object, so opts.ctx is the BASE ctx.
      // Spreading baseOpts LAST used to overwrite over.ctx with that base ctx: a grant
      // whose key was supplied only via perSlot returned UNKNOWN_KEY. Per-slot is the
      // more specific value and MUST win. Keys never come from the bundle; perSlot
      // exists so the caller can supply the right key per slot in the non-deprecated form.
      const slotCtx = over.ctx != null ? over.ctx : (ctx || {});
      const mergedOpts = { ...(opts || {}), ...(over.opts || {}) };
      const restOpts = { ...mergedOpts };
      delete restOpts.perSlot;
      delete restOpts.ctx;
      r = def.verify(token, { ...restOpts, ...slotCtx, ctx: slotCtx });
    } catch (err) {
      r = { valid: false, status: 'VERIFIER_THREW', reason: String(err && err.message).slice(0, 120) };
    }
    slots.push(slotResult(def.key, r && r.valid === true ? SLOT.VERIFIED : SLOT.INVALID, {
      status: r && r.status,
      ...(r && r.reason ? { reason: r.reason } : {}),
    }));
  }

  // ── LINKAGE: the bundle is more than a container ──
  // A grant binds `receipt_digest`. If both are present and verified, the grant must bind THIS
  // receipt — otherwise the bundle holds two valid documents about different things.
  const linkage = [];
  const rec = given.receipt && (given.receipt.token || given.receipt);
  const grant = given.execution_grant && (given.execution_grant.token || given.execution_grant);
  const recOk = slots.find((s) => s.slot === 'receipt')?.state === SLOT.VERIFIED;
  const grantOk = slots.find((s) => s.slot === 'execution_grant')?.state === SLOT.VERIFIED;
  if (recOk && grantOk) {
    let bound = false;
    try {
      const payload = JSON.parse(Buffer.from(String(grant).split('.')[0], 'base64url').toString('utf8'));
      const digest = receiptDigest(rec);
      // v1 binds receipt_digest; v2 binds receipt_hash (same sha256 of the token).
      bound = payload.receipt_digest === digest || payload.receipt_hash === digest;
    } catch { bound = false; }
    linkage.push({
      link: 'grant_binds_receipt',
      ok: bound,
      ...(bound ? {} : { reason: 'the grant in this bundle does not bind the receipt in this bundle' }),
    });
  }

  const verified = slots.filter((s) => s.state === SLOT.VERIFIED).length;
  const invalid = slots.filter((s) => s.state === SLOT.INVALID).length;
  const brokenLink = linkage.some((l) => l.ok === false);

  let verdict;
  if (verified === 0) verdict = BUNDLE.EMPTY;
  else if (invalid > 0 || brokenLink) verdict = BUNDLE.INVALID;
  else verdict = BUNDLE.VERIFIED;

  return assertNoGreenEmpty({
    bundle: verdict,
    verified_count: verified,
    invalid_count: invalid,
    absent_count: slots.filter((s) => s.state === SLOT.ABSENT).length,
    slots,
    linkage,
    ceiling: CEILING,
  });
}

function verifyBundle(bundle, second, third) {
  const { ctx, opts } = split3ary('verifyBundle', arguments.length, second, third);
  return verifyBundleInner(bundle, ctx, opts);
}

module.exports = {
  verifyProviderReadback,
  verifyBundle, assertNoGreenEmpty, BUNDLE_VERSION, SLOT, BUNDLE, SLOTS, SLOT_KEYS, CEILING,
};

// ── CLI ────────────────────────────────────────────────────────────────────
//
// `node verify-bundle.js <bundle.json> --slot-keys <file>` — the offline end of the chain.
//
// NAME: this is NOT `coderifts verify-proof-bundle`. That spelling is the future APP-CLI verb
// (roadmap 1107) and lives in the coderifts package; nothing here provides it. What this file
// provides is the same thing every sibling verifier provides — a `node <file>.js` entry point.
//
// WHY --slot-keys AND NOT --keys, which is what the five siblings take. A bundle's slots are signed
// by DIFFERENT parties, and the four slot verifiers do not even take key material in the same
// shape: verifyReceipt and verifyExecutionGrant read `ctx.publicKey` / `ctx.expectedKid`, while
// verifyExecutionAttestation and verifyToolsetAttestation read `opts.registry`. A single --keys
// registry could only serve all four by inventing a mapping from one shape to the others, and a
// mapping invented here would be a second, undocumented contract that the library does not have.
//
// So this flag takes the `opts` object the library ALREADY documents (verify-bundle.js:118):
//   { "perSlot": { "receipt": { "ctx": {...}, "opts": {...} }, "execution_grant": { ... } } }
// passed through unchanged. The CLI adds no key handling of its own, which is why it cannot
// silently disagree with the library about what a slot was verified against.
const fs = require('node:fs');

const USAGE =
  'usage: node verify-bundle.js <bundle.json> --slot-keys <file> [--ctx <file>]\n'
  + '\n'
  + '--slot-keys is REQUIRED and is the library opts object, passed through unchanged:\n'
  + '  { "perSlot": { "<slot>": { "ctx": {...}, "opts": {...} } } }\n'
  + 'Slots are signed by different parties, so there is no single registry to default to and\n'
  + 'this verifier NEVER fetches one.\n'
  + '\n'
  + 'Exit 0 = VERIFIED, 1 = INVALID or EMPTY, 2 = usage or load error.\n';

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args[0].startsWith('-')) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  const bundleRef = args[0];
  let slotKeysRef = null;
  let ctxRef = null;
  for (let i = 1; i < args.length; i += 1) {
    if (args[i] === '--slot-keys') { slotKeysRef = args[i + 1]; i += 1; continue; }
    if (args[i] === '--ctx') { ctxRef = args[i + 1]; i += 1; continue; }
    process.stderr.write(USAGE);
    process.exit(2);
  }
  if (!slotKeysRef) {
    process.stderr.write('--slot-keys is required: this verifier NEVER fetches a default key registry.\n');
    process.exit(2);
  }

  let bundle;
  let opts;
  let ctx = {};
  try {
    bundle = JSON.parse(fs.readFileSync(bundleRef, 'utf8'));
    opts = JSON.parse(fs.readFileSync(slotKeysRef, 'utf8'));
    if (ctxRef) ctx = JSON.parse(fs.readFileSync(ctxRef, 'utf8'));
  } catch (err) {
    // A file we could not read or parse is a LOAD error (exit 2), never an INVALID bundle (exit 1).
    // Collapsing them would let a typo in a path read as a verdict about someone's proof.
    process.stderr.write(String((err && err.message) || err) + '\n');
    process.exit(2);
  }

  // 2-ary unified: perSlot now takes precedence over base ctx, so the CLI is
  // not forced onto the deprecated 3-ary path. --slot-keys is still the library
  // opts object, passed through; --ctx is the base ctx.
  const result = verifyBundle(bundle, { ...opts, ctx });
  process.stdout.write(JSON.stringify(result) + '\n');
  // NOT `result.valid` — this verifier has no such field; its verdict is `bundle`. EMPTY is never
  // green (assertNoGreenEmpty), so anything other than VERIFIED exits non-zero.
  process.exit(result.bundle === BUNDLE.VERIFIED ? 0 : 1);
}

if (require.main === module) {
  main(process.argv);
}
