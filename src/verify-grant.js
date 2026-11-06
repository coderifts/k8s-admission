#!/usr/bin/env node
'use strict';

/*
 * CodeRifts cr.exec.v1 execution-grant verifier -- Node >= 20, zero dependencies
 * (node:crypto only). Sibling of verify.js; a user who knows verify.js should
 * feel at home.
 *
 * Usage:
 *   node verify-grant.js <grant> --keys <url|file>
 *        [--intended-operation X --intended-target Y --intended-audience Z]
 *        [--intended-after-file PATH | --intended-scope-hash sha256:…]
 *        [--receipt <token>]
 *   node verify-grant.js <grant> --key pub.pem [--kid <kid>]   # offline pin
 *        [--intended-executor E --intended-adapter A --intended-environment ENV]
 *        [--as-of <ISO>] [--json]
 *   coderifts-receipt-verifier grant <grant> …                  # the same command, npm bin
 *
 * Key discovery: --keys resolves by kid from a registry
 *   ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }).
 * --key pins a single SPKI PEM (same as verify.js). --key and --keys are
 * mutually exclusive. With neither (1.1.7), the pinned snapshot keys/coderifts-keys.json,
 * offline; --fetch [url] is the opt-in network path
 *   (default https://app.coderifts.com/api/v1/attestation/public-key).
 *
 * Output: JSON { valid, status, reason?, payload?, verified_with?, keyring? } to stdout —
 * byte-identical to verify_grant.py, except --as-of (JS only).
 * Exit codes: 0 GRANT_CURRENT (with --as-of: valid_at_as_of), 1 otherwise, 2 usage error.
 *
 * Retired kid → UNKNOWN_KEY. Grants are live execution permission; receipts
 * may forensically verify a retired key inside [valid_from, retired_at),
 * grants must not (see coderifts-app/docs/cr-exec-v1.md).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  loadKeyring,
  keyFromPem,
  sha256hex,
  canonicalJson,
  CLOCK_SKEW_LEEWAY_MS,
  isExpiredAt,
  expiryLeewayMs,
  parseAsOf,
  parseJsonStrict,
} = require('./verify.js');
const { split3ary } = require('./arity');

const GRANT_VERSION = 'cr.exec.v1';
const GRANT_VERSION_V2 = 'cr.exec.v2';
const SIGNING_PREFIX = 'crexec.v1';
const SIGNING_PREFIX_V2 = 'crexec.v2';
// US (Unit Separator, 0x1F). Named for the byte it holds — it is NOT US, which is 0x00.
// The old name mirrored the server's, and that misnomer is what let RECEIPT_FORMAT.md §2.0
// give this separator for the single-spec preimage, which actually uses 0x00 — see the
// corrections note in that section. Renamed in coderifts-app 90c39cc; this mirror follows.
const US = '\x1f';
const SIGNED_FIELDS = Object.freeze([
  'kid', 'receipt_digest', 'scope_hash', 'audience', 'operation', 'target_id', 'jti', 'iat', 'exp',
]);
const V2_REQUIRED_STRINGS = Object.freeze([
  'v', 'kid', 'grant_id', 'receipt_hash', 'tenant_id', 'executor_id', 'adapter_id',
  'operation', 'target_uri', 'expected_state_token', 'after_payload_hash',
  'nonce_hash', 'policy_hash', 'audience_hash', 'not_before', 'expires_at',
]);
/**
 * RESERVED, AND INERT. Optional v2 fields a grant MAY carry and this verifier reads as NOTHING.
 *
 * ── WHY THEY EXIST BEFORE THE GATE THAT USES THEM ───────────────────────────────────────────
 *
 * The admitted key set is closed: an unknown field is `MALFORMED/unknown_field`, which is the
 * right default and also means a future field cannot be introduced without every deployed
 * verifier refusing the grants that carry it. Reserving the names now is what keeps that
 * introduction from being a breaking change later.
 *
 * ── WHAT THEY DO NOT DO, WHICH IS THE POINT ─────────────────────────────────────────────────
 *
 * NOTHING. A grant carrying `call_hash` is graded EXACTLY as one without it. There is no check,
 * no comparison, and no `intended` field they bind to. Same for `applied_policy_hash` (1942):
 * admitted so a later producer can emit it without every deployed verifier going MALFORMED.
 * This verifier does not read it as the evaluated policy, does not compare it to `policy_hash`,
 * and does not fail a grant that omits it.
 *
 * A VERIFIER THAT READS THEIR PRESENCE AS AUTHORIZATION IS WRONG. `call_hash` present does not
 * mean a tool call was bound; `executor_image_digest` present does not mean an executor image was
 * pinned; `applied_policy_hash` present does not mean the evaluator's policy was bound. Nothing
 * signs a promise that the value is true, nothing compares it to anything, and an
 * attacker who can mint a grant can put any value in them. Presence is not proof — it is a slot.
 *
 * They are unsigned-by-default only in the sense that no separate signature covers them: the v2
 * signing input is the canonical JSON of the WHOLE body, so a grant that carries them signs
 * different bytes than one that does not, and neither can be edited into the other. That binds
 * the VALUE to the issuer; it says nothing about whether the value means anything.
 *
 * When a gate for them lands it will be a NEW check with its own negative fixtures, and this
 * comment is what a reader should be shown if anyone claims otherwise before then.
 */
const V2_RESERVED_INERT = Object.freeze(['call_hash', 'executor_image_digest', 'applied_policy_hash']);
/**
 * 1.1.7 (2026-10-31) — `environment`: an OPTIONAL v2 field that IS checked, unlike the reserved ones.
 *
 * MEASURED: the app issuer adds it when the decision names one (coderifts-app
 * src/verdict-core/execution-grant-v2.js) and this verifier read such a grant as MALFORMED /
 * unknown_field. It is signed like every v2 field (the preimage is the canonical JSON of the whole
 * body). Present → a non-empty string, else MALFORMED / bad_environment. Compared only when the
 * caller states an intended environment (--intended-environment), and then an ABSENT environment is
 * a mismatch too: a grant that names no environment is not bound to the one the caller is in.
 */
const V2_OPTIONAL_SIGNED_STRINGS = Object.freeze(['environment']);
const TARGET_SCHEMES = Object.freeze(['fs', 'git', 'api', 'db', 'registry', 'deploy']);
const DEFAULT_FETCH_URL = 'https://app.coderifts.com/api/v1/attestation/public-key';
/** 1.1.7: the CLI default with no --key / --keys / --fetch — the pinned snapshot cli.js uses for receipts. */
const VENDORED_KEYS_PATH = path.join(__dirname, 'keys', 'coderifts-keys.json');

function isIssuedInFuture(issuedAtMs, nowMs, context) {
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(nowMs)) return false;
  return issuedAtMs > (nowMs + expiryLeewayMs(context));
}

function scalar(v) {
  return v == null ? '' : String(v);
}

/**
 * cr.exec.v1 OPTIONAL signed fields — the ATOMIC profile's, and a DELIBERATE widening (1470).
 *
 * ── MEASURED BEFORE OPENING THE SET ─────────────────────────────────────────────────────────
 *
 * This verifier's allowed set was `['v', ...SIGNED_FIELDS]`, so a v1 grant carrying `state_nonce`
 * read MALFORMED / unknown_field. That grant is not malformed: it is what the demo executor issues
 * for the ATOMIC profile, and capability-demo's middleware has always signed and accepted it
 * (OPTIONAL_SIGNED_FIELDS = ['state_nonce', 'deployment_id']). Fail-CLOSED, and wrong — this core
 * is vendored into five consumers, so every one of them refused a valid ATOMIC grant.
 *
 * ── WHY WIDENING IS SAFE HERE, AND WHY IT IS STILL A DECISION ───────────────────────────────
 *
 * These fields are SIGNED: appended to the preimage, so a forger cannot add one without breaking
 * the signature. The closed set never protected against injection; it protects against SEMANTIC
 * DRIFT — a future field that RESTRICTS use must not be silently ignored by an older verifier that
 * then says GRANT_CURRENT. `state_nonce` and `deployment_id` do not restrict: they NARROW, and a
 * verifier that ignores them is not more permissive than one that does not know them.
 *
 * So the set is widened BY NAME, not opened. An actually-unknown field is still unknown_field, and
 * test/v1-atomic-optional-fields.test.js records both halves so the next change is a decision
 * rather than a rediscovery.
 *
 * ── APPENDED ONLY WHEN NON-EMPTY ────────────────────────────────────────────────────────────
 *
 * Byte-identical to capability-demo/packages/middleware/src/verify-grant.js. A BEARER grant's
 * signing input must stay exactly what it was before ATOMIC existed, or every pre-ATOMIC issuance
 * stops verifying — which is why presence, not declaration, decides the slot.
 */
const V1_OPTIONAL_SIGNED_FIELDS = Object.freeze(['state_nonce', 'deployment_id']);

function reconstructSignedInput(payload) {
  const parts = [
    SIGNING_PREFIX,
    scalar(payload.kid),
    scalar(payload.receipt_digest),
    scalar(payload.scope_hash),
    scalar(payload.audience),
    scalar(payload.operation),
    scalar(payload.target_id),
    scalar(payload.jti),
    scalar(payload.iat),
    scalar(payload.exp),
  ];
  for (const k of V1_OPTIONAL_SIGNED_FIELDS) {
    if (payload[k] != null && String(payload[k]).length > 0) parts.push(String(payload[k]));
  }
  return parts.join('|');
}

function sha256pref(s) {
  return `sha256:${sha256hex(String(s))}`;
}

function canonicalizeTargetUri(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  const m = raw.match(/^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^?#]*)$/);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  if (!TARGET_SCHEMES.includes(scheme)) return null;
  let rest = m[2];
  if (/^[^\s/]*:/.test(rest) && rest.includes('@') && scheme !== 'git') return null;
  if (rest.includes('..') || rest.includes('//') || /\s/.test(rest)) return null;
  if (rest.endsWith('/') && rest.length > 1) rest = rest.replace(/\/+$/, '');
  return `${scheme}://${rest}`;
}

function signingInputV2(body) {
  return `${SIGNING_PREFIX_V2}|${canonicalJson(body)}`;
}

function computeScopeHash({ operation, target_id, after_payload }) {
  const preimage = [
    operation == null ? '' : String(operation),
    target_id == null ? '' : String(target_id),
    after_payload == null ? '' : String(after_payload),
  ].join(US);
  return `sha256:${sha256hex(preimage)}`;
}

function receiptDigest(token) {
  return `sha256:${sha256hex(String(token))}`;
}

/**
 * 1.1.7 — a retired key under --as-of. Without as-of a retired kid is always UNKNOWN_KEY (a grant is
 * live permission). With as-of the question is "was this grant usable at that instant", and a key
 * still active then could sign one: allowed only when the grant's start AND the as-of instant are both
 * before retired_at. A retired entry without a parseable retired_at stays refused.
 */
function retiredKeyActiveAt(entry, issuedRaw, asOfMs) {
  const retired = typeof entry.retired_at === 'string' ? Date.parse(entry.retired_at) : NaN;
  const issued = typeof issuedRaw === 'string' ? Date.parse(issuedRaw) : NaN;
  return Number.isFinite(retired) && Number.isFinite(issued) && Number.isFinite(asOfMs)
    && issued < retired && asOfMs < retired;
}

function hasRevokedAt(entry) {
  return typeof entry.revoked_at === 'string' && entry.revoked_at.length > 0;
}

function resolveEntry(ctx, payload) {
  if (ctx.keyring) {
    const entry = ctx.keyring.get(payload.kid);
    if (!entry) return null;
    if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
    return entry;
  }
  if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
  return { publicKey: ctx.publicKey, status: null, retired_at: null, compromised_at: null };
}

/**
 * cr.exec.v2 — JSON-canonical preimage, exact executor/adapter/target/audience bind.
 */
function verifyExecutionGrantV2(payload, sigB64, ctx, opts = {}) {
  for (const k of V2_REQUIRED_STRINGS) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { valid: false, status: 'MALFORMED', reason: 'missing_field', payload };
    }
  }
  if (!Number.isInteger(payload.max_attempts) || payload.max_attempts < 1) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_max_attempts', payload };
  }
  // The reserved names are ADMITTED, never inspected. Everything below this line treats a payload
  // carrying them identically to one that does not — verified by test, not by intent.
  const allowed = new Set([...V2_REQUIRED_STRINGS, 'max_attempts', ...V2_RESERVED_INERT, ...V2_OPTIONAL_SIGNED_STRINGS]);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) return { valid: false, status: 'MALFORMED', reason: 'unknown_field', payload };
  }
  if ('environment' in payload && (typeof payload.environment !== 'string' || payload.environment.length === 0)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_environment', payload };
  }
  if (!canonicalizeTargetUri(payload.target_uri)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_target_uri', payload };
  }

  const entry = resolveEntry(ctx, payload);
  if (!entry) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  // Addendum 1.1.7: a revoked_at refuses at every instant, whatever `status` says (RECEIPT_FORMAT §7.1),
  // and before the retired rule — a retired entry that also carries revoked_at is revoked, not retired.
  if (entry.status === 'revoked' || hasRevokedAt(entry)) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'revoked_kid', payload };
  }
  const auditing = Number.isFinite(opts.auditAsOfMs);
  if (entry.status === 'retired' && !(auditing && retiredKeyActiveAt(entry, payload.not_before, opts.auditAsOfMs))) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'retired_kid', payload };
  }
  // Addendum 1.1.7: an unknown status fails closed, as v1 always did (it was GRANT_CURRENT here).
  if (entry.status != null && entry.status !== 'active' && entry.status !== 'retired') {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_key_status', payload };
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      Buffer.from(signingInputV2(payload), 'utf8'),
      entry.publicKey,
      Buffer.from(sigB64, 'base64url'),
    );
  } catch (_) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_error', payload };
  }
  if (!ok) return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_mismatch', payload };

  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const expMs = Date.parse(payload.expires_at);
  const nbfMs = Date.parse(payload.not_before);
  if (!Number.isFinite(expMs) || !Number.isFinite(nbfMs)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_timestamp', payload };
  }
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : {};
  if (isExpiredAt(expMs, now, intended)) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'expired', payload };
  }
  if (isIssuedInFuture(nbfMs, now, intended)) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'nbf_in_future', payload };
  }

  // 1.1.8: a stated intended value is checked whether or not it is truthy — "given" is the question, not
  // "non-empty" (a library caller passing "" gets a mismatch, never a skipped binding). v1 below keeps its
  // documented reading of "" as not stated.
  if (intended.executor_id != null && payload.executor_id !== String(intended.executor_id)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'executor_mismatch', payload };
  }
  if (intended.adapter_id != null && payload.adapter_id !== String(intended.adapter_id)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'adapter_mismatch', payload };
  }
  if (intended.target_uri != null) {
    const want = canonicalizeTargetUri(String(intended.target_uri)) || String(intended.target_uri);
    if (payload.target_uri !== want) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'target_mismatch', payload };
    }
  }
  if (intended.audience != null) {
    if (payload.audience_hash !== sha256pref(intended.audience)) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'audience_mismatch', payload };
    }
  }
  if (intended.audience_hash != null && payload.audience_hash !== String(intended.audience_hash)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'audience_mismatch', payload };
  }
  if (intended.after_payload != null) {
    if (payload.after_payload_hash !== sha256pref(intended.after_payload)) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'after_payload_mismatch', payload };
    }
  }
  if (intended.operation != null && payload.operation !== String(intended.operation)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'operation_mismatch', payload };
  }
  if (intended.environment != null && payload.environment !== String(intended.environment)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'environment_mismatch', payload };
  }
  if (intended.receipt_token != null) {
    if (sha256pref(intended.receipt_token) !== payload.receipt_hash) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'receipt_hash_mismatch', payload };
    }
  }
  return { valid: true, status: 'GRANT_CURRENT', payload };
}

/**
 * Verify a cr.exec.v1 or cr.exec.v2 grant. 10-step algorithm from docs/cr-exec-v1.md for v1.
 * @param {string} token
 * @param {{ publicKey?: import('crypto').KeyObject, keyring?: Map, expectedKid: (string|null) }} ctx
 * @param {{ intended?: object, now?: number }} [opts]
 * @returns {{ valid: boolean, status: string, reason?: string, payload?: object }}
 */
function verifyExecutionGrantInner(token, ctx, opts = {}) {
  if (opts && opts.asOf != null) return auditGrant(token, ctx, opts);
  return verifyGrantAt(token, ctx, opts);
}

/**
 * 1.1.7 (2026-10-31) — `asOf` for grants: "was this grant inside its window at a stated instant?".
 *
 * The receipt rule of 1.1.6 (verify.js auditResult), with one deliberate difference. The core runs
 * unchanged with now = asOf: signature, key lookup, every binding check. Key rules: revoked fails at
 * any instant; a retired key passes only if it was still active at not_before AND at asOf
 * (retiredKeyActiveAt). Only a verdict the core reached is re-labelled:
 *   GRANT_CURRENT at asOf            → GRANT_CURRENT_AT_AS_OF, valid_at_as_of true
 *   GRANT_EXPIRED expired at asOf    → GRANT_EXPIRED, valid_at_as_of false, expired_now
 *   not yet valid at asOf            → GRANT_NOT_YET_VALID_AT_AS_OF
 * THE DIFFERENCE: `valid` is false on every audit verdict. A receipt is evidence; a grant is live
 * permission, and a caller that reads `valid` must never get a yes to "may I execute now" from an
 * answer about another instant. The audit answer is valid_at_as_of (and the CLI exit code).
 * asOf later than now + 30s throws (as_of_in_future), as for receipts.
 */
const GRANT_AS_OF_DOES_NOT_PROVE = 'that the grant may be used now: as-of evaluates a stated instant, so this is not '
  + 'permission to execute now (valid stays false); verify without --as-of before executing';

function auditGrant(token, ctx, opts) {
  const nowMs = Number.isFinite(opts.now) ? opts.now : Date.now();
  const asOfMs = parseAsOf(opts.asOf, nowMs);
  const r = verifyGrantAt(token, ctx, { ...opts, now: asOfMs, auditAsOfMs: asOfMs });
  const p = r.payload && typeof r.payload === 'object' ? r.payload : null;
  const v2 = p && p.v === GRANT_VERSION_V2;
  const window = {
    not_before: p ? ((v2 ? p.not_before : p.iat) ?? null) : null,
    expires_at: p ? ((v2 ? p.expires_at : p.exp) ?? null) : null,
  };
  const expMs = typeof window.expires_at === 'string' ? Date.parse(window.expires_at) : NaN;
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : {};
  const base = {
    ...r, valid: false, mode: 'audit', as_of: new Date(asOfMs).toISOString(), window,
    expired_now: Number.isFinite(expMs) && isExpiredAt(expMs, nowMs, intended),
  };
  const tail = { does_not_prove: [GRANT_AS_OF_DOES_NOT_PROVE] };
  if (r.status === 'GRANT_CURRENT') return { ...base, status: 'GRANT_CURRENT_AT_AS_OF', valid_at_as_of: true, ...tail };
  if (r.status === 'GRANT_EXPIRED' && (r.reason === 'nbf_in_future' || r.reason === 'iat_in_future')) {
    return { ...base, status: 'GRANT_NOT_YET_VALID_AT_AS_OF', reason: 'as_of_before_not_before', valid_at_as_of: false, ...tail };
  }
  return { ...base, valid_at_as_of: false, ...tail };
}

function verifyGrantAt(token, ctx, opts = {}) {
  // 1. structure
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) {
    return { valid: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }

  // 2. json + version + signed fields as strings; unknown keys MALFORMED
  let payload;
  const text = Buffer.from(segments[0], 'base64url').toString('utf8');
  try {
    payload = JSON.parse(text);
  } catch (_) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  // Addendum 1.1.7 — the v2 body is also read by parseJsonStrict (RECEIPT_FORMAT §2.2, the receipt rule).
  // MEASURED before: a duplicate executor_id was read as its LAST value by JSON.parse and graded
  // GRANT_CURRENT for that reading. A duplicate member, a lone surrogate or a non-finite number is now
  // MALFORMED with the strict code, and the payload is NOT echoed: the body has no single reading. A
  // duplicate "v" is refused whichever version JSON.parse picked, since the version claim itself is
  // ambiguous. Text JSON.parse rejects keeps bad_json above; v1 bodies are otherwise unchanged.
  let strictErr = null;
  try { parseJsonStrict(text); } catch (e) { strictErr = e; }
  if (strictErr && (payload.v === GRANT_VERSION_V2 || strictErr.pointer === '/v')) {
    return { valid: false, status: 'MALFORMED', reason: strictErr.code || 'invalid_json' };
  }
  if (payload.v === GRANT_VERSION_V2) {
    return verifyExecutionGrantV2(payload, segments[1], ctx, opts);
  }
  if (payload.v !== GRANT_VERSION) {
    return { valid: false, status: 'MALFORMED', reason: 'unsupported_version', payload };
  }
  for (const k of SIGNED_FIELDS) {
    if (typeof payload[k] !== 'string') {
      return { valid: false, status: 'MALFORMED', reason: 'missing_field', payload };
    }
  }
  const allowed = new Set(['v', ...SIGNED_FIELDS, ...V1_OPTIONAL_SIGNED_FIELDS]);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) {
      return { valid: false, status: 'MALFORMED', reason: 'unknown_field', payload };
    }
  }

  for (const k of V1_OPTIONAL_SIGNED_FIELDS) {
    if (payload[k] != null && typeof payload[k] !== 'string') {
      return { valid: false, status: 'MALFORMED', reason: 'missing_field', payload };
    }
  }

  // 3. delimiter guard
  for (const k of SIGNED_FIELDS) {
    if (payload[k].includes('|')) {
      return { valid: false, status: 'INVALID_SIGNATURE', reason: 'delimiter_in_field', payload };
    }
  }

  // 4. kid — unknown OR retired → UNKNOWN_KEY.
  // Grants are live execution permission. Receipts may forensically verify a
  // retired key inside [valid_from, retired_at); grants must not.
  const entry = resolveEntry(ctx, payload);
  if (!entry) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  // Addendum 1.1.7: a revoked_at refuses at every instant, whatever `status` says. A status "revoked" entry
  // keeps the compromised_at rule below (revoked_kid / revoked_kid_undecidable).
  if (entry.status !== 'revoked' && hasRevokedAt(entry)) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'revoked_kid', payload };
  }
  const auditing = Number.isFinite(opts.auditAsOfMs);
  if (entry.status === 'retired' && !(auditing && retiredKeyActiveAt(entry, payload.iat, opts.auditAsOfMs))) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'retired_kid', payload };
  }
  // KEY STATUS GATE — RECEIPT_FORMAT.md 7.1 (normative).
  //
  // DECISION: grants KEEP their own status vocabulary (GRANT_* / UNKNOWN_KEY) rather than adopting
  // REVOKED_KEY. A grant is a different artifact class with a different caller branch and a 300s
  // TTL, and it already maps 'retired' to UNKNOWN_KEY rather than to the receipt statuses — so
  // importing two receipt statuses here would give this caller a second vocabulary to learn for no
  // decision it can act on differently. What is NOT optional is the VERDICT: a revoked key must
  // never yield a valid grant, on any timestamp. The distinction survives in `reason`, which is
  // where this verifier already carries its detail.
  if (entry.status === 'revoked') {
    const at = entry.compromised_at;
    const boundary = typeof at === 'string' && at ? Date.parse(at) : NaN;
    // iat is epoch SECONDS in this envelope; ts (when present) is ISO. Neither is guaranteed
    // well-formed on a hostile token, so both are parsed defensively -- a throw here would turn a
    // revoked-key rejection into a crash, which is a worse failure than the one being fixed.
    // MEASURED, not assumed: iat in cr.exec.v1 is an ISO STRING (e.g. 2026-08-23T12:00:00Z).
    // An earlier draft treated it as epoch seconds, which parsed to NaN and silently downgraded
    // every decidable revocation to UNDECIDABLE -- the rule would have looked implemented and
    // never decided. Numeric epoch is still accepted in case an older envelope carries one.
    const rawIat = payload.iat;
    const issued = typeof rawIat === "string" ? Date.parse(rawIat)
      : (Number.isFinite(Number(rawIat)) ? Number(rawIat) * 1000 : Date.parse(payload.ts));
    const decided = Number.isFinite(boundary) && Number.isFinite(issued) && issued >= boundary;
    return {
      valid: false,
      status: 'UNKNOWN_KEY',
      reason: decided ? 'revoked_kid' : 'revoked_kid_undecidable',
      payload,
    };
  }
  if (entry.status != null && entry.status !== 'active' && !(auditing && entry.status === 'retired')) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_key_status', payload };
  }

  // 5. Ed25519 over crexec.v1|… pipe input (not JCS of the JSON)
  const sig = Buffer.from(segments[1], 'base64url');
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), entry.publicKey, sig);
  } catch (_) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_error', payload };
  }
  if (!ok) return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_mismatch', payload };

  // 6. exp/iat + 30s leeway (same CLOCK_SKEW_LEEWAY_MS as receipts)
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const expMs = Date.parse(payload.exp);
  const iatMs = Date.parse(payload.iat);
  if (!Number.isFinite(expMs) || !Number.isFinite(iatMs)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_timestamp', payload };
  }
  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : {};
  if (isExpiredAt(expMs, now, intended)) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'expired', payload };
  }
  if (isIssuedInFuture(iatMs, now, intended)) {
    return { valid: false, status: 'GRANT_EXPIRED', reason: 'iat_in_future', payload };
  }

  // 7. receipt_digest
  if (!payload.receipt_digest || !payload.receipt_digest.startsWith('sha256:')) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'missing_receipt_digest', payload };
  }
  if (intended.receipt_token != null && String(intended.receipt_token).length > 0) {
    if (receiptDigest(intended.receipt_token) !== payload.receipt_digest) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'receipt_digest_mismatch', payload };
    }
  }

  // 8. audience / operation / target_id when supplied
  if (intended.audience != null && intended.audience !== '' && payload.audience !== String(intended.audience)) {
    return { valid: false, status: 'GRANT_WRONG_AUDIENCE', reason: 'audience_mismatch', payload };
  }
  if (intended.operation != null && intended.operation !== '' && payload.operation !== String(intended.operation)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'operation_mismatch', payload };
  }
  if (intended.target_id != null && intended.target_id !== '' && payload.target_id !== String(intended.target_id)) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'target_mismatch', payload };
  }

  // 9. scope_hash recompute from after_payload (or compare supplied scope_hash)
  let expectedScope = null;
  if (intended.scope_hash != null && String(intended.scope_hash).length > 0) {
    expectedScope = String(intended.scope_hash);
  } else if (intended.after_payload != null) {
    expectedScope = computeScopeHash({
      operation: intended.operation != null ? intended.operation : payload.operation,
      target_id: intended.target_id != null ? intended.target_id : payload.target_id,
      after_payload: intended.after_payload,
    });
  }
  if (expectedScope != null && expectedScope !== payload.scope_hash) {
    return { valid: false, status: 'GRANT_SCOPE_MISMATCH', reason: 'scope_hash_mismatch', payload };
  }

  // 1.1.7: v1 has no environment field, so a stated intended environment cannot be met.
  if (intended.environment) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'environment_mismatch', payload };
  }

  // 10.
  return { valid: true, status: 'GRANT_CURRENT', payload };
}

/** The --intended-* flags and the option each one sets (1.1.8: shared, so all eight refuse an empty value). */
const INTENDED_FLAGS = Object.freeze({
  '--intended-operation': 'intendedOperation',
  '--intended-target': 'intendedTarget',
  '--intended-audience': 'intendedAudience',
  '--intended-executor': 'intendedExecutor',
  '--intended-adapter': 'intendedAdapter',
  '--intended-environment': 'intendedEnvironment',
  '--intended-after-file': 'intendedAfterFile',
  '--intended-scope-hash': 'intendedScopeHash',
});

function parseArgs(argv) {
  const opts = {
    grant: null,
    keyFile: null,
    keysSource: null,
    kid: null,
    fetch: false,
    fetchUrl: null,
    intendedOperation: null,
    intendedTarget: null,
    intendedAudience: null,
    intendedExecutor: null,
    intendedAdapter: null,
    intendedEnvironment: null,
    intendedAfterFile: null,
    intendedScopeHash: null,
    receipt: null,
    asOf: undefined,
    json: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--key') opts.keyFile = argv[++i];
    else if (a === '--keys') opts.keysSource = argv[++i];
    else if (a === '--kid') opts.kid = argv[++i];
    // 1.1.7: --fetch [url] — the opt-in network path; without a URL, the default endpoint.
    else if (a === '--fetch') {
      opts.fetch = true;
      if (/^https?:\/\//i.test(argv[i + 1] || '')) opts.fetchUrl = argv[++i];
    }
    // 1.1.8: an --intended-* flag given with an empty (or no) value is a usage error, exit 2. MEASURED on
    // 1.1.7: `--intended-executor ""` set the field to "", every check below read it as falsy and skipped
    // the binding, and the grant answered GRANT_CURRENT, exit 0 — for all eight flags, js and py.
    else if (Object.prototype.hasOwnProperty.call(INTENDED_FLAGS, a)) {
      const value = argv[++i];
      if (value === undefined || value === '') throw new Error(`${a} needs a non-empty value (an empty one would check nothing)`);
      opts[INTENDED_FLAGS[a]] = value;
    }
    else if (a === '--receipt') opts.receipt = argv[++i];
    else if (a === '--as-of') opts.asOf = argv[++i];
    else if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.grant === null) opts.grant = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  if (opts.keyFile && opts.keysSource) throw new Error('--key and --keys are mutually exclusive');
  if (opts.fetch && (opts.keyFile || opts.keysSource)) throw new Error('--fetch is mutually exclusive with --key and --keys');
  if (opts.intendedAfterFile && opts.intendedScopeHash) {
    throw new Error('--intended-after-file and --intended-scope-hash are mutually exclusive');
  }
  if (opts.asOf !== undefined) parseAsOf(opts.asOf); // throws as_of_unparsable / as_of_in_future → exit 2
  return opts;
}

const usageFor = (prog) => {
  const pad = ' '.repeat(prog.length + 8);
  return `usage: ${prog} <grant> [--key pub.pem | --keys <url|file> | --fetch [url]] [--kid <kid>]\n`
    + `${pad}[--intended-operation X] [--intended-target Y] [--intended-audience Z]\n`
    + `${pad}[--intended-executor E] [--intended-adapter A] [--intended-environment ENV]\n`
    + `${pad}[--intended-after-file PATH | --intended-scope-hash sha256:…]\n`
    + `${pad}[--receipt <token>] [--as-of <ISO>] [--json]\n`
    + '  no --key / --keys / --fetch: the pinned CodeRifts snapshot (keys/coderifts-keys.json), offline.\n'
    + '  --as-of <ISO>  audit: was the grant inside its window at that instant? valid stays false;\n'
    + '                 exit 0 when valid_at_as_of. Later than now + 30s, or unparsable: exit 2.\n';
};
const USAGE = usageFor('node verify-grant.js');

function fail(msg) {
  process.stderr.write(`${msg}\n${USAGE}`);
  process.exit(2);
}

/** 1.1.7: sha256 of the verifying key's SPKI DER (the same digest cli.js verified_with.key_sha256 carries). */
function keySha256(publicKey) {
  return crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

/** 1.1.7: the pinned snapshot's file digest, first 12 hex — the name the keyring line and verified_with carry. */
function snapshotSha12(file = VENDORED_KEYS_PATH) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 12);
}

/**
 * The keyring line. The snapshot file carries no date of its own (measured 2026-10-31: its only key is
 * `keys`), so the text line says so rather than inventing one.
 */
const keyringLine = (sha12) => `pinned CodeRifts snapshot ${sha12} — an owner-signed grant needs --key or --keys`;
const SNAPSHOT_DATE_NOTE = '(the snapshot file carries no date)';

/**
 * The grant command. `node verify-grant.js …` and `coderifts-receipt-verifier grant …` both land here.
 *
 * 1.1.7 KEY DEFAULT: with no --key / --keys / --fetch the keys come from the pinned snapshot, offline —
 * before, this fetched app.coderifts.com. That snapshot holds CodeRifts' keys only, so a grant an owner
 * signed with their own key is UNKNOWN_KEY against it, and every output in that mode says so (the
 * `keyring` field, and a stderr line unless --json).
 */
async function main(argv = process.argv.slice(2), { prog = 'node verify-grant.js' } = {}) {
  const usage = usageFor(prog);
  const die = (msg) => { process.stderr.write(`${msg}\n${usage}`); process.exit(2); };
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    return die(e.message);
  }
  // 1.1.8: --help / -h is a request, not a usage error: exit 0 (was exit 2).
  if (opts.help) {
    process.stdout.write(usage);
    process.exit(0);
  }
  if (!opts.grant || !String(opts.grant).trim()) {
    return die('no grant provided');
  }

  let ctx;
  let keyringSource;
  let snapshot = null;
  try {
    if (opts.keysSource) {
      const keyring = await loadKeyring(opts.keysSource);
      ctx = { keyring, expectedKid: opts.kid };
      keyringSource = /^https?:\/\//i.test(opts.keysSource) ? 'url' : 'file';
    } else if (opts.keyFile) {
      const pem = fs.readFileSync(opts.keyFile, 'utf8');
      ctx = { publicKey: keyFromPem(pem), expectedKid: opts.kid };
      keyringSource = 'file';
    } else if (opts.fetch) {
      // MEASURED 2026-10-31: this imported fetchKeyInfo from verify.js, which stopped exporting it when
      // the command moved to cli.js — so at 1.1.6 every fetch here (the old default included) was exit 2
      // "fetchKeyInfo is not a function" and never reached the network. The command's copy is used now.
      const info = await require('./cli.js').fetchKeyInfo(opts.fetchUrl || DEFAULT_FETCH_URL, []);
      ctx = info.keyring ? { keyring: info.keyring, expectedKid: opts.kid } : { publicKey: info.publicKey, expectedKid: opts.kid || info.kid };
      keyringSource = 'url';
    } else {
      const keyring = await loadKeyring(VENDORED_KEYS_PATH);
      ctx = { keyring, expectedKid: opts.kid };
      keyringSource = 'pinned-snapshot';
      snapshot = snapshotSha12();
    }
  } catch (e) {
    return die(`could not load public key: ${e.message}`);
  }

  const intended = {};
  if (opts.intendedOperation != null) intended.operation = opts.intendedOperation;
  if (opts.intendedTarget != null) {
    intended.target_id = opts.intendedTarget;
    intended.target_uri = opts.intendedTarget;
  }
  if (opts.intendedAudience != null) intended.audience = opts.intendedAudience;
  if (opts.intendedExecutor != null) intended.executor_id = opts.intendedExecutor;
  if (opts.intendedAdapter != null) intended.adapter_id = opts.intendedAdapter;
  if (opts.intendedEnvironment != null) intended.environment = opts.intendedEnvironment;
  if (opts.intendedScopeHash != null) intended.scope_hash = opts.intendedScopeHash;
  if (opts.receipt != null) intended.receipt_token = opts.receipt;
  if (opts.intendedAfterFile) {
    try {
      intended.after_payload = fs.readFileSync(opts.intendedAfterFile, 'utf8');
    } catch (e) {
      return die(`could not read --intended-after-file: ${e.message}`);
    }
  }

  let result;
  try {
    result = verifyExecutionGrantInner(opts.grant, ctx, { intended, ...(opts.asOf !== undefined ? { asOf: opts.asOf } : {}) });
  } catch (e) {
    return die(e.message);
  }
  const passed = result.valid === true || result.valid_at_as_of === true;
  if (passed && result.payload) {
    const entry = ctx.keyring ? ctx.keyring.get(result.payload.kid) : null;
    const pub = entry ? entry.publicKey : ctx.publicKey;
    result = {
      ...result,
      verified_with: {
        kid: result.payload.kid,
        key_sha256: keySha256(pub),
        keyring_source: keyringSource,
        ...(snapshot ? { keyring_snapshot_sha256: snapshot } : {}),
      },
    };
  }
  if (snapshot) result = { ...result, keyring: keyringLine(snapshot) };
  process.stdout.write(JSON.stringify(result) + '\n');
  if (!opts.json) {
    if (result.mode === 'audit') process.stderr.write(`${grantAuditLine(result)}\n`);
    if (snapshot) process.stderr.write(`keyring: ${keyringLine(snapshot)} ${SNAPSHOT_DATE_NOTE}\n`);
  }
  process.exit((result.mode === 'audit' ? result.valid_at_as_of : result.valid) ? 0 : 1);
}

/** "GRANT_CURRENT_AT_AS_OF 2026-10-31T19:00:00Z · window … to … · expired now" (stderr, text mode). */
function grantAuditLine(r) {
  const w = r.window || {};
  return `${r.status} ${r.as_of} · window ${w.not_before} to ${w.expires_at} · ${r.expired_now ? 'expired now' : 'not expired now'}`;
}

function verifyExecutionGrant(token, second, third) {
  const { ctx, opts } = split3ary('verifyExecutionGrant', arguments.length, second, third);
  return verifyExecutionGrantInner(token, ctx, opts);
}

module.exports = {
  verifyExecutionGrant,
  reconstructSignedInput,
  signingInputV2,
  canonicalizeTargetUri,
  computeScopeHash,
  receiptDigest,
  sha256pref,
  resolveEntry,
  GRANT_VERSION,
  GRANT_VERSION_V2,
  SIGNING_PREFIX,
  SIGNING_PREFIX_V2,
  SIGNED_FIELDS,
  V1_OPTIONAL_SIGNED_FIELDS,
  V2_REQUIRED_STRINGS,
  V2_RESERVED_INERT,
  V2_OPTIONAL_SIGNED_STRINGS,
  VENDORED_KEYS_PATH,
  GRANT_AS_OF_DOES_NOT_PROVE,
  keyringLine,
  snapshotSha12,
  main,
  USAGE,
  CLOCK_SKEW_LEEWAY_MS,
  isIssuedInFuture,
};

if (require.main === module) {
  main().catch((e) => fail(e.message));
}
