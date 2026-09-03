'use strict';

/*
 * CodeRifts chain-receipt verifier — PURE LIBRARY. Node >= 20, zero dependencies (node:crypto only).
 *
 * Verify the receipt yourself — offline, no live CodeRifts API call needed.
 * The reference format is frozen in ./RECEIPT_FORMAT.md.
 *
 * THE SPLIT (1282-A'). This file used to be both the library and the command. The command half
 * carried the parts a library must not have: a shebang, a `require.main` block, argument parsing,
 * and `fetchKeyInfo` — a network call whose LEGACY single-key branch returns a key document with
 * no status field, so a receipt signed by a key that was later revoked verified as current. Four
 * repositories vendor this file as `src/verify.js`; every one of them was carrying that command,
 * and none of them could ever run it.
 *
 * The command now lives in ./cli.js. `node cli.js <receipt> …` is the same CLI it always was.
 * Library behaviour is BYTE-IDENTICAL: the cross-language corpus and the envelope-step vectors
 * pass unmodified, which is the proof that this was a move and not a rewrite.
 *
 * WHAT STAYED, and why it is not an inconsistency: `loadKeyring` reads a registry from a URL **or
 * a local file**, and three of the four vendoring repos call it with a FILE path — it is part of
 * the library surface they depend on. `fetchKeyInfo` has no file branch and no consumer outside
 * the command, so it left.
 *
 * CLI usage now:
 *   node cli.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
 *   node cli.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
 *
 * Key discovery: with no --key/--keys, keys are fetched from
 *   https://app.coderifts.com/.well-known/coderifts-keys.json  (override with --fetch <url>).
 * The fetch-and-resolve path accepts BOTH the registry array (active + retired)
 * and the legacy single-key body from /api/v1/attestation/public-key.
 * --keys resolves each receipt's key by kid from a registry
 *   ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }); accepts a URL or file.
 *
 * Output: JSON { valid, reason?, payload?, chain? } to stdout.
 * Exit codes: 0 valid, 1 invalid, 2 usage error.
 *
 * Verification order (matches the reference taxonomy exactly):
 *   structure -> json -> kid -> signature
 * Reasons: malformed_structure | bad_json | unknown_kid | signature_error | signature_mismatch
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { split3ary } = require('./arity');

const DEFAULT_FETCH_URL = 'https://app.coderifts.com/.well-known/coderifts-keys.json';
const SIGNING_PREFIX = 'crchain.v1';
const MAX_SUPPORTED_V = 4;
/** ID104 — verification expiry leeway (ms). `exp + leeway < now` → VERIFIED_EXPIRED. */
const CLOCK_SKEW_LEEWAY_MS = 30_000;

/**
 * 0s grace only when context DECLARES destructive AND production.
 * Public verifier has `--environment` / envelope.environment; no `destructive`
 * / `operation_class` field — never guess from operation labels.
 */
function expiryLeewayMs(_context) {
  return CLOCK_SKEW_LEEWAY_MS;
}

function isExpiredAt(expiresAtMs, nowMs, context) {
  if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs)) return false;
  return (expiresAtMs + expiryLeewayMs(context)) < nowMs;
}

// Signed fields per the max version — the anti-downgrade delimiter guard rejects any that contain '|'.
const SIGNED_FIELDS = ['kid', 'fp', 'prev', 'caller', 'ts', 'reg', 'ir', 'expires_at', 'bh'];

function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}

/**
 * RFC 8785 (JCS) canonical JSON for our data domain — MUST match the issuer's src/canonical-json.js
 * and verify.py's canonical_json byte-for-byte (ASCII keys, JSON.stringify scalars, sorted keys, no
 * whitespace, reject NaN/Infinity/undefined). Used to recompute decision_body_hash from --envelope.
 */
function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'undefined') throw new TypeError('canonicalJson: undefined');
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported type ${t}`);
}

/**
 * Reconstruct the exact signed bytes from a parsed receipt body.
 *   v1 (v absent or 1): the base string.
 *   v2 (v === 2):       base + '|' + reg.
 *   v3 (v === 3):       base + '|' + reg + '|' + ir.
 *   v4 (v === 4):       base + '|' + reg + '|' + ir + '|' + expires_at + '|' + bh.
 * Field order matches the CodeRifts issuer exactly (chain-attestation.js signingInputV4).
 * This string must be byte-identical to the Python implementation.
 */
function reconstructSignedInput(payload) {
  const base = `${SIGNING_PREFIX}|${payload.kid}|${payload.fp}|${payload.prev}|${payload.caller}|${payload.ts}`;
  if (payload.v === 4) return `${base}|${payload.reg}|${payload.ir}|${payload.expires_at}|${payload.bh}`;
  if (payload.v === 3) return `${base}|${payload.reg}|${payload.ir}`;
  if (payload.v === 2) return `${base}|${payload.reg}`;
  return base;
}

/**
 * Resolve the verification key for a parsed payload.
 * Two modes:
 *   - keyring (from --keys): pick the entry whose kid matches payload.kid; an
 *     unlisted kid resolves to null (=> unknown_kid). A retired key still verifies
 *     so receipts issued before a rotation stay checkable.
 *   - single key (default): the one loaded key, gated by expectedKid when known.
 * Returns a KeyObject, or null when the kid is not accepted.
 */
/**
 * 1306(a) — accept the SERVED registry shape, not only a Map.
 *
 * MEASURED black-box 2026-09-02. `https://app.coderifts.com/.well-known/coderifts-keys.json`
 * serves `{keys:[{kid, public_key_pem, status, ...}]}`. Passing that document straight into
 * `verifyReceipt(token, {ctx:{keyring}})` threw `TypeError: ctx.keyring.get is not a function` —
 * the library path rejected the exact bytes this project publishes for it, while the CLI's
 * `--keys <url>` worked because it converts first.
 *
 * The fix is here rather than in a caller: every consumer that fetches the public registry would
 * otherwise have to know to convert, and the ones that do not find out with a TypeError rather
 * than a verdict. `expectedKid` is a separate trap on the same path and is NOT papered over —
 * `{keyring}` with no `expectedKid` still resolves to null by design (see resolveEntry), because
 * silently defaulting a kid gate is a different and worse behaviour than a clear TypeError.
 */
function coerceKeyring(k, source) {
  if (!k) return k;
  if (typeof k.get === 'function') return k;                 // already a Map
  if (Array.isArray(k.keys) || Array.isArray(k)) {
    return keyringFromDocument(Array.isArray(k) ? { keys: k } : k, source || 'ctx.keyring');
  }
  return k;
}

function resolveEntry(ctx, payload) {
  if (ctx.keyring) {
    const entry = ctx.keyring.get(payload.kid);
    if (!entry) return null;
    if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
    return entry; // { publicKey, status, retired_at }
  }
  if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
  return { publicKey: ctx.publicKey, status: null, retired_at: null, revoked_at: null, compromised_at: null };
}

/**
 * Derive the 12-status taxonomy verdict for an already-signature-valid receipt.
 *   RETIRED_KEY_VALID_AT_ISSUE — retired key, receipt ts predates retired_at (else INVALID_SIGNATURE).
 *   UNSUPPORTED_VERSION        — payload.v beyond MAX_SUPPORTED_V.
 *   VERIFIED_EXPIRED           — v4 receipt whose signed expires_at + 30s leeway is in the past.
 *   VERIFIED_WRONG_AUDIENCE / _WRONG_ENVIRONMENT — dormant: only when --envelope carries the field
 *                                AND a check input (--audience/--environment) is supplied.
 *   VERIFIED_SUPERSEDED / _SCOPE_MISMATCH — dormant: no check input defined this round.
 *   VERIFIED_CURRENT           — otherwise.
 */
function deriveStatus(payload, entry, opts) {
  if (typeof payload.v === 'number' && payload.v > MAX_SUPPORTED_V) return 'UNSUPPORTED_VERSION';
  // FAIL CLOSED ON A STATUS WE DO NOT UNDERSTAND.
  //
  // MEASURED 2026-08-26: a registry entry with status "revoked" returned
  // { valid: true, status: "VERIFIED_CURRENT" } here — the status was read for 'retired' and
  // otherwise ignored, so anything else fell through to the healthy path. An operator who marked a
  // stolen key revoked would have believed they had acted while this verifier kept accepting it.
  // The app kernel and verify-attest/verify-toolset already reject an unknown status; these two
  // did not, so the fleet disagreed about the same registry.
  //
  // This is a bug fix, not revocation: the revocation RULE (compromised_at, REVOKED_KEY /
  // REVOKED_KEY_UNDECIDABLE) is a separate, larger change across eight verifiers. What lands here
  // is only the direction of the unknown case. Safe by measurement: the live registry publishes
  // 'active' only, so no real consumer changes behaviour.
  const KNOWN_STATUSES = new Set(['active', 'retired', 'revoked', null, undefined]);
  if (!KNOWN_STATUSES.has(entry.status)) {
    return 'UNKNOWN_KEY_STATUS';
  }
  // 1079 B — OPTIONAL timestamps, additive. Absent both fields → this function continues
  // exactly as before. Signing time is payload.ts (receipts have no iat).
  // revoked_at = compromise: EVERY receipt under the key is invalid, including those
  // whose ts predates revoked_at (the attacker chooses ts).
  // retired_at = planned rotation: ts < retired_at stays on the existing path;
  // ts >= retired_at is KEY_RETIRED_AFTER_SIGNING.
  if (typeof entry.revoked_at === 'string' && entry.revoked_at.length > 0) {
    return 'KEY_REVOKED';
  }
  if (typeof entry.retired_at === 'string' && entry.retired_at.length > 0 && payload.ts) {
    const issued = Date.parse(payload.ts);
    const retired = Date.parse(entry.retired_at);
    if (Number.isFinite(issued) && Number.isFinite(retired) && issued >= retired) {
      return 'KEY_RETIRED_AFTER_SIGNING';
    }
  }
  // REVOKED — RECEIPT_FORMAT.md §7.1 (normative). The attacker chooses ts, so no timestamp may
  // rehabilitate a revoked key's signature: BOTH outcomes are valid:false. UNDECIDABLE is not a
  // softer valid; it reports that we cannot tell a legitimate pre-compromise receipt from a
  // backdated forgery. A missing compromised_at means the whole key history is suspect.
  if (entry.status === 'revoked') {
    const at = entry.compromised_at;
    if (typeof at !== 'string' || at.length === 0) return 'REVOKED_KEY_UNDECIDABLE';
    const boundary = Date.parse(at);
    const issued = Date.parse(payload.ts);
    if (!Number.isFinite(boundary) || !Number.isFinite(issued)) return 'REVOKED_KEY_UNDECIDABLE';
    return issued >= boundary ? 'REVOKED_KEY' : 'REVOKED_KEY_UNDECIDABLE';
  }
  if (entry.status === 'retired') {
    if (entry.retired_at && payload.ts
      && Date.parse(payload.ts) < Date.parse(entry.retired_at)) {
      return 'RETIRED_KEY_VALID_AT_ISSUE';
    }
    return 'INVALID_SIGNATURE'; // signed by a key already retired at issue -> reject
  }
  const now = opts.now != null ? opts.now : Date.now();
  if (payload.v === 4 && typeof payload.expires_at === 'string') {
    const exp = Date.parse(payload.expires_at);
    const context = opts.envelope || { environment: opts.expectedEnvironment };
    if (isExpiredAt(exp, now, context)) return 'VERIFIED_EXPIRED';
  }
  if (opts.envelope) {
    const env = opts.envelope;
    if (opts.expectedAudience != null && env.audience != null && env.audience !== opts.expectedAudience) {
      return 'VERIFIED_WRONG_AUDIENCE';
    }
    if (opts.expectedEnvironment != null && env.environment != null && env.environment !== opts.expectedEnvironment) {
      return 'VERIFIED_WRONG_ENVIRONMENT';
    }
  }
  return 'VERIFIED_CURRENT';
}

/**
 * Verify a single receipt token against a public key (or keyring) + expected kid.
 * @param {string} token
 * @param {{ publicKey?: import('crypto').KeyObject, keyring?: Map<string,{publicKey:import('crypto').KeyObject}>, expectedKid: (string|null) }} ctx
 * @returns {{ valid: boolean, reason?: string, payload?: object }}
 */
function verifyReceiptInner(token, ctx, opts = {}) {
  // 1. structure
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) {
    return { valid: false, status: 'MALFORMED', reason: 'malformed_structure' };
  }

  // 2. json
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
  }

  // 3. kid -- resolve the entry by kid (keyring) or gate the single key by expectedKid.
  // 1306(a): a served `{keys:[...]}` document is accepted here as well as a Map.
  const entry = resolveEntry(
    ctx.keyring ? { ...ctx, keyring: coerceKeyring(ctx.keyring, 'ctx.keyring') } : ctx,
    payload,
  );
  if (!entry) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }

  // 4. signature (raw Ed25519 over the reconstructed UTF-8 bytes)
  const sig = Buffer.from(segments[1], 'base64url');
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), entry.publicKey, sig);
  } catch (_) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_error', payload };
  }
  if (!ok) return { valid: false, status: 'INVALID_SIGNATURE', reason: 'signature_mismatch', payload };

  // 5. anti-downgrade delimiter guard — a signed field containing '|' could re-split into a lower
  // version whose reconstructed bytes collide with these. Legitimate fields never contain '|'.
  for (const k of SIGNED_FIELDS) {
    if (typeof payload[k] === 'string' && payload[k].includes('|')) {
      return { valid: false, status: 'INVALID_SIGNATURE', reason: 'delimiter_in_field', payload };
    }
  }

  // 6. envelope binding (v4): a supplied envelope's canonical body_hash MUST equal payload.bh.
  if (opts.envelope && payload.v === 4) {
    const rest = { ...opts.envelope };
    delete rest.receipt;
    delete rest.decision_body_hash;
    const recomputed = 'sha256:' + sha256hex(canonicalJson(rest));
    if (recomputed !== payload.bh) {
      return { valid: false, status: 'INVALID_SIGNATURE', reason: 'body_hash_mismatch', payload };
    }
  }

  // 7. taxonomy status (freshness / retirement / dormant field checks).
  const status = deriveStatus(payload, entry, opts);
  if (status === 'KEY_REVOKED') {
    return { valid: false, status, reason: 'KEY_REVOKED', payload };
  }
  if (status === 'KEY_RETIRED_AFTER_SIGNING') {
    return { valid: false, status, reason: 'KEY_RETIRED_AFTER_SIGNING', payload };
  }
  if (status === 'INVALID_SIGNATURE') {
    return { valid: false, status, reason: 'retired_key_after_issue', payload };
  }
  const valid = status === 'VERIFIED_CURRENT' || status === 'RETIRED_KEY_VALID_AT_ISSUE';
  // UNKNOWN_KEY_STATUS is deliberately absent from the valid set — see deriveStatus.
  return { valid, status, payload };
}

/**
 * Verify a chain of tokens (oldest first): every signature valid AND every non-genesis
 * link's prev == 'sha256:' + sha256hex(previous token string).
 */
function verifyChainInner(tokens, ctx, opts = {}) {
  const links = [];
  let allValid = true;
  let first = null;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const res = verifyReceiptInner(token, ctx, opts);
    const link = { index: i, signature_valid: res.valid };
    if (!res.valid) link.reason = res.reason;
    const prev = res.payload ? res.payload.prev : undefined;
    if (res.payload) link.prev = prev;

    if (i === 0) {
      first = prev === 'null' ? 'genesis' : 'continuation';
      link.role = first;
      // A genesis needs prev === 'null'; a continuation links to a token we do not hold.
      link.prev_ok = prev === 'null' ? true : null;
    } else {
      const expected = `sha256:${sha256hex(tokens[i - 1])}`;
      link.expected_prev = expected;
      link.prev_ok = prev === expected;
      if (!link.prev_ok) allValid = false;
    }

    if (!res.valid) allValid = false;
    links.push(link);
  }

  return { valid: allValid, chain: { length: tokens.length, first, links } };
}

// ---------------------------------------------------------------------------
// Key loading
// ---------------------------------------------------------------------------

function keyFromPem(pem) {
  return crypto.createPublicKey(pem);
}

/**
 * Build a kid -> key map from a registry document
 * ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }).
 * Returns null when `keys` is missing/empty so the caller can try the legacy
 * single-key body. --keys still requires a non-empty keys[] (throws).
 */
function keyringFromDocument(doc, source) {
  const keys = doc && Array.isArray(doc.keys) ? doc.keys : null;
  if (!keys || keys.length === 0) return null;
  const keyring = new Map();
  for (const k of keys) {
    if (!k || !k.kid || !k.public_key_pem) throw new Error(`registry entry missing kid/public_key_pem in ${source}`);
    // compromised_at MUST be carried through: deriveStatus reads it for the revoked rule
    // (RECEIPT_FORMAT.md 7.1). Dropping it here made the rule inert — every revoked key
    // returned UNDECIDABLE regardless of ts, which looks implemented and decides nothing.
    keyring.set(k.kid, {
      publicKey: keyFromPem(k.public_key_pem),
      status: k.status || null,
      retired_at: k.retired_at || null,
      revoked_at: k.revoked_at || null,
      compromised_at: k.compromised_at || null,
    });
  }
  return keyring;
}

function pickActiveFromKeyring(keyring) {
  for (const [kid, entry] of keyring) {
    if (entry.status === 'active') return { kid, entry };
  }
  const first = keyring.entries().next().value;
  return first ? { kid: first[0], entry: first[1] } : null;
}

/**
 * Build a kid -> key map from a CodeRifts key registry
 * ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }). A --keys source may be
 * an http(s) URL or a local file path. Both active and retired keys are loaded.
 */
async function loadKeyring(source) {
  let text;
  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${source} -> HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = fs.readFileSync(source, 'utf8');
  }
  const doc = JSON.parse(text);
  const keyring = keyringFromDocument(doc, source);
  if (!keyring) throw new Error(`no keys[] in registry ${source}`);
  return keyring;
}

function verifyReceipt(token, second, third) {
  const { ctx, opts } = split3ary('verifyReceipt', arguments.length, second, third);
  return verifyReceiptInner(token, ctx, opts);
}

function verifyChain(tokens, second, third) {
  const { ctx, opts } = split3ary('verifyChain', arguments.length, second, third);
  return verifyChainInner(tokens, ctx, opts);
}

// Reusable API — require('./verify') imports the pure verify logic WITHOUT running the CLI. The
// GitHub Action + other embedders use these directly (verifyReceipt/verifyChain/deriveStatus/…);
// the receipt format + taxonomy are frozen in RECEIPT_FORMAT.md.
module.exports = {
  verifyReceipt,
  verifyChain,
  deriveStatus,
  resolveEntry,
  reconstructSignedInput,
  canonicalJson,
  loadKeyring,
  keyFromPem,
  keyringFromDocument,
  // Pure keyring helper. Exported for the command (cli.js fetchKeyInfo) after the split —
  // it takes a keyring and returns the active entry; it performs no I/O.
  pickActiveFromKeyring,
  sha256hex,
  DEFAULT_FETCH_URL,
  SIGNING_PREFIX,
  MAX_SUPPORTED_V,
  SIGNED_FIELDS,
  CLOCK_SKEW_LEEWAY_MS,
  expiryLeewayMs,
  isExpiredAt,
};
