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
 *
 * Key discovery: --keys resolves by kid from a registry
 *   ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }).
 * --key pins a single SPKI PEM (same as verify.js). --key and --keys are
 * mutually exclusive. With neither, the public key is fetched from
 *   https://app.coderifts.com/api/v1/attestation/public-key  (override --fetch).
 *
 * Output: JSON { valid, status, reason?, payload? } to stdout — byte-identical
 * to verify_grant.py. Exit codes: 0 GRANT_CURRENT, 1 otherwise, 2 usage error.
 *
 * Retired kid → UNKNOWN_KEY. Grants are live execution permission; receipts
 * may forensically verify a retired key inside [valid_from, retired_at),
 * grants must not (see coderifts-app/docs/cr-exec-v1.md).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const {
  loadKeyring,
  keyFromPem,
  fetchKeyInfo,
  sha256hex,
  canonicalJson,
  CLOCK_SKEW_LEEWAY_MS,
  isExpiredAt,
  expiryLeewayMs,
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
const TARGET_SCHEMES = Object.freeze(['fs', 'git', 'api', 'db', 'registry', 'deploy']);
const DEFAULT_FETCH_URL = 'https://app.coderifts.com/api/v1/attestation/public-key';

function isIssuedInFuture(issuedAtMs, nowMs, context) {
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(nowMs)) return false;
  return issuedAtMs > (nowMs + expiryLeewayMs(context));
}

function scalar(v) {
  return v == null ? '' : String(v);
}

function reconstructSignedInput(payload) {
  return [
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
  ].join('|');
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
  const allowed = new Set([...V2_REQUIRED_STRINGS, 'max_attempts']);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) return { valid: false, status: 'MALFORMED', reason: 'unknown_field', payload };
  }
  if (!canonicalizeTargetUri(payload.target_uri)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_target_uri', payload };
  }

  const entry = resolveEntry(ctx, payload);
  if (!entry) {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'unknown_kid', payload };
  }
  if (entry.status === 'retired') {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'retired_kid', payload };
  }
  if (entry.status === 'revoked') {
    return { valid: false, status: 'UNKNOWN_KEY', reason: 'revoked_kid', payload };
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

  if (intended.executor_id && payload.executor_id !== String(intended.executor_id)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'executor_mismatch', payload };
  }
  if (intended.adapter_id && payload.adapter_id !== String(intended.adapter_id)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'adapter_mismatch', payload };
  }
  if (intended.target_uri) {
    const want = canonicalizeTargetUri(String(intended.target_uri)) || String(intended.target_uri);
    if (payload.target_uri !== want) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'target_mismatch', payload };
    }
  }
  if (intended.audience) {
    if (payload.audience_hash !== sha256pref(intended.audience)) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'audience_mismatch', payload };
    }
  }
  if (intended.audience_hash && payload.audience_hash !== String(intended.audience_hash)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'audience_mismatch', payload };
  }
  if (intended.after_payload != null) {
    if (payload.after_payload_hash !== sha256pref(intended.after_payload)) {
      return { valid: false, status: 'GRANT_UNBOUND', reason: 'after_payload_mismatch', payload };
    }
  }
  if (intended.operation && payload.operation !== String(intended.operation)) {
    return { valid: false, status: 'GRANT_UNBOUND', reason: 'operation_mismatch', payload };
  }
  if (intended.receipt_token) {
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
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, status: 'MALFORMED', reason: 'bad_json' };
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
  const allowed = new Set(['v', ...SIGNED_FIELDS]);
  for (const k of Object.keys(payload)) {
    if (!allowed.has(k)) {
      return { valid: false, status: 'MALFORMED', reason: 'unknown_field', payload };
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
  if (entry.status === 'retired') {
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
  if (entry.status != null && entry.status !== 'active') {
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

  // 10.
  return { valid: true, status: 'GRANT_CURRENT', payload };
}

function parseArgs(argv) {
  const opts = {
    grant: null,
    keyFile: null,
    keysSource: null,
    kid: null,
    fetchUrl: null,
    intendedOperation: null,
    intendedTarget: null,
    intendedAudience: null,
    intendedExecutor: null,
    intendedAdapter: null,
    intendedAfterFile: null,
    intendedScopeHash: null,
    receipt: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--key') opts.keyFile = argv[++i];
    else if (a === '--keys') opts.keysSource = argv[++i];
    else if (a === '--kid') opts.kid = argv[++i];
    else if (a === '--fetch') opts.fetchUrl = argv[++i];
    else if (a === '--intended-operation') opts.intendedOperation = argv[++i];
    else if (a === '--intended-target') opts.intendedTarget = argv[++i];
    else if (a === '--intended-audience') opts.intendedAudience = argv[++i];
    else if (a === '--intended-executor') opts.intendedExecutor = argv[++i];
    else if (a === '--intended-adapter') opts.intendedAdapter = argv[++i];
    else if (a === '--intended-after-file') opts.intendedAfterFile = argv[++i];
    else if (a === '--intended-scope-hash') opts.intendedScopeHash = argv[++i];
    else if (a === '--receipt') opts.receipt = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.grant === null) opts.grant = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  if (opts.keyFile && opts.keysSource) throw new Error('--key and --keys are mutually exclusive');
  if (opts.intendedAfterFile && opts.intendedScopeHash) {
    throw new Error('--intended-after-file and --intended-scope-hash are mutually exclusive');
  }
  return opts;
}

const USAGE =
  'usage: node verify-grant.js <grant> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n'
  + '                         [--intended-operation X] [--intended-target Y] [--intended-audience Z]\n'
  + '                         [--intended-after-file PATH | --intended-scope-hash sha256:…]\n'
  + '                         [--receipt <token>]\n';

function fail(msg) {
  process.stderr.write(`${msg}\n${USAGE}`);
  process.exit(2);
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    return fail(e.message);
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    process.exit(2);
  }
  if (!opts.grant || !String(opts.grant).trim()) {
    return fail('no grant provided');
  }

  let ctx;
  try {
    if (opts.keysSource) {
      const keyring = await loadKeyring(opts.keysSource);
      ctx = { keyring, expectedKid: opts.kid };
    } else if (opts.keyFile) {
      const pem = fs.readFileSync(opts.keyFile, 'utf8');
      ctx = { publicKey: keyFromPem(pem), expectedKid: opts.kid };
    } else {
      const info = await fetchKeyInfo(opts.fetchUrl || DEFAULT_FETCH_URL);
      ctx = { publicKey: info.publicKey, expectedKid: opts.kid || info.kid };
    }
  } catch (e) {
    return fail(`could not load public key: ${e.message}`);
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
  if (opts.intendedScopeHash != null) intended.scope_hash = opts.intendedScopeHash;
  if (opts.receipt != null) intended.receipt_token = opts.receipt;
  if (opts.intendedAfterFile) {
    try {
      intended.after_payload = fs.readFileSync(opts.intendedAfterFile, 'utf8');
    } catch (e) {
      return fail(`could not read --intended-after-file: ${e.message}`);
    }
  }

  const result = verifyExecutionGrantInner(opts.grant, ctx, { intended });
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(result.valid ? 0 : 1);
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
  CLOCK_SKEW_LEEWAY_MS,
  isIssuedInFuture,
};

if (require.main === module) {
  main().catch((e) => fail(e.message));
}
