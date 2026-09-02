#!/usr/bin/env node
'use strict';

/*
 * CodeRifts cr.exec.attest.v1 execution-attestation verifier -- Node >= 20,
 * zero dependencies (node:crypto only). Sibling of verify.js / verify-grant.js.
 *
 * Usage:
 *   node verify-attest.js <token> --keys <file|url>
 *        [--grant <token>] [--receipt-digest sha256:…]
 *
 * --keys is REQUIRED. Executor keys are CUSTOMER-HELD; this verifier never
 * fetches CodeRifts. The registry is the same JSON shape as
 * .well-known/coderifts-keys.json ({ keys: [{ kid, public_key_pem, status,
 * valid_from, retired_at }] }).
 *
 * Output: JSON { valid, status, reason?, payload? } to stdout — byte-identical
 * to verify_attest.py. Exit codes: 0 valid (ATTEST_VALID |
 * ATTEST_RETIRED_KEY_VALID_AT_ISSUE), 1 otherwise, 2 usage error.
 *
 * Retired-key rule is HISTORICAL (receipt class): retired kid + committed_at
 * inside [valid_from, retired_at) → ATTEST_RETIRED_KEY_VALID_AT_ISSUE.
 * Contrast grants: retired → UNKNOWN_KEY (live permission).
 *
 * Honesty: a valid attestation proves a holder of the executor key asserts
 * this commit. It does NOT prove that the executor's code is unmodified
 * (deploy attestation is out of scope, named as such — a later artifact, not
 * this one); that a human saw anything; that the underlying grant is currently
 * GRANT_CURRENT (re-check the grant if live permission is required; this
 * statement is historical); that result_digest is a CodeRifts fingerprint, a
 * receipt digest, or an after-payload hash — result_digest is the executor's
 * choice of bytes.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { CLOCK_SKEW_LEEWAY_MS, expiryLeewayMs } = require('./verify.js');

const ATTEST_VERSION = 'cr.exec.attest.v1';
const SIGNING_PREFIX = 'crexecattest.v1';
const ENVELOPE_TAG = 'cr.exec.attest.v1';
const GRANT_VERSION = 'cr.exec.v1';
const GRANT_SIGNED_FIELDS = Object.freeze([
  'kid', 'receipt_digest', 'scope_hash', 'audience', 'operation', 'target_id', 'jti', 'iat', 'exp',
]);

const REQUIRED_FIELDS = Object.freeze([
  'executor_kid', 'grant_jti', 'receipt_digest', 'scope_hash', 'committed_at',
]);
const OPTIONAL_STRINGS = Object.freeze(['state_nonce', 'result_digest']);
const ALLOWED_KEYS = new Set(['v', ...REQUIRED_FIELDS, ...OPTIONAL_STRINGS, 'meta']);

const STATUSES = Object.freeze({
  ATTEST_VALID: 'ATTEST_VALID',
  ATTEST_INVALID_SIGNATURE: 'ATTEST_INVALID_SIGNATURE',
  ATTEST_UNKNOWN_KEY: 'ATTEST_UNKNOWN_KEY',
  ATTEST_RETIRED_KEY_VALID_AT_ISSUE: 'ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  ATTEST_MALFORMED: 'ATTEST_MALFORMED',
  ATTEST_UNBOUND: 'ATTEST_UNBOUND',
});

function isIssuedInFuture(issuedAtMs, nowMs, context) {
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(nowMs)) return false;
  return issuedAtMs > (nowMs + expiryLeewayMs(context));
}

function scalar(v) {
  return v == null ? '' : String(v);
}

function canonicalMeta(meta) {
  const keys = Object.keys(meta).sort();
  const o = {};
  for (const k of keys) o[k] = meta[k];
  return JSON.stringify(o);
}

function metaOk(meta) {
  if (meta == null) return true;
  if (typeof meta !== 'object' || Array.isArray(meta)) return false;
  const keys = Object.keys(meta);
  if (keys.length > 8) return false;
  for (const k of keys) {
    if (typeof k !== 'string' || k.length === 0 || k.length > 64) return false;
    const v = meta[k];
    const t = typeof v;
    if (t !== 'string' && t !== 'number' && t !== 'boolean') return false;
    if (t === 'string' && v.length > 256) return false;
    if (t === 'string' && v.includes('|')) return false;
    if (k.includes('|')) return false;
  }
  return true;
}

function signingInput(body) {
  const parts = [
    SIGNING_PREFIX,
    scalar(body.executor_kid),
    scalar(body.grant_jti),
    scalar(body.receipt_digest),
    scalar(body.scope_hash),
    body.state_nonce != null && String(body.state_nonce).length > 0 ? String(body.state_nonce) : '',
    scalar(body.committed_at),
    body.result_digest != null && String(body.result_digest).length > 0 ? String(body.result_digest) : '',
  ];
  if (body.meta && typeof body.meta === 'object') parts.push(canonicalMeta(body.meta));
  return parts.join('|');
}

function fieldHasDelimiter(body) {
  for (const k of [...REQUIRED_FIELDS, ...OPTIONAL_STRINGS]) {
    if (typeof body[k] === 'string' && body[k].includes('|')) return true;
  }
  return false;
}

function fail(status, reason, payload) {
  return { valid: false, status, reason, payload };
}

function commitLabelFromPayload(payload) {
  // 1109 / 1085. Measured names: cas_evidence.class is host_claimed | executor_attested
  // (not "host_reported"); labels authorized_and_committed vs
  // authorized_and_host_reported_committed. meta is the signed slot that can carry class
  // without breaking the cr.exec.attest.v1 allowlist.
  const cls = payload && payload.meta && payload.meta.class;
  if (cls === 'executor_attested') return 'authorized_and_committed';
  if (cls === 'host_claimed') return 'authorized_and_host_reported_committed';
  return undefined;
}

function okStatus(status, payload) {
  const out = { valid: true, status, reason: null, payload };
  const label = commitLabelFromPayload(payload);
  if (label) out.commit_label = label;
  return out;
}

function isIssueTimeWithinKeyWindow(ts, keyMeta) {
  if (!keyMeta || keyMeta.status === 'active') return true;
  if (keyMeta.status !== 'retired') return false;
  if (typeof keyMeta.retired_at !== 'string' || keyMeta.retired_at.length === 0) return false;
  if (typeof ts !== 'string' || ts.length === 0) return false;
  const issueMs = Date.parse(ts);
  if (!Number.isFinite(issueMs)) return false;
  if (keyMeta.valid_from) {
    const fromMs = Date.parse(keyMeta.valid_from);
    if (Number.isFinite(fromMs) && issueMs < fromMs) return false;
  }
  const retiredMs = Date.parse(keyMeta.retired_at);
  if (!Number.isFinite(retiredMs)) return false;
  if (issueMs >= retiredMs) return false;
  return true;
}

function resolveExecutorKey(registry, kid) {
  if (!registry || !Array.isArray(registry.keys) || typeof kid !== 'string' || !kid) return null;
  const matches = registry.keys.filter((k) => k && k.kid === kid && typeof k.public_key_pem === 'string');
  if (matches.length === 0) return null;
  const entry = matches.find((k) => k.status === 'active') || matches[0];
  try {
    const publicKey = crypto.createPublicKey(entry.public_key_pem);
    return {
      publicKey,
      // PASS THE REAL STATUS THROUGH. This used to normalise anything that was not 'retired'
      // to 'active', which LAUNDERED a revoked key into a healthy one before any gate could see
      // it -- the status check downstream was correct and simply never received the truth.
      status: entry.status || 'active',
      valid_from: entry.valid_from || null,
      retired_at: entry.retired_at || null,
      compromised_at: entry.compromised_at || null,  // carried through for the 7.1 revoked rule
    };
  } catch (_) {
    return null;
  }
}

function parseAttestToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  const segments = token.split('|');
  if (segments.length !== 4 || segments.some((s) => !s)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  if (segments[0] !== ENVELOPE_TAG) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'unsupported_version' };
  }
  const envelopeKid = segments[1];
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[2], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (payload.v !== ATTEST_VERSION) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'unsupported_version', payload };
  }
  for (const k of REQUIRED_FIELDS) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'missing_field', payload };
    }
  }
  for (const k of OPTIONAL_STRINGS) {
    if (payload[k] != null && typeof payload[k] !== 'string') {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_optional', payload };
    }
  }
  if (payload.executor_kid !== envelopeKid) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'kid_mismatch', payload };
  }
  for (const k of Object.keys(payload)) {
    if (!ALLOWED_KEYS.has(k)) {
      return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'unknown_field', payload };
    }
  }
  if (!metaOk(payload.meta)) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'meta_bounds', payload };
  }
  if (payload.result_digest != null && payload.result_digest !== ''
      && !payload.result_digest.startsWith('sha256:')) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_result_digest', payload };
  }
  if (payload.receipt_digest && !payload.receipt_digest.startsWith('sha256:')) {
    return { ok: false, status: STATUSES.ATTEST_MALFORMED, reason: 'bad_receipt_digest', payload };
  }
  return { ok: true, payload, sig: segments[3], envelopeKid };
}

function parseGrantToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) return { ok: false };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { ok: false };
  if (payload.v !== GRANT_VERSION) return { ok: false };
  for (const k of GRANT_SIGNED_FIELDS) {
    if (typeof payload[k] !== 'string') return { ok: false };
  }
  return { ok: true, payload };
}

function grantFieldsFromIntended(intended) {
  if (!intended || typeof intended !== 'object') return null;
  if (intended.grant_fields && typeof intended.grant_fields === 'object') {
    return intended.grant_fields;
  }
  if (typeof intended.grant === 'string' && intended.grant.length > 0) {
    const parsed = parseGrantToken(intended.grant);
    if (!parsed.ok) return { unparseable: true };
    return parsed.payload;
  }
  return null;
}

function nonceOf(obj) {
  if (!obj) return '';
  return typeof obj.state_nonce === 'string' && obj.state_nonce.length > 0 ? obj.state_nonce : '';
}

/**
 * Offline attestation verifier. Kernel algorithm from
 * coderifts-app/src/verdict-core/execution-attestation.js / docs/cr-exec-attest-v1.md.
 *
 * @param {string} token
 * @param {object} opts
 * @param {object} opts.registry  customer-pinned { keys: [...] }
 * @param {object} [opts.intended]  { grant?: string, grant_fields?: object, receipt_digest?: string }
 * @param {number} [opts.now]
 */
function verifyExecutionAttestation(token, opts = {}) {
  // ── 1128: A THIRD ARGUMENT IS A CALLER ERROR, AND IT USED TO BE SILENT ──────────────────────
  //
  // This function is 2-ary while verifyReceipt and verifyExecutionGrant are 3-ary
  // (token, ctx, opts). A caller following their shape puts `intended` in a third argument, it is
  // dropped, `wantsCross` at the cross-check below stays false, and a MISMATCHED attestation
  // returns ATTEST_VALID. Measured: the same vector returns ATTEST_UNBOUND/receipt_digest_mismatch
  // when `intended` is passed correctly, and ATTEST_VALID when passed third — a fail-open at the
  // caller boundary, which cost one wrong run before it was noticed.
  //
  // The arity is NOT changed here: that is breaking and belongs to a versioned wave. What is
  // closed is the SILENCE. Python needs no equivalent — `verify_execution_attestation(token, opts)`
  // already raises TypeError on an extra positional, measured 2026-08-27.
  if (arguments.length > 2) {
    throw new Error(
      'verifyExecutionAttestation(token, opts) — pass intended via opts.intended. '
      + `Received ${arguments.length} arguments; the third would be ignored and the cross-check `
      + 'would silently not run, grading a mismatched attestation ATTEST_VALID.',
    );
  }
  if (opts && opts.ctx && opts.registry == null && opts.ctx.registry) {
    opts = { ...opts, registry: opts.ctx.registry };
  }
  const parsed = parseAttestToken(token);
  if (!parsed.ok) {
    return fail(parsed.status, parsed.reason, parsed.payload);
  }
  const payload = parsed.payload;
  if (fieldHasDelimiter(payload)) {
    return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'delimiter_in_field', payload);
  }

  const resolved = resolveExecutorKey(opts.registry, payload.executor_kid);
  if (!resolved) {
    return fail(STATUSES.ATTEST_UNKNOWN_KEY, 'unknown_kid', payload);
  }

  let sigOk = false;
  try {
    sigOk = crypto.verify(
      null,
      Buffer.from(signingInput(payload), 'utf8'),
      resolved.publicKey,
      Buffer.from(parsed.sig, 'base64url'),
    );
  } catch (_) {
    return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'signature_error', payload);
  }
  if (!sigOk) {
    return fail(STATUSES.ATTEST_INVALID_SIGNATURE, 'signature_mismatch', payload);
  }

  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const committedMs = Date.parse(payload.committed_at);
  if (!Number.isFinite(committedMs)) {
    return fail(STATUSES.ATTEST_MALFORMED, 'bad_timestamp', payload);
  }
  if (isIssuedInFuture(committedMs, now, opts.intended)) {
    return fail(STATUSES.ATTEST_MALFORMED, 'committed_at_in_future', payload);
  }


  // KEY STATUS GATE — RECEIPT_FORMAT.md 7.1 (normative), same rule as verify.js.
  //
  // MEASURED 2026-08-26: this verifier returned {valid:true} for a REVOKED key. The window check
  // below fails closed on an unknown status, but the caller only invoked it for status==='retired',
  // so 'revoked' fell straight through to the healthy path. A window function that is never called
  // is not a gate.
  //
  // Attestations carry their own status vocabulary, so the revoked verdict is reported through
  // STATUSES.ATTEST_UNKNOWN_KEY with a distinct REASON rather than by importing the receipt statuses -- the caller
  // branches on this artifact class's own vocabulary and must not have to learn a second one.
  {
    const st = resolved && resolved.status;
    if (st != null && st !== 'active' && st !== 'retired' && st !== 'revoked') {
      return fail(STATUSES.ATTEST_UNKNOWN_KEY, 'unknown_key_status', payload);
    }
    if (st === 'revoked') {
      const at = resolved.compromised_at;
      const boundary = typeof at === 'string' && at ? Date.parse(at) : NaN;
      const issued = Date.parse(payload.committed_at);
      const decided = Number.isFinite(boundary) && Number.isFinite(issued) && issued >= boundary;
      return fail(STATUSES.ATTEST_UNKNOWN_KEY, decided ? 'revoked_key' : 'revoked_key_undecidable', payload);
    }
  }
  let retiredHistorical = false;
  if (resolved.status === 'retired') {
    if (!isIssueTimeWithinKeyWindow(payload.committed_at, resolved)) {
      return fail(STATUSES.ATTEST_UNKNOWN_KEY, 'retired_key_outside_window', payload);
    }
    retiredHistorical = true;
  }

  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : null;
  const wantsCross = !!(intended && (intended.grant || intended.grant_fields || intended.receipt_digest));
  if (wantsCross) {
    const gf = grantFieldsFromIntended(intended);
    if (gf && gf.unparseable) {
      return fail(STATUSES.ATTEST_UNBOUND, 'grant_unparseable', payload);
    }
    if (gf) {
      if (String(gf.jti || '') !== payload.grant_jti) {
        return fail(STATUSES.ATTEST_UNBOUND, 'grant_jti_mismatch', payload);
      }
      if (String(gf.scope_hash || '') !== payload.scope_hash) {
        return fail(STATUSES.ATTEST_UNBOUND, 'scope_hash_mismatch', payload);
      }
      if (nonceOf(gf) !== nonceOf(payload)) {
        return fail(STATUSES.ATTEST_UNBOUND, 'state_nonce_mismatch', payload);
      }
      if (gf.receipt_digest && gf.receipt_digest !== payload.receipt_digest) {
        return fail(STATUSES.ATTEST_UNBOUND, 'receipt_digest_mismatch', payload);
      }
    }
    if (intended.receipt_digest != null && String(intended.receipt_digest).length > 0
        && String(intended.receipt_digest) !== payload.receipt_digest) {
      return fail(STATUSES.ATTEST_UNBOUND, 'receipt_digest_mismatch', payload);
    }
  }

  if (retiredHistorical) {
    return okStatus(STATUSES.ATTEST_RETIRED_KEY_VALID_AT_ISSUE, payload);
  }
  return okStatus(STATUSES.ATTEST_VALID, payload);
}

async function loadRegistryDocument(source) {
  let text;
  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${source} -> HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = fs.readFileSync(source, 'utf8');
  }
  const doc = JSON.parse(text);
  if (!doc || !Array.isArray(doc.keys)) throw new Error(`no keys[] in registry ${source}`);
  return doc;
}

function parseArgs(argv) {
  const opts = {
    token: null,
    keysSource: null,
    grant: null,
    receiptDigest: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--keys') opts.keysSource = argv[++i];
    else if (a === '--grant') opts.grant = argv[++i];
    else if (a === '--receipt-digest') opts.receiptDigest = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.token === null) opts.token = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  return opts;
}

const USAGE =
  'usage: node verify-attest.js <token> --keys <file|url> [--grant <token>] [--receipt-digest sha256:…]\n'
  + '\n'
  + '--keys is REQUIRED (customer-held executor registry). There is no default fetch.\n';

function failUsage(msg) {
  process.stderr.write(`${msg}\n${USAGE}`);
  process.exit(2);
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    return failUsage(e.message);
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    process.exit(2);
  }
  if (!opts.token || !String(opts.token).trim()) {
    return failUsage('no attestation token provided');
  }
  if (!opts.keysSource) {
    return failUsage('--keys is required (customer-held executor registry; no default fetch)');
  }

  let registry;
  try {
    registry = await loadRegistryDocument(opts.keysSource);
  } catch (e) {
    return failUsage(`could not load executor registry: ${e.message}`);
  }

  const intended = {};
  if (opts.grant != null) intended.grant = opts.grant;
  if (opts.receiptDigest != null) intended.receipt_digest = opts.receiptDigest;

  const result = verifyExecutionAttestation(opts.token, {
    registry,
    ...(Object.keys(intended).length ? { intended } : {}),
  });
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

module.exports = {
  verifyExecutionAttestation,
  parseAttestToken,
  signingInput,
  resolveExecutorKey,
  isIssueTimeWithinKeyWindow,
  ATTEST_VERSION,
  SIGNING_PREFIX,
  ENVELOPE_TAG,
  STATUSES,
  CLOCK_SKEW_LEEWAY_MS,
  loadRegistryDocument,
};

if (require.main === module) {
  main().catch((e) => failUsage(e.message));
}
