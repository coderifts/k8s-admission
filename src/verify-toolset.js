#!/usr/bin/env node
/**
 * verify-toolset.js — offline verifier for cr.toolset.attest.v1 ("Represented").
 *
 * A host operator's signed declaration that the tool set with a given digest is the COMPLETE set
 * of tools that can mutate a governed target.
 *
 * Standalone: no dependency on coderifts-app. This is an independent port of the spec, exactly
 * like verify-attest.js and verify-grant.js. Node >= 20, zero dependencies (node:crypto only).
 *
 * WHAT A VALID RESULT MEANS, and it is narrow on purpose:
 *   PROVES  a holder of the declarer's key stated, at declared_at, that the set with this digest
 *           is the complete set of mutating tools, under the named framework/guard versions.
 *   DOES NOT PROVE  that the statement is true. Nothing here inspects a running process. A tool
 *           absent from the declaration is absent from this artifact too. Sampling
 *           (@coderifts/bypass-probe) is the other half; this is the accountable half.
 *
 * RETIRED KEYS follow the ATTESTATION rule, not the grant rule: a declaration authorises nothing,
 * so a key valid at declared_at still proves the declarer made the statement
 * (TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE). Window is half-open [valid_from, retired_at).
 * Contrast cr.exec.v1 grants, where a retired key is UNKNOWN_KEY because a grant is live permission.
 *
 * Exit: 0 when valid (TOOLSET_ATTEST_VALID or TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE),
 *       1 otherwise, 2 usage error.
 *
 *   node verify-toolset.js <token> --keys <file|url> [--entries <file>] [--declarer <name>]
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const ATTEST_VERSION = 'cr.toolset.attest.v1';
const SIGNING_PREFIX = 'crtoolsetattest.v1';
const ENVELOPE_TAG = 'cr.toolset.attest.v1';
const CLOCK_SKEW_LEEWAY_MS = 30000;
const MAX_ENTRIES = 512;

const STATEMENTS = Object.freeze([
  'this is the complete set of tools that can mutate a governed target',
]);
const MUTATION_CLASSES = Object.freeze(['mutating', 'readonly']);

const REQUIRED_FIELDS = Object.freeze(['kid', 'declarer', 'statement', 'set_digest', 'declared_at']);
const OPTIONAL_STRINGS = Object.freeze([
  'session_id', 'receipt_digest', 'scope_note', 'framework', 'framework_version', 'guard_version',
]);
const ALLOWED_KEYS = new Set([
  'v', ...REQUIRED_FIELDS, ...OPTIONAL_STRINGS, 'tool_count', 'mutating_count', 'meta',
]);

const STATUSES = Object.freeze({
  TOOLSET_ATTEST_VALID: 'TOOLSET_ATTEST_VALID',
  TOOLSET_ATTEST_INVALID_SIGNATURE: 'TOOLSET_ATTEST_INVALID_SIGNATURE',
  TOOLSET_ATTEST_UNKNOWN_KEY: 'TOOLSET_ATTEST_UNKNOWN_KEY',
  TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE: 'TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  TOOLSET_ATTEST_MALFORMED: 'TOOLSET_ATTEST_MALFORMED',
  TOOLSET_ATTEST_UNBOUND: 'TOOLSET_ATTEST_UNBOUND',
});

const scalar = (v) => (v == null ? '' : String(v));
const optional = (v) => (v != null && String(v).length > 0 ? String(v) : '');
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

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
    if (k.includes('|')) return false;
    const v = meta[k];
    const t = typeof v;
    if (t !== 'string' && t !== 'number' && t !== 'boolean') return false;
    if (t === 'string' && (v.length > 256 || v.includes('|'))) return false;
  }
  return true;
}

function signingInput(body) {
  const parts = [
    SIGNING_PREFIX,
    scalar(body.kid), scalar(body.declarer), scalar(body.statement),
    scalar(body.set_digest), scalar(body.declared_at),
    optional(body.session_id), optional(body.receipt_digest),
    optional(body.framework), optional(body.framework_version), optional(body.guard_version),
    body.tool_count == null ? '' : String(body.tool_count),
    body.mutating_count == null ? '' : String(body.mutating_count),
    optional(body.scope_note),
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

function computeSetDigest(entries) {
  if (!Array.isArray(entries)) return { ok: false, reason: 'entries_not_array' };
  if (entries.length === 0) return { ok: false, reason: 'entries_empty' };
  if (entries.length > MAX_ENTRIES) return { ok: false, reason: 'entries_too_many' };
  const seen = new Set();
  const rows = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, reason: 'entry_not_object' };
    const name = e.name;
    const cls = e.mutation_class;
    const sd = e.input_schema_digest;
    if (typeof name !== 'string' || !name || name.length > 128) return { ok: false, reason: 'bad_entry_name' };
    if (name.includes('|')) return { ok: false, reason: 'delimiter_in_entry_name' };
    if (!MUTATION_CLASSES.includes(cls)) return { ok: false, reason: 'bad_mutation_class' };
    if (sd != null) {
      if (typeof sd !== 'string' || !sd.startsWith('sha256:') || sd.includes('|')) {
        return { ok: false, reason: 'bad_input_schema_digest' };
      }
    }
    if (seen.has(name)) return { ok: false, reason: 'duplicate_entry_name' };
    seen.add(name);
    rows.push([name, cls, sd == null ? '' : sd]);
  }
  rows.sort((a, b) => (a[0] < b[0] ? -1 : (a[0] > b[0] ? 1 : 0)));
  const canonical = rows.map((r) => r.join(' ')).join('');
  return {
    ok: true,
    digest: 'sha256:' + sha256hex(canonical),
    tool_count: rows.length,
    mutating_count: rows.filter((r) => r[1] === 'mutating').length,
  };
}

/** Half-open [valid_from, retired_at): equal to retired_at is OUTSIDE. */
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

function resolveDeclarerKey(registry, kid) {
  if (!registry || !Array.isArray(registry.keys) || typeof kid !== 'string' || !kid) return null;
  const matches = registry.keys.filter((k) => k && k.kid === kid && typeof k.public_key_pem === 'string');
  if (matches.length === 0) return null;
  const entry = matches.find((k) => k.status === 'active') || matches[0];
  try {
    return {
      publicKey: crypto.createPublicKey(entry.public_key_pem),
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

const fail = (status, reason, payload) => ({ valid: false, status, reason, payload: payload || null });
const okStatus = (status, payload) => ({ valid: true, status, reason: null, payload });

function parseAttestToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  const segments = token.split('|');
  if (segments.length !== 4 || segments.some((s) => !s)) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  if (segments[0] !== ENVELOPE_TAG) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'unsupported_version' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[2], 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (payload.v !== ATTEST_VERSION) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'unsupported_version', payload };
  }
  for (const k of REQUIRED_FIELDS) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'missing_field', payload };
    }
  }
  if (!STATEMENTS.includes(payload.statement)) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_statement', payload };
  }
  if (!payload.set_digest.startsWith('sha256:')) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_set_digest', payload };
  }
  for (const k of OPTIONAL_STRINGS) {
    if (payload[k] != null && typeof payload[k] !== 'string') {
      return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_optional', payload };
    }
  }
  const hasFw = payload.framework != null && payload.framework !== '';
  const hasFwV = payload.framework_version != null && payload.framework_version !== '';
  if (hasFw !== hasFwV) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'framework_version_unpaired', payload };
  }
  for (const k of ['tool_count', 'mutating_count']) {
    const v = payload[k];
    if (v != null && (typeof v !== 'number' || !Number.isInteger(v) || v < 0)) {
      return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_' + k, payload };
    }
  }
  if (Number.isInteger(payload.tool_count) && Number.isInteger(payload.mutating_count)
      && payload.mutating_count > payload.tool_count) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'mutating_exceeds_total', payload };
  }
  if (payload.receipt_digest != null && payload.receipt_digest !== ''
      && !payload.receipt_digest.startsWith('sha256:')) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'bad_receipt_digest', payload };
  }
  if (payload.kid !== segments[1]) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'kid_mismatch', payload };
  }
  for (const k of Object.keys(payload)) {
    if (!ALLOWED_KEYS.has(k)) {
      return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'unknown_field', payload };
    }
  }
  if (!metaOk(payload.meta)) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'meta_bounds', payload };
  }
  if (fieldHasDelimiter(payload)) {
    return { ok: false, status: STATUSES.TOOLSET_ATTEST_MALFORMED, reason: 'delimiter_in_field', payload };
  }
  return { ok: true, payload, sig: segments[3] };
}

function verifyToolsetAttestation(token, opts) {
  // ── 1128: A THIRD ARGUMENT IS A CALLER ERROR, AND IT USED TO BE SILENT ──────────────────────
  //
  // This function is 2-ary while verifyReceipt and verifyExecutionGrant are 3-ary
  // (token, ctx, opts). A caller following their shape puts `intended` in a third argument, it is
  // dropped, the comparison at the `intended` block below never runs, and a MISMATCHED declaration
  // returns TOOLSET_ATTEST_VALID. Measured on TS-A-VALID with intended.declarer set to a foreign
  // value: TOOLSET_ATTEST_UNBOUND/declarer_mismatch when passed correctly, TOOLSET_ATTEST_VALID
  // when passed third — the same fail-open the attestation verifier had.
  //
  // The arity is NOT changed here: that is breaking and belongs to a versioned wave. What is
  // closed is the SILENCE. Python needs no equivalent — verify_toolset_attestation is
  // keyword-based and raises on an unexpected positional.
  if (arguments.length > 2) {
    throw new Error(
      'verifyToolsetAttestation(token, opts) — pass intended via opts.intended. '
      + `Received ${arguments.length} arguments; the third would be ignored and the cross-check `
      + 'would silently not run, grading a mismatched declaration TOOLSET_ATTEST_VALID.',
    );
  }
  const o = Object.assign({}, opts || {});
  if (o.ctx && o.registry == null && o.ctx.registry) o.registry = o.ctx.registry;
  if (o.ctx && o.entries == null && o.ctx.entries) o.entries = o.ctx.entries;
  const parsed = parseAttestToken(token);
  if (!parsed.ok) return fail(parsed.status, parsed.reason, parsed.payload);
  const payload = parsed.payload;

  const resolved = resolveDeclarerKey(o.registry, payload.kid);
  if (!resolved) return fail(STATUSES.TOOLSET_ATTEST_UNKNOWN_KEY, 'kid_not_in_registry', payload);

  // KEY STATUS GATE — RECEIPT_FORMAT.md 7.1 (normative), same rule as verify.js.
  //
  // MEASURED 2026-08-26: this verifier returned {valid:true} for a REVOKED key. The window check
  // below fails closed on an unknown status, but the caller only invoked it for status==='retired',
  // so 'revoked' fell straight through to the healthy path. A window function that is never called
  // is not a gate.
  //
  // Attestations carry their own status vocabulary, so the revoked verdict is reported through
  // STATUSES.TOOLSET_ATTEST_UNKNOWN_KEY with a distinct REASON rather than by importing the receipt statuses -- the caller
  // branches on this artifact class's own vocabulary and must not have to learn a second one.
  {
    const st = resolved && resolved.status;
    if (st != null && st !== 'active' && st !== 'retired' && st !== 'revoked') {
      return fail(STATUSES.TOOLSET_ATTEST_UNKNOWN_KEY, 'unknown_key_status', payload);
    }
    if (st === 'revoked') {
      const at = resolved.compromised_at;
      const boundary = typeof at === 'string' && at ? Date.parse(at) : NaN;
      const issued = Date.parse(payload.declared_at || payload.observed_at || payload.ts);
      const decided = Number.isFinite(boundary) && Number.isFinite(issued) && issued >= boundary;
      return fail(STATUSES.TOOLSET_ATTEST_UNKNOWN_KEY, decided ? 'revoked_key' : 'revoked_key_undecidable', payload);
    }
  }


  let sigOk = false;
  try {
    sigOk = crypto.verify(null, Buffer.from(signingInput(payload), 'utf8'),
      resolved.publicKey, Buffer.from(parsed.sig, 'base64url'));
  } catch (_) {
    return fail(STATUSES.TOOLSET_ATTEST_INVALID_SIGNATURE, 'signature_error', payload);
  }
  if (!sigOk) return fail(STATUSES.TOOLSET_ATTEST_INVALID_SIGNATURE, 'signature_mismatch', payload);

  const nowMs = o.now == null ? Date.now() : o.now;
  const declMs = Date.parse(payload.declared_at);
  if (Number.isFinite(declMs) && Number.isFinite(nowMs) && declMs > nowMs + CLOCK_SKEW_LEEWAY_MS) {
    return fail(STATUSES.TOOLSET_ATTEST_MALFORMED, 'declared_at_in_future', payload);
  }

  if (o.entries != null) {
    const recomputed = computeSetDigest(o.entries);
    if (!recomputed.ok) return fail(STATUSES.TOOLSET_ATTEST_MALFORMED, 'entries_' + recomputed.reason, payload);
    if (recomputed.digest !== payload.set_digest) {
      return fail(STATUSES.TOOLSET_ATTEST_UNBOUND, 'set_digest_mismatch', payload);
    }
    if (Number.isInteger(payload.tool_count) && payload.tool_count !== recomputed.tool_count) {
      return fail(STATUSES.TOOLSET_ATTEST_UNBOUND, 'tool_count_mismatch', payload);
    }
    if (Number.isInteger(payload.mutating_count) && payload.mutating_count !== recomputed.mutating_count) {
      return fail(STATUSES.TOOLSET_ATTEST_UNBOUND, 'mutating_count_mismatch', payload);
    }
  }

  const intended = o.intended || null;
  if (intended) {
    for (const k of ['session_id', 'receipt_digest', 'declarer']) {
      if (intended[k] != null && String(intended[k]) !== String(payload[k] == null ? '' : payload[k])) {
        return fail(STATUSES.TOOLSET_ATTEST_UNBOUND, k + '_mismatch', payload);
      }
    }
  }

  if (resolved.status === 'retired') {
    if (!isIssueTimeWithinKeyWindow(payload.declared_at, resolved)) {
      return fail(STATUSES.TOOLSET_ATTEST_UNKNOWN_KEY, 'retired_key_outside_window', payload);
    }
    return okStatus(STATUSES.TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE, payload);
  }
  return okStatus(STATUSES.TOOLSET_ATTEST_VALID, payload);
}

module.exports = {
  ATTEST_VERSION, SIGNING_PREFIX, ENVELOPE_TAG, STATUSES, STATEMENTS, MUTATION_CLASSES,
  computeSetDigest, signingInput, verifyToolsetAttestation,
};

// ── CLI ────────────────────────────────────────────────────────────────────
async function loadKeys(ref) {
  if (/^https?:\/\//.test(ref)) {
    const res = await fetch(ref);
    if (!res.ok) throw new Error('keys fetch failed: HTTP ' + res.status);
    return res.json();
  }
  return JSON.parse(fs.readFileSync(ref, 'utf8'));
}

const USAGE =
  'usage: node verify-toolset.js <token> --keys <file|url> [--entries <file>] [--declarer <name>]\n';

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args[0].startsWith('-')) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  const token = args[0];
  let keysRef = null;
  let entriesRef = null;
  let declarer = null;
  for (let i = 1; i < args.length; i += 1) {
    if (args[i] === '--keys') { keysRef = args[i + 1]; i += 1; continue; }
    if (args[i] === '--entries') { entriesRef = args[i + 1]; i += 1; continue; }
    if (args[i] === '--declarer') { declarer = args[i + 1]; i += 1; continue; }
    process.stderr.write(USAGE);
    process.exit(2);
  }
  if (!keysRef) {
    process.stderr.write('--keys is required: this verifier NEVER fetches a default key registry.\n');
    process.exit(2);
  }
  let registry;
  let entries = null;
  try {
    registry = await loadKeys(keysRef);
    if (entriesRef) entries = JSON.parse(fs.readFileSync(entriesRef, 'utf8'));
  } catch (err) {
    process.stderr.write(String((err && err.message) || err) + '\n');
    process.exit(2);
  }
  const opts = { registry };
  if (entries != null) opts.entries = entries;
  if (declarer) opts.intended = { declarer };
  const result = verifyToolsetAttestation(token, opts);
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

if (require.main === module) {
  main(process.argv).catch((err) => {
    process.stderr.write(String((err && err.message) || err) + '\n');
    process.exit(2);
  });
}
