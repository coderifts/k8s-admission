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
 *   node cli.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]
 *   node cli.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]
 *
 * Key discovery: with no --key/--keys/--fetch/--refresh-keys, the command loads the
 * vendored snapshot at keys/coderifts-keys.json (offline). Live fetch is opt-in
 * (--refresh-keys or --fetch <url> / --keys <url>). DEFAULT_FETCH_URL is the well-known
 * registry used by those opt-in flags. This library never fetches.
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
 * 1.1.7 — strict JSON parse: RFC 8259 text, with the three inputs two parsers can read differently
 * REJECTED, not given one reading (RECEIPT_FORMAT §2.2; purysho/mcp-digest-vectors SPEC §2 rejects them too):
 *   duplicate_key   an object, at any depth, has two members with the same name after unescaping
 *                   (JSON.parse keeps the last one: a pin over a duplicate "description" pins whichever came last)
 *   lone_surrogate  a string holds an unpaired UTF-16 surrogate (JSON.parse passes it through;
 *                   canonicalJson then writes it as \udxxx)
 *   non_finite      a number is not finite as binary64 (1e400; JSON.parse gives Infinity)
 *   invalid_json    anything else that is not one JSON text (NaN, comments, trailing commas, …)
 * Throws a SyntaxError with .code and .pointer (RFC 6901). On valid input it returns what JSON.parse
 * returns. A separate function: canonicalJson and every existing caller are unchanged.
 */
function parseJsonStrict(text) {
  const src = String(text);
  let i = 0;
  const fail = (code, pointer, detail) => {
    const e = new SyntaxError(`${code}${pointer != null ? ` at ${pointer === '' ? '(root)' : pointer}` : ''}${detail ? `: ${detail}` : ''}`);
    e.code = code;
    e.pointer = pointer;
    throw e;
  };
  const ptr = (base, token) => `${base}/${String(token).replace(/~/g, '~0').replace(/\//g, '~1')}`;
  const ws = () => { while (i < src.length && (src[i] === ' ' || src[i] === '\t' || src[i] === '\n' || src[i] === '\r')) i += 1; };
  const expect = (ch, at) => { if (src[i] !== ch) fail('invalid_json', at, `expected '${ch}' at offset ${i}`); i += 1; };

  function str(at) {
    expect('"', at);
    let out = '';
    for (;;) {
      if (i >= src.length) fail('invalid_json', at, 'unterminated string');
      const c = src[i];
      if (c === '"') { i += 1; break; }
      if (c === '\\') {
        const e = src[i + 1];
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (e in simple) { out += simple[e]; i += 2; continue; }
        if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(src.slice(i + 2, i + 6))) { out += String.fromCharCode(parseInt(src.slice(i + 2, i + 6), 16)); i += 6; continue; }
        fail('invalid_json', at, `bad escape at offset ${i}`);
      }
      if (c.charCodeAt(0) < 0x20) fail('invalid_json', at, `control character in string at offset ${i}`);
      out += c;
      i += 1;
    }
    for (let k = 0; k < out.length; k += 1) {
      const u = out.charCodeAt(k);
      if (u >= 0xD800 && u <= 0xDBFF) {
        const next = out.charCodeAt(k + 1);
        if (next >= 0xDC00 && next <= 0xDFFF) { k += 1; continue; }
        fail('lone_surrogate', at, `unpaired \\u${u.toString(16)}`);
      }
      if (u >= 0xDC00 && u <= 0xDFFF) fail('lone_surrogate', at, `unpaired \\u${u.toString(16)}`);
    }
    return out;
  }

  function num(at) {
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(src.slice(i));
    if (!m) fail('invalid_json', at, `unexpected '${src[i] === undefined ? 'end of input' : src[i]}' at offset ${i}`);
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) fail('non_finite', at, m[0]);
    return n;
  }

  function value(at) {
    ws();
    const c = src[i];
    let v;
    if (c === '{') {
      i += 1;
      v = {};
      const seen = new Set();
      ws();
      if (src[i] === '}') { i += 1; return v; }
      for (;;) {
        ws();
        const key = str(at);
        const here = ptr(at, key);
        if (seen.has(key)) fail('duplicate_key', here);
        seen.add(key);
        ws();
        expect(':', here);
        const member = value(here);
        // JSON.parse makes "__proto__" an own data property; so does this.
        Object.defineProperty(v, key, { value: member, writable: true, enumerable: true, configurable: true });
        ws();
        if (src[i] === ',') { i += 1; continue; }
        expect('}', at);
        break;
      }
    } else if (c === '[') {
      i += 1;
      v = [];
      ws();
      if (src[i] === ']') { i += 1; return v; }
      for (;;) {
        v.push(value(ptr(at, v.length)));
        ws();
        if (src[i] === ',') { i += 1; continue; }
        expect(']', at);
        break;
      }
    } else if (c === '"') {
      v = str(at);
    } else if (src.startsWith('true', i)) { i += 4; v = true; } else if (src.startsWith('false', i)) { i += 5; v = false; } else if (src.startsWith('null', i)) { i += 4; v = null; } else {
      v = num(at);
    }
    return v;
  }

  const result = value('');
  ws();
  if (i !== src.length) fail('invalid_json', '', `unexpected data at offset ${i}`);
  return result;
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
  const single = { publicKey: ctx.publicKey, status: null, retired_at: null, revoked_at: null, compromised_at: null };
  // 1.1.5: a --key PEM classified by classifyPublicKeyPem (cli.js) carries its algorithm verdict.
  if (ctx.unsupportedAlg) single.unsupported_alg = ctx.unsupportedAlg;
  return single;
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
  //
  // 10t-rv (2026-11-05) — THE NORMATIVE ORDER (RECEIPT_FORMAT.md §7.1), one row each:
  //   1. a status this verifier does not know      → UNKNOWN_KEY_STATUS (above; fail-closed)
  //   2. revoked                                    → REVOKED_KEY at every signing time; compromised_at
  //                                                   is carried in the result, it does not soften it
  //   3. retired, signed at or after retired_at     → KEY_RETIRED_AFTER_SIGNING
  //   4. retired, signed before retired_at, with an
  //      independent time anchor                    → RETIRED_KEY_VALID_AT_ISSUE — NOT REACHABLE: no
  //                                                   anchor input exists in this verifier (no RFC 3161
  //                                                   token, no transparency-log inclusion is read)
  //   5. retired, signed before retired_at, no anchor → RETIRED_KEY_UNANCHORED (valid:false)
  //   6. active                                     → the signature decides (below)
  // MEASURED before (d7d30a09 / 15fbdc4): retired_at was read BEFORE the revoked status, so a key both
  // revoked and retired answered KEY_RETIRED_AFTER_SIGNING for ts >= retired_at; a revoked key with
  // ts < compromised_at answered REVOKED_KEY_UNDECIDABLE; and a retired key's ts < retired_at answered
  // RETIRED_KEY_VALID_AT_ISSUE, valid:true — on a timestamp the signer chooses.
  // revoked_at (1079 B) is the older revocation field: every receipt under the key is KEY_REVOKED.
  if (typeof entry.revoked_at === 'string' && entry.revoked_at.length > 0) {
    return 'KEY_REVOKED';
  }
  if (entry.status === 'revoked') return 'REVOKED_KEY';
  if (entry.status === 'retired') {
    const issued = payload.ts ? Date.parse(payload.ts) : NaN;
    const retired = typeof entry.retired_at === 'string' && entry.retired_at.length > 0 ? Date.parse(entry.retired_at) : NaN;
    if (!Number.isFinite(issued) || !Number.isFinite(retired)) return 'INVALID_SIGNATURE'; // no boundary to judge by
    return issued >= retired ? 'KEY_RETIRED_AFTER_SIGNING' : 'RETIRED_KEY_UNANCHORED';
  }
  // An active entry that carries retired_at (a retirement announced ahead): ts at or after it is refused.
  if (typeof entry.retired_at === 'string' && entry.retired_at.length > 0 && payload.ts) {
    const issued = Date.parse(payload.ts);
    const retired = Date.parse(entry.retired_at);
    if (Number.isFinite(issued) && Number.isFinite(retired) && issued >= retired) {
      return 'KEY_RETIRED_AFTER_SIGNING';
    }
  }
  const now = opts.now != null ? opts.now : Date.now();
  const expired = payload.v === 4 && typeof payload.expires_at === 'string'
    && isExpiredAt(Date.parse(payload.expires_at), now, opts.envelope || { environment: opts.expectedEnvironment });
  if (expired) return 'VERIFIED_EXPIRED';
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
  // 1.1.1 (2026-10-12, audit-2 F6): a signed field is a string or absent — checked before the signature, so
  // both verifiers answer alike. MEASURED: `expires_at: [...]` passed the '|' guard (string-only) and the v4
  // expiry check (string-only), and an expired receipt verified VERIFIED_CURRENT.
  for (const k of SIGNED_FIELDS) {
    if (payload[k] !== undefined && typeof payload[k] !== 'string') {
      return { valid: false, status: 'MALFORMED', reason: 'non_string_signed_field', field: k, payload };
    }
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
  // 3b. 1.1.5: only an Ed25519 key verifies a receipt (classifyPublicKeyPem).
  const unsupportedAlg = entry.unsupported_alg || (entry.publicKey ? unsupportedKeyObjectAlg(entry.publicKey) : null);
  if (unsupportedAlg) {
    return { valid: false, status: 'INVALID_SIGNATURE', reason: `unsupported key algorithm: ${unsupportedAlg}`, payload };
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
  // 10t-rv: the key's compromised_at rides with the verdict (null when the registry gives none).
  if (status === 'REVOKED_KEY') {
    return { valid: false, status, compromised_at: typeof entry.compromised_at === 'string' && entry.compromised_at ? entry.compromised_at : null, payload };
  }
  if (status === 'KEY_RETIRED_AFTER_SIGNING') {
    return { valid: false, status, reason: 'KEY_RETIRED_AFTER_SIGNING', payload };
  }
  if (status === 'INVALID_SIGNATURE') {
    return { valid: false, status, reason: 'retired_key_after_issue', payload };
  }
  // RETIRED_KEY_VALID_AT_ISSUE stays in the valid set for row 4 of the table, which needs an anchor input
  // this verifier does not have yet; deriveStatus does not return it today.
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

/*
 * 1.1.5 (2026-10-25) — ONLY ED25519 VERIFIES A RECEIPT, IN BOTH PORTS.
 *
 * MEASURED 2026-10-25 (Node 24.12): a keyring entry carrying an ML-DSA-65 PEM loaded, and a receipt
 * ML-DSA-signed under that kid came back { valid: true, VERIFIED_CURRENT } — crypto.verify(null, …)
 * accepts any key type Node knows. verify.py already refused a non-Ed25519 key, but by throwing at load,
 * so the same keyring took the whole Python run down while JS accepted. The algorithm is now read from
 * the SPKI AlgorithmIdentifier OID by the same few lines in both ports (never from what a crypto library
 * happens to support), and a declared `alg` other than Ed25519 is refused too, even over an Ed25519 PEM.
 * Refused = valid:false, status INVALID_SIGNATURE (an existing status), reason
 * "unsupported key algorithm: <alg>".
 */
const ED25519_OID = '1.3.101.112';
const KEY_ALG_NAMES = Object.freeze({
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '1.2.840.10045.2.1': 'EC',
  '1.2.840.113549.1.1.1': 'RSA',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
});
const SUPPORTED_DECLARED_ALGS = new Set(['ed25519', 'eddsa']);

/** The DER bytes of a `PUBLIC KEY` PEM block, or null. Strict base64 (verify.py decodes the same way). */
function spkiDerFromPem(pem) {
  const m = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/.exec(String(pem || ''));
  if (!m) return null;
  const body = m[1].replace(/\s+/g, '');
  if (!body || body.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return null;
  return Buffer.from(body, 'base64');
}

function readTlv(buf, off) {
  if (off + 2 > buf.length) return null;
  const tag = buf[off];
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || p + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) return null;
  return { tag, start: p, end: p + len };
}

/** The AlgorithmIdentifier OID of an SPKI DER, dotted, or null when it is not an SPKI. */
function spkiAlgorithmOid(der) {
  const outer = readTlv(der, 0);
  if (!outer || outer.tag !== 0x30 || outer.end !== der.length) return null;
  const alg = readTlv(der, outer.start);
  if (!alg || alg.tag !== 0x30) return null;
  const oid = readTlv(der, alg.start);
  if (!oid || oid.tag !== 0x06 || oid.end > alg.end || oid.end === oid.start) return null;
  const bytes = der.subarray(oid.start, oid.end);
  const first = bytes[0];
  const a = first < 40 ? 0 : (first < 80 ? 1 : 2);
  const parts = [a, first - 40 * a];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; } else if (i === bytes.length - 1) return null;
  }
  return parts.join('.');
}

/**
 * Classify one PEM for receipt verification. Never throws.
 *   { publicKey, key_sha256 }                         an Ed25519 key (key_sha256: hex sha256 of the SPKI DER)
 *   { publicKey: null, key_sha256, unsupported_alg }  a parseable key of another algorithm, or a declared
 *                                                     `alg` other than Ed25519
 *   { unparseable: true }                             not an SPKI PEM at all
 */
function classifyPublicKeyPem(pem, declaredAlg) {
  const der = spkiDerFromPem(pem);
  if (!der) return { unparseable: true };
  const oid = spkiAlgorithmOid(der);
  if (!oid) return { unparseable: true };
  const key_sha256 = crypto.createHash('sha256').update(der).digest('hex');
  if (declaredAlg !== undefined && declaredAlg !== null && !SUPPORTED_DECLARED_ALGS.has(String(declaredAlg).toLowerCase())) {
    return { publicKey: null, key_sha256, unsupported_alg: String(declaredAlg) || '(empty)' };
  }
  if (oid !== ED25519_OID) return { publicKey: null, key_sha256, unsupported_alg: KEY_ALG_NAMES[oid] || oid };
  try {
    return { publicKey: crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }), key_sha256 };
  } catch (_) {
    return { unparseable: true };
  }
}

/** For a caller-built KeyObject (library use): the algorithm when it is not Ed25519, else null. */
function unsupportedKeyObjectAlg(key) {
  const t = key && key.asymmetricKeyType;
  if (!t || t === 'ed25519') return null;
  const named = { ed448: 'Ed448', rsa: 'RSA', 'rsa-pss': 'RSA-PSS', ec: 'EC', 'ml-dsa-44': 'ML-DSA-44', 'ml-dsa-65': 'ML-DSA-65', 'ml-dsa-87': 'ML-DSA-87' };
  return named[t] || t;
}

/**
 * Build a kid -> key map from a registry document
 * ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }).
 * Returns null when `keys` is missing/empty so the caller can try the legacy
 * single-key body. --keys still requires a non-empty keys[] (throws).
 */
function keyringFromDocument(doc, source, warnings) {
  const keys = doc && Array.isArray(doc.keys) ? doc.keys : null;
  if (!keys || keys.length === 0) return null;
  const keyring = new Map();
  // 1.1.5: TOLERANT PER ENTRY. MEASURED 2026-10-25: one entry with a bad PEM, or with no
  // public_key_pem, threw here and the whole keyring failed to load — the good keys beside it were
  // unusable ("could not load public key", exit 2). Now that entry is skipped, the reason goes to
  // `warnings` (the CLI prints them as keyring_warnings), and every other key still verifies.
  const warn = (msg) => { if (Array.isArray(warnings)) warnings.push(msg); };
  keys.forEach((k, i) => {
    if (!k || typeof k !== 'object' || Array.isArray(k)) { warn(`registry entry #${i}: not an object — skipped`); return; }
    if (!k.kid) { warn(`registry entry #${i}: missing kid — skipped`); return; }
    if (!k.public_key_pem) { warn(`registry entry ${k.kid}: missing public_key_pem — skipped`); return; }
    const key = classifyPublicKeyPem(k.public_key_pem, k.alg);
    if (key.unparseable) { warn(`registry entry ${k.kid}: unparseable public_key_pem — skipped`); return; }
    // compromised_at MUST be carried through: deriveStatus reads it for the revoked rule
    // (RECEIPT_FORMAT.md 7.1). Dropping it here made the rule inert — every revoked key
    // returned UNDECIDABLE regardless of ts, which looks implemented and decides nothing.
    const entry = {
      publicKey: key.publicKey,
      status: k.status || null,
      retired_at: k.retired_at || null,
      revoked_at: k.revoked_at || null,
      compromised_at: k.compromised_at || null,
      key_sha256: key.key_sha256,
    };
    if (key.unsupported_alg) entry.unsupported_alg = key.unsupported_alg;
    keyring.set(k.kid, entry);
  });
  return keyring;
}

/** The active entry that can verify (an unsupported-algorithm entry cannot), else the first that can. */
function pickActiveFromKeyring(keyring) {
  for (const [kid, entry] of keyring) {
    if (entry.status === 'active' && entry.publicKey) return { kid, entry };
  }
  for (const [kid, entry] of keyring) {
    if (entry.publicKey) return { kid, entry };
  }
  return null;
}

/**
 * Build a kid -> key map from a CodeRifts key registry
 * ({ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }). A --keys source may be
 * an http(s) URL or a local file path. Both active and retired keys are loaded.
 */
async function loadKeyring(source, warnings) {
  let text;
  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${source} -> HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = fs.readFileSync(source, 'utf8');
  }
  const doc = JSON.parse(text);
  const local = [];
  const keyring = keyringFromDocument(doc, source, local);
  if (Array.isArray(warnings)) warnings.push(...local);
  if (!keyring) throw new Error(`no keys[] in registry ${source}`);
  if (keyring.size === 0) throw new Error(`no usable keys in registry ${source}: ${local.join('; ')}`);
  return keyring;
}

/**
 * 1.1.4 (2026-10-18): a receipt used beside an envelope must be v4 — the rule moves here from cli.js
 * (1.1.1, P66), so every consumer of the core gets it. MEASURED 2026-10-17: two gateways that vendored
 * this core admitted a production-signed v2 receipt beside a forged ALLOW envelope, because the core
 * answered valid:true; v1–v3 bind no envelope (no `bh`) and carry no expiry. Any envelope object counts,
 * `{}` included (the CLI's JS truthiness). A bare token with no envelope stays a signature check, and
 * verifyChain is unchanged (it checks links, not an envelope per link).
 */
function v4EnvelopeRule(result, opts) {
  const v = result && result.payload && result.payload.v;
  if (!opts || !opts.envelope || !result || !result.valid || !result.payload || v === 4) return result;
  return { ...result, valid: false, signature_status: result.status, status: 'RECEIPT_VERSION_UNSUPPORTED',
    reason: `receipt version v${v} binds no envelope and carries no expiry; only a v4 receipt is accepted with an envelope or --from-commit` };
}

/**
 * 1.1.6 (2026-10-29) — AUDIT MODE: `asOf`, "was this receipt inside its window at a stated instant?".
 * A v4 receipt carries a signed expires_at (merge: 4 h); after it (+ leeway) the normal answer is
 * VERIFIED_EXPIRED, which cannot answer an after-incident question. With asOf the EXPIRY COMPARISON
 * uses that instant instead of now; nothing else moves: the signature, the key lookup, every key-status
 * rule (RECEIPT_FORMAT §7.1 — a revoked key is valid:false at any asOf; a retired key exactly as
 * today), the envelope binding and the v4-with-envelope rule run unchanged, because the core is the
 * same call with `now` = asOf. asOf never turns a refusal into a pass: only a verdict the core already
 * reached is re-labelled.
 */
const AS_OF_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const AS_OF_NOTE = 'no expiry to evaluate; as-of has no effect';

/** An as-of input → epoch ms. Throws a TypeError with .code 'as_of_unparsable' / 'as_of_in_future'. */
function parseAsOf(value, nowMs = Date.now()) {
  const text = typeof value === 'string' ? value : (value instanceof Date ? value.toISOString() : null);
  const ms = text && AS_OF_RE.test(text) ? Date.parse(text) : NaN;
  if (!Number.isFinite(ms)) {
    const err = new TypeError(`--as-of must be an ISO 8601 instant with a zone (e.g. 2026-10-29T13:00:00Z): ${String(value)}`);
    err.code = 'as_of_unparsable';
    throw err;
  }
  if (ms > nowMs + CLOCK_SKEW_LEEWAY_MS) {
    const err = new RangeError(`as_of_in_future: ${new Date(ms).toISOString()} is later than now + ${CLOCK_SKEW_LEEWAY_MS / 1000}s`);
    err.code = 'as_of_in_future';
    throw err;
  }
  return ms;
}

/** The audit fields for a verdict the core reached with now = asOf. */
function auditResult(result, asOfMs, nowMs, opts) {
  const p = result && result.payload;
  const asOf = new Date(asOfMs).toISOString();
  const window = { ts: p && typeof p.ts === 'string' ? p.ts : null, expires_at: p && p.v === 4 && typeof p.expires_at === 'string' ? p.expires_at : null };
  const base = { ...result, mode: 'audit', as_of: asOf, window };
  if (!window.expires_at) {
    // 1.1.8: v1–v3 have no expiry, but they have ts. An as-of before the signed ts is before the receipt
    // existed: NOT_YET_VALID_AT_AS_OF (valid:false), the status v4 already gives. MEASURED on 1.1.7: a v1/v2/v3
    // receipt (ts 2026-10-01T12:00Z) with --as-of 2026-09-30T12:00Z was valid:true, VERIFIED_CURRENT, exit 0.
    // Only a verdict that passed can be re-labelled; any other result stays as it is.
    const issuedAt = window.ts ? Date.parse(window.ts) : NaN;
    if (result.valid === true && Number.isFinite(issuedAt) && asOfMs < issuedAt) {
      return { ...base, valid: false, status: 'NOT_YET_VALID_AT_AS_OF', reason: 'as_of_before_issue', valid_at_as_of: false, expired_now: false };
    }
    // At or after ts: today's result, unchanged; the note says why as-of did nothing more.
    return { ...base, valid_at_as_of: result.valid === true, expired_now: false, as_of_note: AS_OF_NOTE };
  }
  const exp = Date.parse(window.expires_at);
  const context = opts.envelope || { environment: opts.expectedEnvironment };
  const expiredNow = isExpiredAt(exp, nowMs, context);
  const issued = Date.parse(window.ts);
  const beforeIssue = Number.isFinite(issued) && asOfMs < issued;
  const insideWindow = !beforeIssue && !isExpiredAt(exp, asOfMs, context);
  // Only a verdict that passed the signature and every key rule can be re-labelled.
  const reachedWindow = result.valid === true || result.status === 'VERIFIED_EXPIRED';
  if (!reachedWindow) return { ...base, valid_at_as_of: false, expired_now: expiredNow };
  if (beforeIssue) {
    return { ...base, valid: false, status: 'NOT_YET_VALID_AT_AS_OF', reason: 'as_of_before_issue', valid_at_as_of: false, expired_now: expiredNow };
  }
  if (result.status === 'VERIFIED_CURRENT') {
    return { ...base, valid: true, status: 'VERIFIED_AT_AS_OF', valid_at_as_of: true, expired_now: expiredNow };
  }
  // VERIFIED_EXPIRED at asOf, a retired key valid at issue (status kept, as today), or a dormant check
  // status: the verdict stays; valid_at_as_of says whether asOf was inside the window as well.
  return { ...base, valid_at_as_of: result.valid === true && insideWindow, expired_now: expiredNow };
}

function verifyReceipt(token, second, third) {
  const { ctx, opts } = split3ary('verifyReceipt', arguments.length, second, third);
  if (opts && opts.asOf != null) {
    const nowMs = opts.now != null ? opts.now : Date.now();
    const asOfMs = parseAsOf(opts.asOf, nowMs);
    const atAsOf = v4EnvelopeRule(verifyReceiptInner(token, ctx, { ...opts, now: asOfMs }), opts);
    return auditResult(atAsOf, asOfMs, nowMs, opts);
  }
  return v4EnvelopeRule(verifyReceiptInner(token, ctx, opts), opts);
}

function verifyChain(tokens, second, third) {
  const { ctx, opts } = split3ary('verifyChain', arguments.length, second, third);
  return verifyChainInner(tokens, ctx, opts);
}

// Reusable API — require('./verify') imports the pure verify logic WITHOUT running the CLI; the
// receipt format + taxonomy are frozen in RECEIPT_FORMAT.md.
//
// WHO ACTUALLY CALLS THESE, measured across the public surface on 2026-09-13:
//   verifyChain    — cli.js:219 (--chain, with a test) and the Python verifier's public API
//                    (coderifts_verifier/_verify.py verify_chain).
//   verifyReceipt  — the contract-gate Action.
// The previous wording said "the GitHub Action + other embedders use these directly" and listed
// verifyChain first. That is false for the Action: contract-gate calls verifyReceipt and never
// verifyChain — its copy of this file only carries the definition. Naming the callers instead of
// a category keeps the claim checkable.
module.exports = {
  verifyReceipt,
  verifyChain,
  deriveStatus,
  resolveEntry,
  reconstructSignedInput,
  canonicalJson,
  parseJsonStrict,
  loadKeyring,
  keyFromPem,
  keyringFromDocument,
  classifyPublicKeyPem,
  spkiDerFromPem,
  spkiAlgorithmOid,
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
  parseAsOf,
  AS_OF_NOTE,
};
