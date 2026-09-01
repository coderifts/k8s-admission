'use strict';

/**
 * The vendored verify core is the canonical one, and it still refuses a key the
 * registry has withdrawn.
 *
 * Three halves, because none alone is enough.
 *
 * The DIGEST half fails when a pinned file drifts from `src/VENDOR.sha256`.
 *
 * The CORPUS half runs the shared cross-language vector set — the same file the
 * Python verifier is checked against — and asserts this core reaches the exact
 * status each vector records, not merely the same accept/reject. One corpus
 * governing every implementation is the point: a divergence that only one
 * language notices is the failure a multi-language verifier exists to avoid.
 *
 * The LOCAL half keeps what the corpus cannot carry. MEASURED: every corpus
 * token is a `v: 1` receipt, while these gates verify `v: 4` — the version with
 * `expires_at` and the envelope body-hash binding. A v4 receipt bound to an
 * envelope is repo-specific, so it is minted here.
 *
 * MEASURED 2026-08-26: an earlier vendored core read `status` only for
 * 'retired'. Every other value, 'revoked' included, fell through to the healthy
 * path and returned { valid: true, status: 'VERIFIED_CURRENT' }. An operator who
 * marked a stolen key revoked would have believed they had acted while this
 * verifier kept accepting its signatures. The corpus carries that measurement.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const core = require('../src/verify.js');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const PIN_FILE = path.join(SRC, 'VENDOR.sha256');
const CORPUS_FILE = path.join(__dirname, 'fixtures', 'xlang-vectors.json');

/** A pin entry naming a path (with a slash) resolves from the repo root; a bare name from src/. */
const resolvePinned = (name) => (name.includes('/') ? path.join(ROOT, name) : path.join(SRC, name));
const sha256File = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

describe('vendored core — digests match the pin', () => {
  const pinned = fs.readFileSync(PIN_FILE, 'utf8').trim().split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter(([name]) => name.endsWith('.js') || name.endsWith('.json'));

  it('the pin covers verify.js, arity.js and the shared corpus', () => {
    const names = pinned.map(([n]) => n);
    assert.ok(names.includes('verify.js'), 'verify.js must be pinned');
    assert.ok(names.includes('arity.js'), 'arity.js must be pinned');
    assert.ok(
      names.some((n) => n.endsWith('xlang-vectors.json')),
      'the shared corpus must be pinned, or it could be edited to agree with a broken core',
    );
  });

  for (const [name, digest] of pinned) {
    it(`${name} is byte-identical to its pinned digest`, () => {
      assert.equal(
        sha256File(resolvePinned(name)), digest,
        `${name} drifted from src/VENDOR.sha256 — recopy from source, or update the pin deliberately`,
      );
    });
  }
});

// ── the shared cross-language corpus ────────────────────────────────────────
const CORPUS = JSON.parse(fs.readFileSync(CORPUS_FILE, 'utf8'));

/**
 * The keyring the vector says was published for its kid. Each vector carries its
 * own `key` block, because the verdict depends on what the registry says about
 * the key and not only on the signed bytes.
 */
function keyringFor(key) {
  const entry = key || { status: 'active' };
  return new Map([[CORPUS.kid, {
    publicKey: core.keyFromPem(CORPUS.public_key_pem),
    status: entry.status ?? null,
    retired_at: entry.retired_at ?? null,
    revoked_at: entry.revoked_at ?? null,
    compromised_at: entry.compromised_at ?? null,
  }]]);
}

describe('vendored core — the shared cross-language corpus', () => {
  for (const vector of CORPUS.vectors) {
    it(`${vector.name} → ${vector.js.valid ? 'accept' : 'reject'} ${vector.js.status}`, () => {
      const r = core.verifyReceipt(vector.token, { ctx: { keyring: keyringFor(vector.key), expectedKid: null } });
      assert.equal(r.valid, vector.js.valid, `${vector.name}: accept/reject`);
      // The exact status, not just valid:false — a core that rejected this for
      // an unrelated reason would otherwise pass.
      assert.equal(r.status, vector.js.status, `${vector.name}: status`);
    });
  }

  it('the corpus still carries the withdrawal class it was extended for', () => {
    const statuses = new Set(CORPUS.vectors.map((v) => v.js.status));
    for (const required of ['REVOKED_KEY', 'REVOKED_KEY_UNDECIDABLE', 'KEY_REVOKED',
      'KEY_RETIRED_AFTER_SIGNING', 'UNKNOWN_KEY_STATUS']) {
      assert.ok(statuses.has(required), `the corpus no longer covers ${required}`);
    }
  });

  it('the corpus is not all-reject: a passing vector proves the vectors are live', () => {
    const accepted = CORPUS.vectors.filter((v) => v.js.valid);
    assert.ok(accepted.length >= 1, 'a corpus that rejects everything would pass against a broken core');
  });
});

// ── what the corpus cannot carry: a v4 receipt ──────────────────────────────
describe('vendored core — v4, the version this gate verifies', () => {
  const KID = 'v4-local-k1';
  const kp = crypto.generateKeyPairSync('ed25519');
  const PEM = kp.publicKey.export({ type: 'spki', format: 'pem' });
  const BOUNDARY = '2026-06-01T00:00:00.000Z';
  const b64url = (b) => Buffer.from(b).toString('base64url');

  function mint(ts) {
    const p = {
      v: 4, kid: KID, fp: `sha256:${'a'.repeat(64)}`, prev: 'null', caller: 'bundle', ts,
      reg: 'r'.repeat(64), ir: `sha256:${'b'.repeat(64)}`,
      expires_at: '2027-01-01T00:00:00.000Z', bh: `sha256:${'c'.repeat(64)}`,
    };
    const si = `crchain.v1|${p.kid}|${p.fp}|${p.prev}|${p.caller}|${p.ts}|${p.reg}|${p.ir}|${p.expires_at}|${p.bh}`;
    return `${b64url(JSON.stringify(p))}.${b64url(crypto.sign(null, Buffer.from(si, 'utf8'), kp.privateKey))}`;
  }
  const SIGNED_BEFORE = mint('2026-01-01T00:00:00.000Z');
  const SIGNED_AFTER = mint('2026-08-01T00:00:00.000Z');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vendor-pin-'));
  async function verifyWith(entry, token) {
    const file = path.join(tmp, `${crypto.randomUUID()}.json`);
    fs.writeFileSync(file, JSON.stringify({ keys: [{ kid: KID, alg: 'Ed25519', public_key_pem: PEM, ...entry }] }));
    const keyring = await core.loadKeyring(file);
    // skipBodyHash: this vector is about the KEY's registry state, not envelope binding.
    return core.verifyReceipt(token, { ctx: { keyring, expectedKid: null }, skipBodyHash: true });
  }

  it('control: an active key verifies a v4 receipt', async () => {
    const r = await verifyWith({ status: 'active' }, SIGNED_AFTER);
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
  });

  it('a revoked key is refused on v4 too, not only on the corpus v1 tokens', async () => {
    const r = await verifyWith({ status: 'revoked', compromised_at: BOUNDARY }, SIGNED_AFTER);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'REVOKED_KEY');
  });

  it('planned rotation on v4: signed before retired_at stays valid, after does not', async () => {
    const ok = await verifyWith({ status: 'retired', retired_at: BOUNDARY }, SIGNED_BEFORE);
    assert.equal(ok.status, 'RETIRED_KEY_VALID_AT_ISSUE');
    assert.equal(ok.valid, true);

    const no = await verifyWith({ status: 'retired', retired_at: BOUNDARY }, SIGNED_AFTER);
    assert.equal(no.status, 'KEY_RETIRED_AFTER_SIGNING');
    assert.equal(no.valid, false);
  });

  it('loadKeyring reads the registry document shape this gate is configured with', async () => {
    const r = await verifyWith({ status: 'suspended' }, SIGNED_AFTER);
    assert.equal(r.status, 'UNKNOWN_KEY_STATUS');
  });
});

describe('vendored core — the unified call form is not deprecated', () => {
  it('verifyReceipt(token, { ctx, ... }) emits no DeprecationWarning', async () => {
    const seen = [];
    const onWarn = (w) => { if (w.name === 'DeprecationWarning') seen.push(w.message); };
    process.on('warning', onWarn);
    core.verifyReceipt(CORPUS.vectors[0].token, { ctx: { keyring: keyringFor(CORPUS.vectors[0].key) } });
    await new Promise((r) => setImmediate(r));
    process.off('warning', onWarn);
    assert.deepEqual(seen, [], 'the vendored core must be called in its current form');
  });
});
