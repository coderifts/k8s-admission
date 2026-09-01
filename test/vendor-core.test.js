'use strict';

/**
 * The vendored verify core is the canonical one, and it still refuses a key the
 * registry has withdrawn.
 *
 * Two halves, because either alone is weak. The digest half fails when the files
 * drift from `src/VENDOR.sha256`. The behaviour half mints a real receipt and
 * feeds a real registry, so a core silently replaced by an older copy — whose
 * digests someone also updated — still fails here.
 *
 * MEASURED 2026-09-01: an earlier vendored core read `status` only for
 * 'retired'. Every other value, 'revoked' included, fell through to the healthy
 * path and returned { valid: true, status: 'VERIFIED_CURRENT' }. An operator who
 * marked a stolen key revoked in the registry would have believed they had acted
 * while this surface kept accepting its signatures. These vectors are that
 * measurement, kept executable.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const core = require('../src/verify.js');

const SRC = path.join(__dirname, '..', 'src');
const PIN_FILE = path.join(SRC, 'VENDOR.sha256');
const sha256File = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

describe('vendored core — digests match the pin', () => {
  const pinned = fs.readFileSync(PIN_FILE, 'utf8').trim().split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter(([name]) => name.endsWith('.js'));

  it('VENDOR.sha256 lists at least verify.js and arity.js', () => {
    const names = pinned.map(([n]) => n);
    assert.ok(names.includes('verify.js'), 'verify.js must be pinned');
    assert.ok(names.includes('arity.js'), 'arity.js must be pinned');
  });

  for (const [name, digest] of pinned) {
    it(`${name} is byte-identical to its pinned digest`, () => {
      assert.equal(
        sha256File(path.join(SRC, name)), digest,
        `${name} drifted from src/VENDOR.sha256 — recopy from receipt-verifier, or update the pin deliberately`,
      );
    });
  }
});

// ── the behaviour the pin exists to protect ─────────────────────────────────
const KID = 'vendor-pin-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const BOUNDARY = '2026-06-01T00:00:00.000Z';
const b64url = (b) => Buffer.from(b).toString('base64url');

function mint(ts) {
  const p = {
    v: 4, kid: KID, fp: `sha256:${'a'.repeat(64)}`, prev: 'null', caller: 'bundle', ts,
    reg: 'r'.repeat(64), ir: `sha256:${'b'.repeat(64)}`,
    expires_at: '2027-01-01T00:00:00.000Z', bh: `sha256:${'c'.repeat(64)}`,
  };
  const si = `crchain.v1|${p.kid}|${p.fp}|${p.prev}|${p.caller}|${p.ts}|${p.reg}|${p.ir}|${p.expires_at}|${p.bh}`;
  return `${b64url(JSON.stringify(p))}.${b64url(crypto.sign(null, Buffer.from(si, 'utf8'), privateKey))}`;
}
const SIGNED_BEFORE = mint('2026-01-01T00:00:00.000Z');
const SIGNED_AFTER = mint('2026-08-01T00:00:00.000Z');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vendor-pin-'));
async function verifyWith(entry, token) {
  const file = path.join(tmp, `${crypto.randomUUID()}.json`);
  fs.writeFileSync(file, JSON.stringify({ keys: [{ kid: KID, alg: 'Ed25519', public_key_pem: PEM, ...entry }] }));
  const keyring = await core.loadKeyring(file);
  // skipBodyHash: these vectors are about the KEY's registry state, not envelope binding.
  return core.verifyReceipt(token, { ctx: { keyring, expectedKid: null }, skipBodyHash: true });
}

describe('vendored core — a withdrawn key is refused', () => {
  it('control: an active key still verifies (the vectors are not vacuous)', async () => {
    const r = await verifyWith({ status: 'active' }, SIGNED_AFTER);
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
  });

  it('status revoked + compromised_at, signed after → REVOKED_KEY', async () => {
    const r = await verifyWith({ status: 'revoked', compromised_at: BOUNDARY }, SIGNED_AFTER);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'REVOKED_KEY');
  });

  it('status revoked + compromised_at, signed before → REVOKED_KEY_UNDECIDABLE, still not valid', async () => {
    // The attacker chooses ts, so an earlier timestamp cannot rehabilitate the key.
    const r = await verifyWith({ status: 'revoked', compromised_at: BOUNDARY }, SIGNED_BEFORE);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'REVOKED_KEY_UNDECIDABLE');
  });

  it('status revoked with no compromised_at → REVOKED_KEY_UNDECIDABLE', async () => {
    const r = await verifyWith({ status: 'revoked' }, SIGNED_AFTER);
    assert.equal(r.valid, false);
    // The exact status, not just valid:false — a core that rejected this for an
    // unrelated reason (an unresolved kid, say) would otherwise pass here.
    assert.equal(r.status, 'REVOKED_KEY_UNDECIDABLE');
  });

  it('revoked_at on an otherwise active entry → KEY_REVOKED', async () => {
    const r = await verifyWith({ status: 'active', revoked_at: BOUNDARY }, SIGNED_BEFORE);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'KEY_REVOKED');
  });

  it('a status this core does not understand fails closed, not open', async () => {
    const r = await verifyWith({ status: 'suspended' }, SIGNED_AFTER);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'UNKNOWN_KEY_STATUS');
  });

  it('planned rotation is unchanged: signed before retired_at stays valid, after does not', async () => {
    const ok = await verifyWith({ status: 'retired', retired_at: BOUNDARY }, SIGNED_BEFORE);
    assert.equal(ok.valid, true);
    assert.equal(ok.status, 'RETIRED_KEY_VALID_AT_ISSUE');

    const no = await verifyWith({ status: 'retired', retired_at: BOUNDARY }, SIGNED_AFTER);
    assert.equal(no.valid, false);
    assert.equal(no.status, 'KEY_RETIRED_AFTER_SIGNING');
  });
});

describe('vendored core — the unified call form is not deprecated', () => {
  it('verifyReceipt(token, { ctx, ... }) emits no DeprecationWarning', async () => {
    const seen = [];
    const onWarn = (w) => { if (w.name === 'DeprecationWarning') seen.push(w.message); };
    process.on('warning', onWarn);
    await verifyWith({ status: 'active' }, SIGNED_AFTER);
    await new Promise((r) => setImmediate(r));
    process.off('warning', onWarn);
    assert.deepEqual(seen, [], 'the vendored core must be called in its current form');
  });
});
