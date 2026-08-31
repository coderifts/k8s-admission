'use strict';

/**
 * Test-only receipt minter — MIRRORED from coderifts-contract-gate/test/mint.js.
 * Real Ed25519; only the key identity is a test key. Not a *.test.js file.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256hex } = require('../src/verify');

const SIGNING_PREFIX = 'crchain.v1';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function bodyHash(envelope) {
  const rest = { ...envelope };
  delete rest.receipt;
  delete rest.decision_body_hash;
  return 'sha256:' + sha256hex(canonicalJson(rest));
}

function newSigner(kid = 'test-k1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return { kid, publicKey, privateKey, publicKeyPem };
}

function mintV4(signer, envelope, overrides = {}) {
  const payload = {
    v: 4,
    kid: overrides.kid || signer.kid,
    fp: overrides.fp || (envelope.fingerprint || envelope.input_fingerprint || ('sha256:' + 'a'.repeat(64))),
    prev: overrides.prev || 'null',
    caller: overrides.caller || 'bundle',
    ts: overrides.ts || '2026-07-26T00:00:00.000Z',
    reg: overrides.reg || 'r'.repeat(64),
    ir: overrides.ir || ('sha256:' + 'b'.repeat(64)),
    expires_at: overrides.expires_at || '2027-01-01T00:00:00.000Z',
    bh: overrides.bh || bodyHash(envelope),
  };
  const signedInput = `${SIGNING_PREFIX}|${payload.kid}|${payload.fp}|${payload.prev}|${payload.caller}|${payload.ts}|${payload.reg}|${payload.ir}|${payload.expires_at}|${payload.bh}`;
  const sig = crypto.sign(null, Buffer.from(signedInput, 'utf8'), signer.privateKey);
  return `${b64url(JSON.stringify(payload))}.${b64url(sig)}`;
}

function tamperSignature(token) {
  const [body, sig] = token.split('.');
  const raw = Buffer.from(sig, 'base64url');
  raw[0] ^= 0xff;
  return `${body}.${b64url(raw)}`;
}

function writeKeyringFile(dir, signer, status = 'active') {
  const file = path.join(dir, 'test-keyring.json');
  fs.writeFileSync(file, JSON.stringify({
    keys: [{ kid: signer.kid, alg: 'Ed25519', status, public_key_pem: signer.publicKeyPem }],
  }) + '\n');
  return file;
}

function envelope({ execution_action = 'CONTINUE', decision = 'ALLOW', extra = {} } = {}) {
  return {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: 'dec_test',
    correlation_id: 'corr_test',
    fingerprint: 'sha256:' + 'c'.repeat(64),
    input_fingerprint: 'sha256:' + 'd'.repeat(64),
    summary: `${decision} — test`,
    decision_body_hash: null,
    receipt: null,
    ...extra,
  };
}

module.exports = { newSigner, mintV4, tamperSignature, writeKeyringFile, envelope, bodyHash };
