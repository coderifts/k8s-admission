'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const { handleAdmissionReview, createHandler, loadPinnedKeyringSyncPath } = require('../src/server');
const { ANNOTATION_RECEIPT, ANNOTATION_ENVELOPE, REASON } = require('../src/admit');
const { loadKeyring } = require('../src/verify');
const { newSigner, mintV4, writeKeyringFile, envelope } = require('./mint');

const signer = newSigner('k8s-http-k1');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-http-'));
const keyringFile = writeKeyringFile(tmp, signer);

const TARGET = 'k8s:pod:default/api';

function boundEnv() {
  return envelope({
    extra: {
      preflight_mode: 'authorize',
      operation: 'deploy',
      target_id: TARGET,
    },
  });
}

function pod(ann) {
  return {
    kind: 'Pod',
    metadata: { name: 'api', namespace: 'default', annotations: ann || {} },
  };
}

function review(object, operation = 'CREATE', uid = 'uid-1') {
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    request: { uid, operation, object, kind: { kind: object.kind } },
  };
}

describe('handleAdmissionReview', () => {
  it('CREATE with a valid receipt is allowed', async () => {
    const env = boundEnv();
    const obj = pod({
      [ANNOTATION_RECEIPT]: mintV4(signer, env),
      [ANNOTATION_ENVELOPE]: JSON.stringify(env),
    });
    const out = handleAdmissionReview(review(obj), { keyring: await loadKeyring(keyringFile) });
    assert.equal(out.response.uid, 'uid-1');
    assert.equal(out.response.allowed, true);
  });

  it('CREATE without a receipt is denied receipt_missing', async () => {
    const out = handleAdmissionReview(review(pod()), { keyring: await loadKeyring(keyringFile) });
    assert.equal(out.response.allowed, false);
    assert.match(out.response.status.message, /^receipt_missing/);
    assert.equal(out.response.status.code, 403);
  });

  it('DELETE is not gated', async () => {
    const out = handleAdmissionReview(review(pod(), 'DELETE'), { keyring: await loadKeyring(keyringFile) });
    assert.equal(out.response.allowed, true);
  });
});

describe('HTTP handler', () => {
  it('POST AdmissionReview returns 200 with allowed:false on missing receipt', async () => {
    const keyring = await loadKeyring(keyringFile);
    const handler = createHandler({ keyring });
    const server = http.createServer(handler);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    try {
      const body = JSON.stringify(review(pod()));
      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1', port, path: '/', method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, (resp) => {
          let data = '';
          resp.on('data', (c) => { data += c; });
          resp.on('end', () => resolve({ status: resp.statusCode, body: JSON.parse(data) }));
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.response.allowed, false);
      assert.equal(res.body.response.status.message.startsWith(REASON.RECEIPT_MISSING), true);
    } finally {
      server.close();
    }
  });

  it('refuses an http(s) KEYRING_PATH (customer pin is a local file)', () => {
    assert.throws(
      () => loadPinnedKeyringSyncPath('https://app.coderifts.com/.well-known/coderifts-keys.json'),
      /local file/,
    );
  });
});
