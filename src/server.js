'use strict';

/**
 * AdmissionReview HTTP(S) handler. Kubernetes POSTs an AdmissionReview;
 * we return an AdmissionReview with response.allowed.
 *
 * TLS is required in-cluster (ValidatingWebhookConfiguration). Tests may
 * use plain HTTP. Keyring is a LOCAL file — never fetched.
 */

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const { evaluateAdmission, REASON } = require('./admit');
const { loadKeyring } = require('./verify');

const MAX_BODY = 2 * 1024 * 1024;

function admissionResponse(uid, decision) {
  const allowed = decision.allowed === true;
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: {
      uid: uid || '',
      allowed,
      status: allowed
        ? { code: 200, message: decision.reason }
        : { code: 403, message: decision.reason + (decision.detail ? `: ${decision.detail}` : '') },
    },
  };
}

function parseBody(raw) {
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

function handleAdmissionReview(review, { keyring, expectedOperation, now } = {}) {
  if (!review || typeof review !== 'object') {
    return admissionResponse('', { allowed: false, reason: REASON.RECEIPT_INVALID, detail: 'malformed AdmissionReview' });
  }
  const req = review.request;
  if (!req || typeof req !== 'object') {
    return admissionResponse(review.request && review.request.uid, {
      allowed: false, reason: REASON.RECEIPT_MISSING, detail: 'no request',
    });
  }
  const uid = req.uid || '';
  const op = req.operation;
  if (op === 'DELETE') {
    return admissionResponse(uid, { allowed: true, reason: 'delete_not_gated' });
  }
  const object = req.object;
  const decision = evaluateAdmission({ object, keyring, expectedOperation, now });
  return admissionResponse(uid, decision);
}

function loadPinnedKeyringSyncPath(source) {
  if (source == null || String(source).trim() === '') {
    throw new Error('KEYRING_PATH is required (local file; no fetch)');
  }
  const p = String(source).trim();
  if (/^https?:\/\//i.test(p)) {
    throw new Error('KEYRING_PATH must be a local file (customer-pinned; no network fetch)');
  }
  return loadKeyring(p);
}

function createHandler({ keyring, expectedOperation = 'deploy' }) {
  return (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('POST only');
      return;
    }
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) {
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const review = parseBody(raw);
      if (!review) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(admissionResponse('', {
          allowed: false, reason: REASON.RECEIPT_INVALID, detail: 'body is not JSON',
        })));
        return;
      }
      const out = handleAdmissionReview(review, { keyring, expectedOperation });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  };
}

function startServer({ keyring, cert, key, port = 8443, expectedOperation = 'deploy' }) {
  const handler = createHandler({ keyring, expectedOperation });
  const server = (cert && key)
    ? https.createServer({ cert, key }, handler)
    : http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(port, '0.0.0.0', () => resolve(server));
  });
}

function readFileIf(p) {
  if (!p) return null;
  return fs.readFileSync(p);
}

module.exports = {
  handleAdmissionReview,
  createHandler,
  startServer,
  loadPinnedKeyringSyncPath,
  readFileIf,
  admissionResponse,
};
