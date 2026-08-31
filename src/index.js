'use strict';

/**
 * Kubernetes ValidatingAdmissionWebhook process entry.
 *
 * Customer-hosted: runs in the customer's cluster, verifies against a
 * customer-pinned local keyring. No CodeRifts-operated network dependency.
 */

const { startServer, loadPinnedKeyringSyncPath, readFileIf } = require('./server');

async function main() {
  const keyringPath = process.env.KEYRING_PATH || '/etc/coderifts/keyring.json';
  const keyring = await loadPinnedKeyringSyncPath(keyringPath);
  const cert = readFileIf(process.env.TLS_CERT_FILE);
  const key = readFileIf(process.env.TLS_KEY_FILE);
  if (!cert || !key) {
    console.error('TLS_CERT_FILE and TLS_KEY_FILE are required in-cluster');
    process.exit(2);
  }
  const port = Number(process.env.LISTEN_PORT || 8443);
  const expectedOperation = process.env.EXPECTED_OPERATION || 'deploy';
  const server = await startServer({ keyring, cert, key, port, expectedOperation });
  const addr = server.address();
  console.error(`coderifts-k8s-admission listening on ${addr.port} (TLS); operation=${expectedOperation}`);
}

module.exports = { main };

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
