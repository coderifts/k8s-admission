'use strict';
/**
 * Structural validation of a deny-remedy against the canonical schema.
 *
 * The schema is copied into this repo's fixtures as the contract; there is no
 * JSON-schema validator in this package's dependencies (measured), and adding
 * one to check a five-field object would be a dependency a customer has to
 * trust for no gain. This asserts the schema's rules directly and pins the
 * schema file's own hash, so a change to the contract fails here.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_PATH = path.join(__dirname, 'fixtures', 'deny-remedy.v1.json');
const SCHEMA_SHA256 = '3f51c5afd1708a9185075a4f19f6386ea7d63ad39b0104e31f0e4e887b6e167f';

function schema() {
  const raw = fs.readFileSync(SCHEMA_PATH);
  assert.equal(
    crypto.createHash('sha256').update(raw).digest('hex'), SCHEMA_SHA256,
    'the vendored schema copy drifted from the canonical capability-demo/docs/deny-remedy.v1.json',
  );
  return JSON.parse(raw.toString('utf8'));
}

/** Assert one emitted remedy satisfies every rule the schema states. */
function assertValidRemedy(remedy, label = 'remedy') {
  const s = schema();
  const props = s.properties;

  assert.ok(remedy && typeof remedy === 'object', `${label}: not an object`);
  for (const req of s.required) {
    assert.ok(req in remedy, `${label}: required field missing: ${req}`);
  }
  for (const key of Object.keys(remedy)) {
    assert.ok(key in props, `${label}: additionalProperties — unexpected key ${key}`);
  }
  assert.ok(props.error.enum.includes(remedy.error), `${label}: error not in the closed set`);

  // target / fingerprint are nullable but never a wildcard or a malformed value.
  assert.ok(remedy.target === null || typeof remedy.target === 'string', `${label}: bad target`);
  assert.notEqual(remedy.target, '*', `${label}: target must never be a wildcard`);
  if (remedy.fingerprint !== null) {
    assert.match(remedy.fingerprint, new RegExp(props.fingerprint.pattern), `${label}: bad fingerprint`);
  }

  const a = remedy.action_required;
  assert.equal(a.tool, props.action_required.properties.tool.const, `${label}: wrong tool`);
  assert.equal(a.mode, props.action_required.properties.mode.const, `${label}: wrong mode`);
  const shape = props.action_required.properties.args_shape.properties;
  assert.equal(a.args_shape.artifacts, shape.artifacts.const, `${label}: args_shape.artifacts drifted`);
  assert.equal(a.args_shape.context, shape.context.const, `${label}: args_shape.context drifted`);
  assert.deepEqual(Object.keys(a).sort(), ['args_shape', 'mode', 'tool'], `${label}: extra action_required keys`);

  assert.equal(remedy.does_not_promise, props.does_not_promise.const,
    `${label}: the does-not-promise line was altered`);
}

module.exports = { assertValidRemedy, schema, SCHEMA_PATH, SCHEMA_SHA256 };
