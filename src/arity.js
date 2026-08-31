'use strict';

/**
 * 1129 — unified (token, opts) with opts.ctx / opts.intended.
 * 3-ary (token, ctx, opts) wrappers warn once and forward.
 * 2-ary verifiers keep the 1128 throw on a third argument.
 */
const warned = new Set();

function warnOnce(name) {
  if (warned.has(name)) return;
  warned.add(name);
  const msg = `DEPRECATION: ${name}(token, ctx, opts) is deprecated; use ${name}(token, { ctx, intended }). This warning is emitted once.`;
  if (typeof process !== 'undefined' && typeof process.emitWarning === 'function') {
    process.emitWarning(msg, 'DeprecationWarning');
  } else {
    console.warn(msg);
  }
}

function throw1128(name, n, consequence) {
  throw new Error(
    `${name}(token, opts) — pass intended via opts.intended. `
    + `Received ${n} arguments; the third would be ignored and the cross-check `
    + `would silently not run, grading a mismatched artifact ${consequence}.`,
  );
}

function looksUnified(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  // perSlot is the bundle-dispatch unified shape: verifyBundle(bundle, { ctx, perSlot }).
  // Without it, `{ perSlot }` was treated as a bare ctx and opts.perSlot vanished.
  return obj.ctx != null || obj.intended != null || obj.envelope != null || obj.perSlot != null;
}

function split3ary(name, nArgs, second, third) {
  if (nArgs > 3) throw1128(name, nArgs, 'VALID');
  if (nArgs === 3) {
    warnOnce(name);
    return { ctx: second || {}, opts: third && typeof third === 'object' ? third : {} };
  }
  const o = second && typeof second === 'object' ? second : {};
  if (looksUnified(o)) {
    return { ctx: o.ctx || {}, opts: o };
  }
  return { ctx: o, opts: {} };
}

function _resetWarnedForTest() {
  warned.clear();
}

module.exports = { warnOnce, throw1128, split3ary, looksUnified, _resetWarnedForTest };
