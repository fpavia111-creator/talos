'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { checkScope, isInside } = require('../src/guards/scope');
const { evaluate } = require('../src/engine');

describe('scope guard', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-scope-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');

  it('isInside works', () => {
    assert.equal(isInside(root, path.join(root, 'src/a.js')), true);
    assert.equal(isInside(root, path.join(root, '..', 'outside.js')), false);
    assert.equal(isInside(root, '/etc/passwd'), false);
  });

  it('blocks outside project', () => {
    const hits = checkScope({ filePath: '/etc/passwd', projectRoot: root, cwd: root });
    assert.ok(hits.length);
  });

  it('allows inside project', () => {
    const hits = checkScope({ filePath: path.join(root, 'src/x.js'), projectRoot: root, cwd: root });
    assert.equal(hits.length, 0);
  });

  it('evaluate blocks Write outside', () => {
    const r = evaluate({
      filePath: path.join(os.tmpdir(), 'nope.js'),
      content: 'x',
      cwd: root,
      projectRoot: root,
      agent: 'test',
    });
    assert.equal(r.decision, 'deny');
  });
});
