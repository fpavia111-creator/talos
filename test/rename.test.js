'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const pkg = require('../package.json');
const BIN = path.join(__dirname, '..', 'bin', 'agent-guard.js');

test('renamed to Talos of Humans: package, bins, license id', () => {
  assert.equal(pkg.name, '@kurtfrancisco/talos');
  assert.equal(pkg.bin.talos, 'bin/agent-guard.js');
  assert.equal(pkg.bin['agent-guard'], 'bin/agent-guard.js');
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'src', 'license.js'), 'utf8'), /PRODUCT = 'agent-guard-pro'/);
});
test('help shows the new name; old command still runs', () => {
  const r = spawnSync(process.execPath, [BIN, 'version'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  const h = spawnSync(process.execPath, [BIN, 'help'], { encoding: 'utf8' });
  assert.match(h.stdout + h.stderr, /Talos of Humans/);
});
test('TALOS_PROFILE is honored, AGENT_GUARD_PROFILE still works', () => {
  const { loadPolicy } = require('../src/policy');
  const save = { ...process.env };
  try {
    delete process.env.AGENT_GUARD_PROFILE; process.env.TALOS_PROFILE = 'strict';
    assert.equal(loadPolicy(require('os').tmpdir()).name, 'strict');
    delete process.env.TALOS_PROFILE; process.env.AGENT_GUARD_PROFILE = 'ci';
    assert.equal(loadPolicy(require('os').tmpdir()).name, 'ci');
  } finally { process.env = save; }
});
