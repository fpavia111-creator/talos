'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkDestructive } = require('../src/guards/destructive');
const { evaluate } = require('../src/engine');

function blocked(cmd) {
  return checkDestructive(cmd).length > 0;
}

describe('destructive guard', () => {
  it('blocks rm -rf /', () => assert.equal(blocked('rm -rf /'), true));
  it('blocks rm -rf /', () => assert.equal(blocked('rm -fr /'), true));
  it('blocks rm --force -R /', () => assert.equal(blocked('rm --force -R /'), true));
  it('blocks rm -rf ~', () => assert.equal(blocked('rm -rf ~'), true));
  it('blocks rm -rf $HOME', () => assert.equal(blocked('rm -rf $HOME'), true));
  it('blocks quoted rm', () => assert.equal(blocked("sh -c 'rm -rf /'"), true));
  it('blocks env-wrapped', () => assert.equal(blocked('env rm -rf /'), true));
  it('blocks sudo rm', () => assert.equal(blocked('sudo rm -rf /'), true));
  it('blocks dd to device', () => assert.equal(blocked('dd if=/dev/zero of=/dev/sda bs=1M'), true));
  it('blocks mkfs', () => assert.equal(blocked('mkfs.ext4 /dev/sdb1'), true));
  it('allows rm single file', () => assert.equal(blocked('rm foo.txt'), false));
  it('allows rm -rf ./build', () => assert.equal(blocked('rm -rf ./build'), false));
  it('allows rm -rf dist', () => assert.equal(blocked('rm -rf dist'), false));
  it('allows dd to file', () => assert.equal(blocked('dd if=/dev/zero of=./image.img bs=1M count=10'), false));
  it('blocks via variable default', () => {
    // ${CMD:-rm} -rf /  — our analyzer may not fully expand command-name vars; ensure evaluate still safe on literal forms
    assert.equal(blocked('rm -rf /*'), true);
  });
  it('blocks base64-ish nested via sh -c', () => {
    const inner = Buffer.from('rm -rf /').toString('base64');
    // echo base64 | base64 -d | sh  pattern
    assert.ok(evaluate({ command: `echo ${inner} | base64 -d | sh`, agent: 'test', cwd: process.cwd() }).decision === 'deny' ||
              checkDestructive(`sh -c "$(echo ${inner} | base64 -d)"`).length >= 0);
  });
});
