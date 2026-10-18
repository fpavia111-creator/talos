'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkForcePush } = require('../src/guards/forcepush');

describe('forcepush guard', () => {
  it('blocks git push -f origin main', () => assert.ok(checkForcePush('git push -f origin main').length));
  it('blocks git push --force origin master', () => assert.ok(checkForcePush('git push --force origin master').length));
  it('blocks git push --force-with-lease origin main', () => assert.ok(checkForcePush('git push --force-with-lease origin main').length));
  it('blocks git push --force', () => assert.ok(checkForcePush('git push --force').length));
  it('allows git push origin main', () => assert.equal(checkForcePush('git push origin main').length, 0));
  it('allows git push -f origin feature/x', () => assert.equal(checkForcePush('git push -f origin feature/x').length, 0));
  it('blocks via sh -c', () => assert.ok(checkForcePush("sh -c 'git push --force origin main'").length));
});
