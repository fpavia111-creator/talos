'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkSecretsWrite } = require('../src/guards/secrets');
const { evaluate } = require('../src/engine');
const path = require('path');
const fs = require('fs');
const os = require('os');

describe('secrets guard', () => {
  it('blocks writing PEM private key', () => {
    const hits = checkSecretsWrite({
      filePath: 'id_rsa',
      content: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----',
    });
    assert.ok(hits.length);
  });
  it('blocks AWS key in file', () => {
    const hits = checkSecretsWrite({
      filePath: 'config.txt',
      content: 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n',
    });
    assert.ok(hits.length);
  });
  it('blocks .env with values', () => {
    const hits = checkSecretsWrite({
      filePath: '.env',
      content: 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n',
    });
    assert.ok(hits.length);
  });
  it('allows normal source write', () => {
    const hits = checkSecretsWrite({
      filePath: 'src/index.js',
      content: 'module.exports = { ok: true };\n',
    });
    assert.equal(hits.length, 0);
  });
  it('blocks echo secret redirect to .env', () => {
    const hits = checkSecretsWrite({ command: 'echo "API_KEY=sk-abcdefghijklmnopqrstuvwxyz" >> .env' });
    assert.ok(hits.length);
  });
});
