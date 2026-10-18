'use strict';
const { readStdin, parseStdinJson, extractCursor, denyCursor, allowCursor, runAs } = require('./common');

async function main(kind) {
  const k = kind || process.argv[2] || 'shell';
  const input = parseStdinJson(await readStdin());
  const extracted = extractCursor(input, k);
  // afterFileEdit can't block — only audit via evaluate; for beforeShell / preToolUse we deny
  const result = runAs('cursor', extracted);
  if (k === 'edit') {
    // observational — still evaluate for audit; cannot block after the fact
    process.stdout.write(JSON.stringify({}) + '\n');
    process.exit(0);
  }
  if (result.decision === 'deny') {
    process.stdout.write(JSON.stringify(denyCursor(result.reason)) + '\n');
    process.exit(0);
  }
  process.stdout.write(JSON.stringify(allowCursor()) + '\n');
  process.exit(0);
}

if (require.main === module) {
  main().catch(err => {
    process.stderr.write('talos hook error: ' + err.message + '\n');
    // fail-open unless failClosed
    process.stdout.write(JSON.stringify(allowCursor()) + '\n');
    process.exit(0);
  });
}

module.exports = { main };
