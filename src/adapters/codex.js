'use strict';
const { readStdin, parseStdinJson, extractClaudeOrCodex, denyCodex, runAs } = require('./common');

async function main() {
  const input = parseStdinJson(await readStdin());
  const extracted = extractClaudeOrCodex(input);
  const tool = extracted.tool || '';
  const relevant = /bash|shell|apply_patch|edit|write/i.test(tool) || extracted.command || extracted.filePath;
  if (!relevant) process.exit(0);
  const result = runAs('codex', extracted);
  if (result.decision === 'deny') {
    process.stdout.write(JSON.stringify(denyCodex(result.reason)) + '\n');
    process.exit(0);
  }
  process.exit(0);
}

if (require.main === module) {
  main().catch(err => {
    process.stderr.write('talos hook error: ' + err.message + '\n');
    process.exit(1);
  });
}

module.exports = { main };
