'use strict';
const { readStdin, parseStdinJson, extractClaudeOrCodex, denyClaude, runAs } = require('./common');

async function main() {
  const input = parseStdinJson(await readStdin());
  const extracted = extractClaudeOrCodex(input);
  // Only gate shell + file write/edit tools
  const tool = extracted.tool || '';
  const relevant = /bash|shell|edit|write|apply_patch|create_file|notebookedit/i.test(tool) || extracted.command || extracted.filePath;
  if (!relevant) {
    process.exit(0);
  }
  const result = runAs('claude-code', extracted);
  if (result.decision === 'deny') {
    process.stdout.write(JSON.stringify(denyClaude(result.reason)) + '\n');
    // Also exit 2 as belt-and-suspenders for older Claude Code
    process.stderr.write('talos: ' + result.reason + '\n');
    process.exit(0); // JSON deny is preferred; exit 0 so JSON is honored
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
