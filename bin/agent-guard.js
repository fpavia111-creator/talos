#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { evaluate, FREE_GUARDS } = require('../src/engine');
const { loadPolicy, PROFILES } = require('../src/policy');
const { writeHtmlReport } = require('../src/report');
const { readAudit, verifyAuditChain } = require('../src/audit');
const license = require('../src/license');

const PKG_ROOT = path.resolve(__dirname, '..');
// Renamed in 0.2.0: agent-guard -> talos (Talos of Humans). The old command still works.
if (/agent-guard(\.js)?$/.test(path.basename(process.argv[1] || '')) && process.stderr.isTTY) {
  process.stderr.write('agent-guard: deprecated command name, use "talos" instead.\n');
}
const VERSION = (() => {
  try { return require('../package.json').version; } catch { return '0.0.0'; }
})();

function usage() {
  console.log(`Talos of Humans (talos, formerly agent-guard) v${VERSION} — runtime guardrails for Claude Code, Cursor, and Codex

Usage:
  talos init [--agent claude|cursor|codex|all] [--profile solo|strict|ci] [--dir <path>]
  talos check [--command <cmd>] [--file <path>] [--stdin] [--profile <name>]
  talos report [--out <file>] [--dir <path>]
  talos license [key]
  talos profiles
  talos version

Free (MIT): 5 guards — destructive, secrets, exfil, forcepush, scope.
Pro (launch price $11 one-time, will rise later): more guards, profiles, JSONL audit, HTML report, multi-agent.
`);
}

function mergeJsonFile(file, mutator) {
  let data = {};
  if (fs.existsSync(file)) {
    try { data = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (e) { throw new Error(`Cannot parse ${file}: ${e.message}`); }
  }
  mutator(data);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

function hookCommand(agent) {
  // Prefer invoking via node + absolute package path so init works without global install
  const adapter = {
    claude: path.join(PKG_ROOT, 'src', 'adapters', 'claude.js'),
    codex: path.join(PKG_ROOT, 'src', 'adapters', 'codex.js'),
    cursorShell: path.join(PKG_ROOT, 'src', 'adapters', 'cursor.js'),
  };
  return {
    claude: `node "${adapter.claude}"`,
    codex: `node "${adapter.codex}"`,
    cursorShell: `node "${adapter.cursorShell}" shell`,
    cursorTool: `node "${adapter.cursorShell}" tool`,
  };
}

function initClaude(dir, profile) {
  const settings = path.join(dir, '.claude', 'settings.json');
  const cmds = hookCommand();
  mergeJsonFile(settings, (data) => {
    data.hooks = data.hooks || {};
    data.hooks.PreToolUse = data.hooks.PreToolUse || [];
    // remove previous agent-guard entries
    data.hooks.PreToolUse = data.hooks.PreToolUse.filter(g => {
      const hooks = g.hooks || [];
      return !hooks.some(h => /agent-guard|adapters\/claude\.js/.test(h.command || ''));
    });
    data.hooks.PreToolUse.push({
      matcher: 'Bash|Edit|Write|MultiEdit|NotebookEdit',
      hooks: [{
        type: 'command',
        command: cmds.claude,
        timeout: 15,
        statusMessage: 'agent-guard',
        onFailure: 'block',
      }],
    });
  });
  writePolicy(dir, profile, ['claude']);
  console.log(`Claude Code hooks written → ${settings}`);
}

function initCodex(dir, profile) {
  const hooksFile = path.join(dir, '.codex', 'hooks.json');
  const cmds = hookCommand();
  mergeJsonFile(hooksFile, (data) => {
    data.hooks = data.hooks || {};
    data.hooks.PreToolUse = (data.hooks.PreToolUse || []).filter(g => {
      const hooks = g.hooks || [];
      return !hooks.some(h => /agent-guard|adapters\/codex\.js/.test(h.command || ''));
    });
    data.hooks.PreToolUse.push({
      matcher: 'Bash|apply_patch|Edit|Write',
      hooks: [{
        type: 'command',
        command: cmds.codex,
        timeout: 15,
        statusMessage: 'agent-guard',
      }],
    });
  });
  writePolicy(dir, profile, ['codex']);
  console.log(`Codex hooks written → ${hooksFile}`);
  console.log('Note: Codex requires you to review/trust new hooks via /hooks before they run.');
}

function initCursor(dir, profile) {
  const hooksFile = path.join(dir, '.cursor', 'hooks.json');
  const cmds = hookCommand();
  mergeJsonFile(hooksFile, (data) => {
    data.version = data.version || 1;
    data.hooks = data.hooks || {};
    const filterOwn = (arr) => (arr || []).filter(h => !/agent-guard|adapters\/cursor\.js/.test(h.command || ''));
    data.hooks.beforeShellExecution = filterOwn(data.hooks.beforeShellExecution);
    data.hooks.preToolUse = filterOwn(data.hooks.preToolUse);
    data.hooks.beforeShellExecution.push({
      command: cmds.cursorShell,
      timeout: 15,
      failClosed: true,
    });
    data.hooks.preToolUse.push({
      command: cmds.cursorTool,
      matcher: 'Shell|Write|Delete',
      timeout: 15,
      failClosed: true,
    });
  });
  writePolicy(dir, profile, ['cursor']);
  console.log(`Cursor hooks written → ${hooksFile}`);
}

function writePolicy(dir, profile, agents) {
  const file = path.join(dir, 'agent-guard.config.json');
  let existing = {};
  if (fs.existsSync(file)) {
    try { existing = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {}
  }
  const next = {
    profile: profile || existing.profile || 'solo',
    agents: Array.from(new Set([...(existing.agents || []), ...agents])),
    audit: (profile === 'strict' || profile === 'ci') ? true : !!existing.audit,
  };
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n');
  console.log(`Policy → ${file} (profile=${next.profile})`);
}

function cmdInit(args) {
  let agent = 'all';
  let profile = 'solo';
  let dir = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--agent') agent = args[++i];
    else if (args[i] === '--profile') profile = args[++i];
    else if (args[i] === '--dir') dir = path.resolve(args[++i]);
  }
  if (!['solo', 'strict', 'ci'].includes(profile)) {
    console.error('Unknown profile. Use solo|strict|ci (strict/ci require Pro — launch price $11).');
    process.exit(1);
  }
  if (profile !== 'solo' && !license.hasProLicense()) {
    console.error(`Profile "${profile}" is a Pro feature (launch price $11). Set ${license.ENV_VAR} or use --profile solo.`);
    console.error(`Dev override: ${license.DEV_ENV_VAR}=1`);
    process.exit(1);
  }
  const agents = agent === 'all' ? ['claude', 'cursor', 'codex'] : [agent];
  for (const a of agents) {
    if (a === 'claude') initClaude(dir, profile);
    else if (a === 'cursor') initCursor(dir, profile);
    else if (a === 'codex') initCodex(dir, profile);
    else {
      console.error('Unknown agent. Use claude|cursor|codex|all');
      process.exit(1);
    }
  }
  console.log('\nDone. Free guards active:', FREE_GUARDS.join(', '));
  if (!license.hasProLicense()) {
    console.log(`Upgrade to Pro (launch price $11, will rise later) for profiles, audit log, HTML report, and extra guards.`);
  }
}

function cmdCheck(args) {
  let command = null, file = null, useStdin = false, profile;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--command' || args[i] === '-c') command = args[++i];
    else if (args[i] === '--file' || args[i] === '-f') file = args[++i];
    else if (args[i] === '--stdin') useStdin = true;
    else if (args[i] === '--profile') profile = args[++i];
    else if (!command && !args[i].startsWith('-')) command = args[i];
  }
  const run = (cmd, filePath, content) => {
    const result = evaluate({
      agent: 'cli',
      command: cmd,
      filePath,
      content,
      cwd: process.cwd(),
      projectRoot: process.cwd(),
      profile,
      event: 'check',
    });
    if (result.decision === 'deny') {
      console.error('DENY:', result.reason);
      for (const h of result.blocked) console.error(`  - [${h.guard}/${h.rule}] ${h.message}`);
      process.exit(2);
    }
    console.log('ALLOW');
    process.exit(0);
  };

  if (useStdin) {
    const chunks = [];
    process.stdin.on('data', c => chunks.push(c));
    process.stdin.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        const j = JSON.parse(raw);
        run(j.command || j.tool_input?.command, j.file_path || j.tool_input?.file_path, j.content || j.tool_input?.content);
      } catch {
        run(raw.trim());
      }
    });
    return;
  }
  let content = null;
  if (file && fs.existsSync(file)) {
    // for check we pass path; content optional
  }
  if (!command && !file) {
    console.error('Provide --command or --file');
    process.exit(1);
  }
  run(command, file, content);
}

function cmdReport(args) {
  if (!license.hasProLicense()) {
    try { license.requirePro(); } catch (e) {
      console.error(e.message);
      process.exit(1);
    }
  }
  let out, dir = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out') out = args[++i];
    else if (args[i] === '--dir') dir = path.resolve(args[++i]);
  }
  const dest = writeHtmlReport(out, { projectRoot: dir });
  const entries = readAudit({ projectRoot: dir });
  const chain = verifyAuditChain(entries);
  console.log(`Report written → ${dest}`);
  console.log(`Events: ${entries.length}; chain: ${chain.ok ? 'OK' : 'BROKEN'}`);
}

function cmdLicense(args) {
  const key = args[0] || process.env[license.ENV_VAR];
  const payload = license.decode(key);
  if (payload) {
    console.log(`valid (order ${payload.oid}, issued ${payload.d}, product ${payload.p})`);
    process.exit(0);
  }
  console.log('invalid');
  process.exit(1);
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') return usage();
  if (cmd === 'version' || cmd === '-V' || cmd === '--version') return console.log(VERSION);
  if (cmd === 'init') return cmdInit(argv.slice(1));
  if (cmd === 'check') return cmdCheck(argv.slice(1));
  if (cmd === 'report') return cmdReport(argv.slice(1));
  if (cmd === 'license') return cmdLicense(argv.slice(1));
  if (cmd === 'profiles') {
    for (const [k, v] of Object.entries(PROFILES)) {
      console.log(`${k}\t${v.description}`);
    }
    return;
  }
  // subcommand used as hook entry: agent-guard hook claude
  if (cmd === 'hook') {
    const agent = argv[1];
    if (agent === 'claude') return require('../src/adapters/claude').main();
    if (agent === 'codex') return require('../src/adapters/codex').main();
    if (agent === 'cursor') return require('../src/adapters/cursor').main(argv[2]);
    console.error('hook agent must be claude|codex|cursor');
    process.exit(1);
  }
  console.error('Unknown command:', cmd);
  usage();
  process.exit(1);
}

main();
