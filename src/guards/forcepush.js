'use strict';
const { analyzeCommand } = require('../shell');

const PROTECTED_BRANCHES = new Set(['main', 'master', 'production', 'prod', 'release', 'trunk']);

function parseGitPush(args) {
  const flags = new Set();
  const positionals = [];
  let force = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--force' || a === '-f') force = true;
    else if (a === '--force-with-lease' || a === '--force-if-includes') force = true;
    else if (a.startsWith('-')) {
      if (a.startsWith('-') && !a.startsWith('--') && a.includes('f')) force = true;
      flags.add(a);
    } else positionals.push(a);
  }
  return { force, positionals, flags };
}

function refBranch(ref) {
  if (!ref) return null;
  // HEAD:main, main, refs/heads/main, +main, origin/main
  let r = ref.replace(/^\+/, '');
  if (r.includes(':')) r = r.split(':').pop();
  r = r.replace(/^refs\/heads\//, '');
  if (r.includes('/')) r = r.split('/').pop();
  return r;
}

function checkForcePush(command, opts = {}) {
  const hits = [];
  const analysis = typeof command === 'object' && command.commands
    ? command
    : analyzeCommand(command, opts);
  const protectedBranches = new Set([...(opts.protectedBranches || []), ...PROTECTED_BRANCHES]);

  for (const c of analysis.commands) {
    if (c.cmd !== 'git') continue;
    const args = c.args || [];
    if (args[0] !== 'push') continue;
    const { force, positionals } = parseGitPush(args.slice(1));
    if (!force) continue;

    // git push --force origin main
    // git push -f origin HEAD:main
    // git push --force
    let branches = [];
    if (positionals.length >= 2) {
      branches = positionals.slice(1).map(refBranch).filter(Boolean);
    } else if (positionals.length === 1 && !positionals[0].includes('@') && !positionals[0].includes(':')) {
      // could be remote only — force push default branch; treat as risky
      branches = ['(default)'];
    } else if (positionals.length === 0) {
      branches = ['(default)'];
    } else {
      branches = positionals.map(refBranch).filter(Boolean);
    }

    const hitProtected = branches.some(b => b === '(default)' || protectedBranches.has(b));
    if (hitProtected) {
      hits.push({
        guard: 'forcepush',
        rule: 'force_push_protected',
        severity: 'block',
        message: `Blocked force-push to protected branch (${branches.join(', ') || 'default'})`,
        detail: { args, branches },
      });
    }
  }

  // raw fallback
  if (/git\s+push\s+[^\n]*(-f|--force)\b/i.test(analysis.raw) &&
      /\b(main|master|production|prod)\b/.test(analysis.raw)) {
    if (!hits.length) {
      hits.push({
        guard: 'forcepush',
        rule: 'force_push_protected_raw',
        severity: 'block',
        message: 'Blocked force-push to a protected branch (pattern match)',
        detail: {},
      });
    }
  }

  return hits;
}

module.exports = { checkForcePush, PROTECTED_BRANCHES, parseGitPush };
