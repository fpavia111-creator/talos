'use strict';
const path = require('path');
const { runFreeGuards, FREE_GUARDS } = require('./guards');
const { loadPolicy } = require('./policy');
const { appendAudit } = require('./audit');
const { hasProLicense } = require('./license');

function tryLoadProGuards() {
  // Prefer packaged pro/ next to this package; also allow sibling install.
  const candidates = [
    path.join(__dirname, '..', 'pro', 'agent-guard-pro', 'guards', 'index.js'),
    path.join(__dirname, '..', '..', 'agent-guard-pro', 'guards', 'index.js'),
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch (_) { /* continue */ }
  }
  return null;
}

function evaluate(ctx = {}) {
  const projectRoot = ctx.projectRoot || ctx.cwd || process.cwd();
  const policy = loadPolicy(projectRoot, {
    profile: ctx.profile,
    policyPath: ctx.policyPath,
  });
  const pro = hasProLicense(ctx.licenseKey);
  const guardsEnabled = { ...policy.guards };

  // Free tier: only the 5 free guards; profiles beyond solo, audit, report need Pro
  if (!pro) {
    for (const k of Object.keys(guardsEnabled)) {
      if (!FREE_GUARDS.includes(k)) guardsEnabled[k] = false;
    }
  }

  const baseCtx = {
    ...ctx,
    projectRoot: policy.projectRoot || projectRoot,
    allowPaths: policy.allowPaths || ctx.allowPaths,
    protectedBranches: policy.protectedBranches,
    guardsEnabled,
    env: ctx.env || {},
  };

  let hits = runFreeGuards(baseCtx);

  if (pro) {
    const proGuards = tryLoadProGuards();
    if (proGuards && typeof proGuards.runProGuards === 'function') {
      hits = hits.concat(proGuards.runProGuards(baseCtx));
    }
  }

  const blocked = hits.filter(h => h.severity === 'block');
  const decision = blocked.length ? 'deny' : 'allow';
  const reason = blocked.length
    ? blocked.map(h => h.message).join('; ')
    : null;

  const result = {
    decision,
    reason,
    hits,
    blocked,
    profile: policy.name,
    pro,
    policy,
  };

  const wantAudit = (pro && policy.audit) || ctx.forceAudit;
  if (wantAudit) {
    try {
      appendAudit({
        agent: ctx.agent,
        event: ctx.event,
        decision,
        reason,
        hits: blocked,
        tool: ctx.tool,
        command: ctx.command,
        filePath: ctx.filePath,
        profile: policy.name,
        cwd: ctx.cwd || projectRoot,
      }, {
        projectRoot,
        auditLog: policy.auditLog || ctx.auditLog,
      });
    } catch (err) {
      result.auditError = String(err.message || err);
    }
  }

  return result;
}

module.exports = { evaluate, FREE_GUARDS, tryLoadProGuards };
