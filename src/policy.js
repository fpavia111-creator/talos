'use strict';
const fs = require('fs');
const path = require('path');

/** @typedef {'solo'|'strict'|'ci'} ProfileName */

const PROFILES = {
  solo: {
    name: 'solo',
    description: 'Sensible defaults for a solo developer',
    guards: {
      destructive: true,
      secrets: true,
      exfil: true,
      forcepush: true,
      scope: true,
      // pro
      sudo: false,
      docker_privileged: false,
      chmod_world: false,
      symlink_escape: false,
      curl_any_pipe: false,
      git_config_hooks: false,
    },
    protectedBranches: ['main', 'master', 'production', 'prod'],
    audit: false,
    report: false,
  },
  strict: {
    name: 'strict',
    description: 'Maximum local protection',
    guards: {
      destructive: true,
      secrets: true,
      exfil: true,
      forcepush: true,
      scope: true,
      sudo: true,
      docker_privileged: true,
      chmod_world: true,
      symlink_escape: true,
      curl_any_pipe: true,
      git_config_hooks: true,
    },
    protectedBranches: ['main', 'master', 'production', 'prod', 'release', 'trunk', 'develop'],
    audit: true,
    report: true,
  },
  ci: {
    name: 'ci',
    description: 'CI check mode — fail the job on any block; no interactive ask',
    guards: {
      destructive: true,
      secrets: true,
      exfil: true,
      forcepush: true,
      scope: true,
      sudo: true,
      docker_privileged: true,
      chmod_world: true,
      symlink_escape: true,
      curl_any_pipe: true,
      git_config_hooks: true,
    },
    protectedBranches: ['main', 'master', 'production', 'prod', 'release'],
    audit: true,
    report: true,
    failClosed: true,
  },
};

function loadPolicy(projectRoot, opts = {}) {
  const profileName = opts.profile || process.env.TALOS_PROFILE || process.env.AGENT_GUARD_PROFILE || 'solo';
  const base = { ...(PROFILES[profileName] || PROFILES.solo) };
  base.guards = { ...base.guards };
  base.protectedBranches = [...(base.protectedBranches || [])];

  const candidates = [
    opts.policyPath,
    projectRoot && path.join(projectRoot, 'agent-guard.config.json'),
    projectRoot && path.join(projectRoot, '.agent-guard.json'),
    path.join(process.env.HOME || '', '.agent-guard.json'),
  ].filter(Boolean);

  for (const file of candidates) {
    try {
      if (!fs.existsSync(file)) continue;
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (raw.profile && PROFILES[raw.profile] && !opts.profile) {
        Object.assign(base, PROFILES[raw.profile]);
        base.guards = { ...PROFILES[raw.profile].guards };
        base.protectedBranches = [...PROFILES[raw.profile].protectedBranches];
      }
      if (raw.guards) Object.assign(base.guards, raw.guards);
      if (raw.protectedBranches) base.protectedBranches = raw.protectedBranches;
      if (raw.audit != null) base.audit = !!raw.audit;
      if (raw.report != null) base.report = !!raw.report;
      if (raw.allowPaths) base.allowPaths = raw.allowPaths;
      if (raw.projectRoot) base.projectRoot = raw.projectRoot;
      if (raw.auditLog) base.auditLog = raw.auditLog;
      base.policyFile = file;
      break;
    } catch (err) {
      base.policyError = String(err.message || err);
    }
  }

  // free tier cannot enable pro-only features without license — enforced by caller
  return base;
}

module.exports = { PROFILES, loadPolicy };
