'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function defaultLogPath(projectRoot) {
  const base = projectRoot || process.cwd();
  return path.join(base, '.agent-guard', 'audit.jsonl');
}

function lastHash(file) {
  try {
    if (!fs.existsSync(file)) return null;
    const buf = fs.readFileSync(file, 'utf8');
    const lines = buf.trim().split('\n').filter(Boolean);
    if (!lines.length) return null;
    const last = JSON.parse(lines[lines.length - 1]);
    return last.hash || null;
  } catch {
    return null;
  }
}

function appendAudit(entry, opts = {}) {
  const file = opts.auditLog || defaultLogPath(opts.projectRoot);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const prev = lastHash(file);
  const body = {
    ts: new Date().toISOString(),
    agent: entry.agent || null,
    event: entry.event || null,
    decision: entry.decision || 'allow',
    reason: entry.reason || null,
    hits: entry.hits || [],
    tool: entry.tool || null,
    command: entry.command ? String(entry.command).slice(0, 2000) : null,
    filePath: entry.filePath || null,
    profile: entry.profile || null,
    cwd: entry.cwd || null,
    prev,
  };
  const hash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
  const line = JSON.stringify({ ...body, hash });
  fs.appendFileSync(file, line + '\n', { mode: 0o600 });
  return { file, hash };
}

function readAudit(opts = {}) {
  const file = opts.auditLog || defaultLogPath(opts.projectRoot);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => {
    try { return JSON.parse(l); } catch { return { parseError: true, raw: l }; }
  });
}

function verifyAuditChain(entries) {
  let prev = null;
  const broken = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.parseError) { broken.push({ i, reason: 'parse' }); continue; }
    if ((e.prev || null) !== prev) broken.push({ i, reason: 'prev_mismatch', expected: prev, got: e.prev });
    const { hash, ...body } = e;
    const h = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    if (hash !== h) broken.push({ i, reason: 'hash_mismatch' });
    prev = hash;
  }
  return { ok: broken.length === 0, broken };
}

module.exports = { appendAudit, readAudit, verifyAuditChain, defaultLogPath };
