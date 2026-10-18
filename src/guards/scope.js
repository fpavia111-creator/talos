'use strict';
const path = require('path');
const fs = require('fs');

function resolveProjectRoot(cwd, explicit) {
  if (explicit) return path.resolve(explicit);
  const start = cwd ? path.resolve(cwd) : process.cwd();
  // walk up for .git or package.json; fall back to cwd
  let dir = start;
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git')) || fs.existsSync(path.join(dir, 'package.json'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

function isInside(root, target) {
  const r = path.resolve(root);
  let t;
  try {
    t = path.resolve(r, target);
  } catch {
    return false;
  }
  // allow exact root
  if (t === r) return true;
  const rel = path.relative(r, t);
  if (!rel || rel === '') return true;
  if (rel.startsWith('..') || path.isAbsolute(rel)) return false;
  // block obvious escapes
  if (rel.split(path.sep).includes('..')) return false;
  return true;
}

function checkScope({ filePath, cwd, projectRoot, allowPaths } = {}) {
  const hits = [];
  if (!filePath) return hits;
  const root = resolveProjectRoot(cwd, projectRoot);
  const allowed = [root, ...(allowPaths || [])].map(p => path.resolve(p));

  // expand ~ 
  let target = filePath;
  if (target.startsWith('~/') || target === '~') {
    target = path.join(process.env.HOME || process.env.USERPROFILE || '', target.slice(1) || '');
  }

  const ok = allowed.some(r => isInside(r, target));
  if (!ok) {
    hits.push({
      guard: 'scope',
      rule: 'outside_project',
      severity: 'block',
      message: `Blocked edit/write outside project root (${path.basename(root)}): ${filePath}`,
      detail: { filePath, projectRoot: root },
    });
  }
  return hits;
}

module.exports = { checkScope, resolveProjectRoot, isInside };
