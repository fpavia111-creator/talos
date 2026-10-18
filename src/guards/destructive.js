'use strict';
const { analyzeCommand, basenameCmd } = require('../shell');

const DEVICE_RE = /^\/dev\/(sd[a-z]|hd[a-z]|vd[a-z]|nvme\d+n\d+|disk\d+|rdisk\d+|mmcblk\d+|xvd[a-z]|loop\d+)(\d+p?\d*)?$/i;
const DANGEROUS_RM_TARGETS = new Set(['/', '/.', '/..', '/*', '/\*']);
const HOME_LIKE = new Set(['~', '$HOME', '${HOME}', '~/', '~/.', '$HOME/', '${HOME}/']);

function isProtectedPath(p) {
  if (!p) return false;
  const s = String(p).replace(/\/+$/, '') || '/';
  if (s === '/' || s === '/.' || s === '/..') return true;
  if (s === '/*' || s === '/\*') return true;
  // $HOME, ~ alone or with trailing slash as rm target
  if (HOME_LIKE.has(p) || HOME_LIKE.has(s)) return true;
  if (/^(\$HOME|\$\{HOME\}|~)\/\*$/.test(p)) return true;
  // Windows drive roots
  if (/^[A-Za-z]:[\\\/]?$/.test(p) || p === 'C:\\' || p === 'C:/') return true;
  return false;
}

function hasForceRecursive(args) {
  let force = false, recursive = false;
  for (const a of args) {
    if (a === '-f' || a === '--force') force = true;
    else if (a === '-r' || a === '-R' || a === '--recursive') recursive = true;
    else if (a.startsWith('-') && !a.startsWith('--')) {
      if (a.includes('f')) force = true;
      if (a.includes('r') || a.includes('R')) recursive = true;
    }
  }
  return force && recursive;
}

function checkDestructive(command, opts = {}) {
  const hits = [];
  const analysis = typeof command === 'object' && command.commands
    ? command
    : analyzeCommand(command, opts);

  for (const c of analysis.commands) {
    const cmd = c.cmd;
    const args = c.args || [];

    if (cmd === 'rm' || cmd === 'rmdir') {
      const fr = hasForceRecursive(args);
      const targets = args.filter(a => !a.startsWith('-') || a === '--');
      // after --
      let afterDash = false;
      const paths = [];
      for (const a of args) {
        if (a === '--') { afterDash = true; continue; }
        if (!afterDash && a.startsWith('-')) continue;
        paths.push(a);
      }
      for (const p of paths) {
        if (isProtectedPath(p) && (fr || cmd === 'rm')) {
          hits.push({
            guard: 'destructive',
            rule: 'rm_protected',
            severity: 'block',
            message: `Blocked destructive remove of protected path: ${p}`,
            detail: { cmd, args, path: p },
          });
        }
        // rm -rf with glob of home
        if (fr && (/^(\$HOME|\$\{HOME\}|~)\//.test(p) || p === '*' || p === './*')) {
          if (p === '*' || p === './*' || isProtectedPath(p) || /^(~|\$HOME)/.test(p)) {
            // only flag * when combined with cd / or when clearly home
            if (p === '*' || p === './*') {
              hits.push({
                guard: 'destructive',
                rule: 'rm_star',
                severity: 'block',
                message: `Blocked rm -rf with broad glob: ${p}`,
                detail: { cmd, args, path: p },
              });
            }
          }
        }
      }
    }

    if (cmd === 'dd') {
      for (const a of args) {
        const m = /^of=(.+)$/i.exec(a);
        if (m && (DEVICE_RE.test(m[1]) || m[1] === '/dev/sda' || /^\/dev\//.test(m[1]) && !/\/dev\/(null|zero|random|urandom|stdout|stderr|stdin|fd\/)/.test(m[1]))) {
          hits.push({
            guard: 'destructive',
            rule: 'dd_device',
            severity: 'block',
            message: `Blocked dd writing to device: ${m[1]}`,
            detail: { cmd, args },
          });
        }
      }
    }

    if (['mkfs', 'mkfs.ext4', 'mkfs.ext3', 'mkfs.xfs', 'mkfs.btrfs', 'mkfs.vfat', 'mkfs.ntfs', 'mkfs.fat', 'newfs', 'diskutil', 'format'].includes(cmd) || /^mkfs\./.test(cmd)) {
      hits.push({
        guard: 'destructive',
        rule: 'mkfs',
        severity: 'block',
        message: `Blocked filesystem format command: ${cmd}`,
        detail: { cmd, args },
      });
    }

    if (cmd === 'wipefs' || cmd === 'shred') {
      const paths = args.filter(a => !a.startsWith('-'));
      if (paths.some(p => DEVICE_RE.test(p) || p === '/' || /^\/dev\//.test(p))) {
        hits.push({
          guard: 'destructive',
          rule: 'wipe_device',
          severity: 'block',
          message: `Blocked ${cmd} on device/root`,
          detail: { cmd, args },
        });
      }
    }

    if (cmd === 'chmod' && args.some(a => a === '-R' || a === '--recursive')) {
      const mode = args.find(a => /^[0-7]{3,4}$/.test(a) || a === '777' || a === 'a+rwx');
      const target = args.filter(a => !a.startsWith('-') && !/^[0-7]{3,4}$/.test(a)).pop();
      if (mode && (mode === '777' || mode === '0777' || mode === 'a+rwx') && target && (target === '/' || target === '/*' || target === '~' || target === '$HOME')) {
        hits.push({
          guard: 'destructive',
          rule: 'chmod_world_root',
          severity: 'block',
          message: `Blocked chmod -R ${mode} on ${target}`,
          detail: { cmd, args },
        });
      }
    }

    // git clean -fdx / and similar already covered elsewhere; fork bomb
    if (args.some(a => a.includes(':(){') || a.includes(':(){:|:&};:'))) {
      hits.push({
        guard: 'destructive',
        rule: 'fork_bomb',
        severity: 'block',
        message: 'Blocked fork bomb pattern',
        detail: { cmd, args },
      });
    }
  }

  // raw text fallbacks for highly obfuscated but obvious patterns
  const raw = analysis.raw || '';
  if (/(?:^|[\s;|&])rm\s+(?:-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*)\s+(?:--\s+)?(?:\/|\/\*|~(?:\/)?|\$HOME(?:\/)?)\s*(?:$|[\s;|&])/.test(raw)) {
    if (!hits.some(h => h.rule === 'rm_protected' || h.rule === 'rm_star')) {
      hits.push({
        guard: 'destructive',
        rule: 'rm_protected_raw',
        severity: 'block',
        message: 'Blocked destructive rm -rf on protected path (pattern match)',
        detail: { raw: raw.slice(0, 200) },
      });
    }
  }

  return hits;
}

module.exports = { checkDestructive, isProtectedPath, hasForceRecursive };
