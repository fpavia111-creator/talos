'use strict';
const fs = require('fs');
const path = require('path');
const { readAudit, verifyAuditChain, defaultLogPath } = require('./audit');

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildHtmlReport(opts = {}) {
  const entries = readAudit(opts);
  const chain = verifyAuditChain(entries);
  const blocked = entries.filter(e => e.decision === 'deny' || e.decision === 'block');
  const byGuard = {};
  for (const e of blocked) {
    for (const h of e.hits || []) {
      byGuard[h.guard] = (byGuard[h.guard] || 0) + 1;
    }
  }
  const rows = entries.slice(-500).reverse().map(e => {
    const hitSummary = (e.hits || []).map(h => `${h.guard}:${h.rule}`).join(', ');
    return `<tr class="${e.decision === 'deny' || e.decision === 'block' ? 'deny' : 'allow'}">
      <td>${esc(e.ts)}</td>
      <td>${esc(e.agent)}</td>
      <td>${esc(e.decision)}</td>
      <td>${esc(e.tool)}</td>
      <td class="mono">${esc((e.command || e.filePath || '').slice(0, 120))}</td>
      <td>${esc(hitSummary || e.reason || '')}</td>
    </tr>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Talos of Humans audit report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; line-height: 1.45; }
  h1 { font-size: 1.4rem; }
  .meta { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }
  .card { border: 1px solid #8884; border-radius: 8px; padding: .75rem 1rem; min-width: 8rem; }
  .card b { display: block; font-size: 1.4rem; }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { border-bottom: 1px solid #8883; text-align: left; padding: .4rem .5rem; vertical-align: top; }
  tr.deny { background: #f4312014; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .ok { color: #1a7f37; } .bad { color: #cf222e; }
  footer { margin-top: 2rem; opacity: .7; font-size: .85rem; }
</style>
</head>
<body>
  <h1>Talos of Humans audit report</h1>
  <p>Generated ${esc(new Date().toISOString())}. Chain integrity:
    <span class="${chain.ok ? 'ok' : 'bad'}">${chain.ok ? 'OK' : 'BROKEN (' + chain.broken.length + ')'}</span>
  </p>
  <div class="meta">
    <div class="card"><span>Events</span><b>${entries.length}</b></div>
    <div class="card"><span>Blocked</span><b>${blocked.length}</b></div>
    <div class="card"><span>Guards hit</span><b>${Object.keys(byGuard).length}</b></div>
  </div>
  <h2>Blocks by guard</h2>
  <ul>${Object.keys(byGuard).length ? Object.entries(byGuard).map(([k,v]) => `<li><code>${esc(k)}</code>: ${v}</li>`).join('') : '<li>None yet</li>'}</ul>
  <h2>Recent events</h2>
  <table>
    <thead><tr><th>Time</th><th>Agent</th><th>Decision</th><th>Tool</th><th>Command / path</th><th>Reason</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6">No audit events yet.</td></tr>'}</tbody>
  </table>
  <footer>Talos Pro · local JSONL at <code class="mono">${esc(opts.auditLog || defaultLogPath(opts.projectRoot))}</code></footer>
</body>
</html>`;
}

function writeHtmlReport(outPath, opts = {}) {
  const html = buildHtmlReport(opts);
  const dest = outPath || path.join(opts.projectRoot || process.cwd(), '.agent-guard', 'report.html');
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, html, 'utf8');
  return dest;
}

module.exports = { buildHtmlReport, writeHtmlReport };
