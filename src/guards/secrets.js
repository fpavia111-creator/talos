'use strict';
const path = require('path');
const { analyzeCommand, SECRET_VAR_RE } = require('../shell');

const SECRET_FILE_RE = /(?:^|\/)(\.env(?:\..+)?|\.npmrc|\.pypirc|\.netrc|\.pgpass|\.aws\/credentials|\.ssh\/id_|\.ssh\/.*key|credentials\.json|service-account.*\.json|.*\.(pem|p12|pfx|key))$/i;

const SECRET_CONTENT_RE = new RegExp(
  [
    '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    '(?:AKIA|ASIA)[A-Z0-9]{16}',
    'gh[pousr]_[A-Za-z0-9_]{20,}',
    'xox[baprs]-[A-Za-z0-9-]{10,}',
    'sk-[A-Za-z0-9]{20,}',
    'sk_live_[A-Za-z0-9]{20,}',
    'AIza[0-9A-Za-z\\-_]{35}',
    'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
    '^(?:export\\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\\s*=\\s*[\'"]?[^\'"\\s]{8,}',
  ].join('|'),
  'im'
);

function checkSecretsWrite({ filePath, content, command } = {}, opts = {}) {
  const hits = [];

  if (filePath) {
    const base = path.basename(filePath);
    const norm = filePath.replace(/\\/g, '/');
    if (SECRET_FILE_RE.test(norm) || SECRET_FILE_RE.test(base)) {
      if (content && SECRET_CONTENT_RE.test(content)) {
        hits.push({
          guard: 'secrets',
          rule: 'write_secret_file',
          severity: 'block',
          message: 'Blocked writing secrets into ' + base,
          detail: { filePath },
        });
      } else if (content && /=\s*['"]?[^'"\s]{6,}/.test(content) && /\.env/.test(base)) {
        hits.push({
          guard: 'secrets',
          rule: 'write_dotenv_values',
          severity: 'block',
          message: 'Blocked writing credential-like values into ' + base,
          detail: { filePath },
        });
      }
    }
    if (content && SECRET_CONTENT_RE.test(content)) {
      // avoid duplicate if already hit write_secret_file
      if (!hits.some(h => h.rule === 'write_secret_file')) {
        hits.push({
          guard: 'secrets',
          rule: 'write_secret_content',
          severity: 'block',
          message: 'Blocked writing secret material to ' + (base || filePath),
          detail: { filePath },
        });
      }
    }
  }

  if (command) {
    const analysis = typeof command === 'object' && command.commands
      ? command
      : analyzeCommand(command, opts);
    for (const c of analysis.commands) {
      if (['echo', 'printf', 'tee'].includes(c.cmd)) {
        const text = [c.cmd, ...c.args].join(' ');
        const redirs = c.redirects || [];
        for (const r of redirs) {
          const target = r.target && r.target.text;
          if (!target) continue;
          if ((r.op === '>' || r.op === '>>') && (SECRET_FILE_RE.test(target) || /\.env/.test(path.basename(target)))) {
            if (SECRET_CONTENT_RE.test(text) || c.args.some(a => SECRET_CONTENT_RE.test(a))) {
              hits.push({
                guard: 'secrets',
                rule: 'redirect_secret',
                severity: 'block',
                message: 'Blocked redirecting secrets into ' + target,
                detail: { target },
              });
            }
          }
        }
      }
      if (c.cmd === 'tee' && c.args.some(a => SECRET_FILE_RE.test(a) || /\.env/.test(a))) {
        hits.push({
          guard: 'secrets',
          rule: 'tee_secret_file',
          severity: 'block',
          message: 'Blocked tee into a secrets file',
          detail: { args: c.args },
        });
      }
    }
  }

  return hits;
}

module.exports = { checkSecretsWrite, SECRET_FILE_RE, SECRET_CONTENT_RE };
