'use strict';
const { analyzeCommand, SECRET_VAR_RE, FETCHERS, SHELLS, INTERPRETERS, looksLikeUrl } = require('../shell');

function argsHaveEnvDump(args) {
  const joined = args.join(' ');
  return /\benv\b/.test(joined) || /printenv/.test(joined) || /\$\{?(?:AWS_|GITHUB_|NPM_|OPENAI_|ANTHROPIC_|STRIPE_|DATABASE_|SECRET|TOKEN|PASSWORD|API_KEY)/i.test(joined);
}

function checkExfil(command, opts = {}) {
  const hits = [];
  const analysis = typeof command === 'object' && command.commands
    ? command
    : analyzeCommand(command, opts);

  
  // env|curl / printenv|wget across pipeline stages
  {
    const cmds = analysis.commands.map(c => c.cmd);
    for (let i = 0; i < cmds.length - 1; i++) {
      if ((cmds[i] === 'env' || cmds[i] === 'printenv' || cmds[i] === 'export') &&
          (FETCHERS.has(cmds[i+1]) || cmds[i+1] === 'nc' || cmds[i+1] === 'ncat' || cmds[i+1] === 'netcat' || cmds[i+1] === 'ssh' || cmds[i+1] === 'openssl')) {
        hits.push({
          guard: 'exfil',
          rule: 'pipeline_env_to_network',
          severity: 'block',
          message: 'Blocked piping environment to a network tool',
          detail: { from: cmds[i], to: cmds[i+1] },
        });
      }
    }
  }

  for (const f of analysis.findings) {
    if (f.kind === 'curl_pipe_shell' || f.kind === 'pipe_to_shell') {
      hits.push({
        guard: 'exfil',
        rule: 'pipe_to_shell',
        severity: 'block',
        message: `Blocked ${f.from}|${f.to} (download/decode piped to shell)`,
        detail: f,
      });
    }
  }

  for (const c of analysis.commands) {
    if (FETCHERS.has(c.cmd)) {
      const args = c.args || [];
      const joined = args.join(' ');
      // curl ... | already in findings; also curl with body from env
      const postsEnv = args.some((a, i) => {
        if (['-d', '--data', '--data-raw', '--data-binary', '--data-urlencode', '-F', '--form'].includes(a)) {
          const v = args[i + 1] || '';
          return SECRET_VAR_RE.test(v) || /\$\{?[A-Z0-9_]*(SECRET|TOKEN|PASS|KEY|CREDENTIAL)/i.test(v) || v === '$(env)' || v.includes('$(printenv');
        }
        if (/^--data/.test(a) && a.includes('=')) {
          return SECRET_VAR_RE.test(a) || /\$\{?[A-Z0-9_]*(SECRET|TOKEN|PASS|KEY)/i.test(a);
        }
        return false;
      });
      const hasUrl = args.some(a => looksLikeUrl(a) || /^[a-z0-9.-]+\.[a-z]{2,}/i.test(a));
      if (postsEnv && hasUrl) {
        hits.push({
          guard: 'exfil',
          rule: 'post_env_to_url',
          severity: 'block',
          message: 'Blocked posting environment/secrets to a remote URL',
          detail: { cmd: c.cmd, args },
        });
      }
      // curl|bash via curl's own -o with .sh then bash — separate
      if (/\|\s*(?:sh|bash|zsh|dash)\b/.test(analysis.raw) && FETCHERS.has(c.cmd)) {
        if (!hits.some(h => h.rule === 'pipe_to_shell')) {
          hits.push({
            guard: 'exfil',
            rule: 'pipe_to_shell_raw',
            severity: 'block',
            message: 'Blocked piping remote content to a shell',
            detail: { cmd: c.cmd },
          });
        }
      }
      // wget -O- url | sh
      if (c.cmd === 'wget' && (args.includes('-O-') || args.includes('-O') && args[args.indexOf('-O')+1] === '-')) {
        // companion pipe checked via findings
      }
    }

    // env | curl
    if ((c.cmd === 'env' || c.cmd === 'printenv' || c.cmd === 'export') && /\|\s*(?:curl|wget|nc|ncat|openssl|ssh)\b/.test(analysis.raw)) {
      hits.push({
        guard: 'exfil',
        rule: 'env_pipe_network',
        severity: 'block',
        message: 'Blocked piping environment to a network tool',
        detail: { cmd: c.cmd },
      });
    }

    // nc / ncat sending files
    if (c.cmd === 'nc' || c.cmd === 'ncat' || c.cmd === 'netcat') {
      if (argsHaveEnvDump(c.args) || /\$\{?(?:AWS_|SECRET|TOKEN)/i.test(c.args.join(' '))) {
        hits.push({
          guard: 'exfil',
          rule: 'nc_secrets',
          severity: 'block',
          message: 'Blocked netcat with secret-like payload',
          detail: { cmd: c.cmd, args: c.args },
        });
      }
    }

    // scp/rsync of .env outward — heuristic: .env as source with remote:
    if (c.cmd === 'scp' || c.cmd === 'rsync') {
      const args = c.args;
      const hasRemote = args.some(a => /^[A-Za-z0-9_.-]+@/.test(a) || /:/.test(a) && !a.startsWith('/'));
      const hasSecretFile = args.some(a => /\.env/.test(a) || /\.(pem|key)$/.test(a) || /id_rsa/.test(a));
      if (hasRemote && hasSecretFile) {
        hits.push({
          guard: 'exfil',
          rule: 'scp_secrets',
          severity: 'block',
          message: `Blocked ${c.cmd} of secret-like files to a remote host`,
          detail: { cmd: c.cmd, args },
        });
      }
    }

    // python/node one-liners posting env
    if (INTERPRETERS.has(c.cmd)) {
      const code = c.args.join(' ');
      if (/(urllib|requests|http\.client|fetch\(|axios|http\.post|net\.connect)/i.test(code) &&
          /(environ|process\.env|os\.env|SECRET|TOKEN|PASSWORD|API_KEY)/i.test(code)) {
        hits.push({
          guard: 'exfil',
          rule: 'interpreter_exfil',
          severity: 'block',
          message: `Blocked ${c.cmd} snippet that sends environment/secrets over the network`,
          detail: { cmd: c.cmd },
        });
      }
      if (/(curl|wget).*\b(sh|bash)\b|(exec|spawn|system).*https?:/i.test(code)) {
        hits.push({
          guard: 'exfil',
          rule: 'interpreter_remote_exec',
          severity: 'block',
          message: `Blocked ${c.cmd} remote-exec pattern`,
          detail: { cmd: c.cmd },
        });
      }
    }
  }

  // base64-decoded curl|sh
  for (const d of analysis.decoded || []) {
    if (/curl[^\n]*\|\s*(?:sh|bash)/i.test(d.text) || /wget[^\n]*\|\s*(?:sh|bash)/i.test(d.text)) {
      hits.push({
        guard: 'exfil',
        rule: 'decoded_pipe_to_shell',
        severity: 'block',
        message: 'Blocked obfuscated curl|sh (decoded payload)',
        detail: { kind: d.kind },
      });
    }
  }

  return hits;
}

module.exports = { checkExfil };
