'use strict';
// Deterministic, dependency-free bash-ish lexer + command analyzer.
// Sees through quoting, escapes, env vars (with known defaults), subshells,
// wrappers (`env`, `xargs`, `nice`, `timeout`, `sudo`, `sh -c`, `bash -c`,
// `eval`, `source`), base64/openssl piping, and curl|sh style exfil.
// Not a full POSIX shell. Unknown dynamics are marked `dyn`.

const SHELLS = new Set(['sh','bash','zsh','dash','ksh','mksh','ash','fish','csh','tcsh']);
const INTERPRETERS = new Set(['python','python2','python3','node','nodejs','perl','ruby','php','deno','bun','pwsh','powershell','lua','osascript']);
const FETCHERS = new Set(['curl','wget','fetch','http','https','xh','aria2c']);
const DECODERS = new Set(['base64','base32','xxd','openssl','gunzip','gzip','zcat','bzip2','xz','rev','tr','uudecode','basenc']);
const WRAPPERS = new Set(['env','command','builtin','nice','nohup','time','timeout','stdbuf','ionice','taskset','numactl','unshare','nsenter','chroot','firejail','sudo','doas','su','xargs','watch','parallel','script','setsid','flock','strace','ltrace','gdb','rlwrap','busybox']);
const SECRET_VAR_RE = /(SECRET|TOKEN|PASSW(OR)?D|PASS$|PASSPHRASE|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY|AUTH|SESSION_?KEY|COOKIE|DATABASE_URL|DSN|BEARER|JWT)/i;
const MAX_DEPTH = 8;

function decodeAnsiC(s) {
  return s.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)/g, (m, e) => {
    const c = e[0];
    if (c === 'x' || c === 'u' || c === 'U') return String.fromCodePoint(parseInt(e.slice(1), 16) || 0);
    if (/[0-7]/.test(c)) return String.fromCharCode(parseInt(e, 8));
    return ({ n:'\n', t:'\t', r:'\r', a:'\x07', b:'\b', e:'\x1b', E:'\x1b', f:'\f', v:'\v', '\\':'\\', "'":"'", '"':'"', '?':'?' })[c] ?? m;
  });
}

function readBalanced(src, i, open='(', close=')') {
  let depth = 1, out = '';
  while (i < src.length) {
    const ch = src[i];
    if (ch === '\\') { out += ch + (src[i+1] ?? ''); i += 2; continue; }
    if (ch === "'") {
      const j = src.indexOf("'", i + 1);
      const e = j < 0 ? src.length : j;
      out += src.slice(i, e + 1); i = e + 1; continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') { if (src[j] === '\\') j++; j++; }
      out += src.slice(i, Math.min(j + 1, src.length)); i = j + 1; continue;
    }
    if (ch === open) depth++;
    else if (ch === close) { depth--; if (depth === 0) return [out, i + 1, true]; }
    out += ch; i++;
  }
  return [out, i, false];
}

function lex(src) {
  const toks = [];
  let i = 0, word = null, unterminated = false;
  const n = src.length;
  const ensure = () => (word ||= { type: 'word', parts: [], quoted: false });
  const lit = (s, q) => {
    const w = ensure();
    const last = w.parts[w.parts.length - 1];
    if (last && last.t === 'lit' && last.q === q) last.v += s;
    else w.parts.push({ t: 'lit', v: s, q });
    if (q) w.quoted = true;
  };
  const flush = () => { if (word) { toks.push(word); word = null; } };
  const readDollar = (inDq) => {
    const nx = src[i + 1];
    if (nx === '(' && src[i + 2] === '(') {
      const [b, j] = readBalanced(src, i + 3);
      i = j; if (src[i] === ')') i++;
      ensure().parts.push({ t: 'var', name: '((' + b + '))', arith: true });
      return;
    }
    if (nx === '(') {
      const [b, j, ok] = readBalanced(src, i + 2);
      if (!ok) unterminated = true;
      i = j;
      ensure().parts.push({ t: 'sub', src: b });
      return;
    }
    if (nx === '{') {
      const [b, j, ok] = readBalanced(src, i + 2, '{', '}');
      if (!ok) unterminated = true;
      i = j;
      const m = /^([#!]?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])([\s\S]*)$/.exec(b) || ['', '', b, ''];
      let def = null;
      const mm = /^:?[-=]([\s\S]*)$/.exec(m[3]);
      if (mm) def = mm[1];
      ensure().parts.push({ t: 'var', name: m[2], raw: '${' + b + '}', def, mod: m[1] || (m[3] && !mm ? m[3] : '') });
      return;
    }
    if (nx === "'" && !inDq) {
      let j = i + 2, s = '';
      while (j < n && src[j] !== "'") {
        if (src[j] === '\\') { s += src[j] + (src[j + 1] ?? ''); j += 2; }
        else s += src[j++];
      }
      if (j >= n) unterminated = true;
      i = j + 1;
      lit(decodeAnsiC(s), true);
      return;
    }
    if (nx === '"' && !inDq) { i++; return; }
    const m = /^([A-Za-z_][A-Za-z0-9_]*|[0-9]|[@*#?$!-])/.exec(src.slice(i + 1));
    if (m) {
      ensure().parts.push({ t: 'var', name: m[1], raw: '$' + m[1] });
      i += 1 + m[1].length;
      return;
    }
    lit('$', false); i++;
  };

  while (i < n) {
    const ch = src[i];
    if (ch === '\\') {
      if (i + 1 < n) {
        if (src[i + 1] === '\n') { i += 2; continue; }
        lit(src[i + 1], false); i += 2; continue;
      }
      lit('\\', false); i++; continue;
    }
    if (ch === '#') {
      if (!word) { while (i < n && src[i] !== '\n') i++; continue; }
      lit('#', false); i++; continue;
    }
    if (/\s/.test(ch)) { flush(); i++; continue; }
    if (ch === "'" ) {
      let j = i + 1, s = '';
      while (j < n && src[j] !== "'") s += src[j++];
      if (j >= n) unterminated = true;
      lit(s, true); i = j + 1; continue;
    }
    if (ch === '"') {
      i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n && '$`"\\\n'.includes(src[i + 1])) {
          if (src[i + 1] === '\n') { i += 2; continue; }
          lit(src[i + 1], true); i += 2; continue;
        }
        if (src[i] === '`') {
          let j = i + 1, b = '';
          while (j < n && src[j] !== '`') { if (src[j] === '\\') { b += src[j] + (src[j+1]??''); j+=2; } else b += src[j++]; }
          if (j >= n) unterminated = true;
          ensure().parts.push({ t: 'sub', src: b, backtick: true });
          i = j + 1; continue;
        }
        if (src[i] === '$') { readDollar(true); continue; }
        lit(src[i], true); i++;
      }
      if (i >= n) unterminated = true; else i++;
      continue;
    }
    if (ch === '`') {
      let j = i + 1, b = '';
      while (j < n && src[j] !== '`') { if (src[j] === '\\') { b += src[j] + (src[j+1]??''); j+=2; } else b += src[j++]; }
      if (j >= n) unterminated = true;
      ensure().parts.push({ t: 'sub', src: b, backtick: true });
      i = j + 1; continue;
    }
    if (ch === '$') { readDollar(false); continue; }
    // operators
    const two = src.slice(i, i + 2);
    const three = src.slice(i, i + 3);
    if (three === '<<-' || three === '<<<') { flush(); toks.push({ type: 'op', v: three }); i += 3; continue; }
    if (['&&','||','>>','<<','>&','<&','>|',';;',';;&',';&',';|'].includes(two)) {
      flush(); toks.push({ type: 'op', v: two }); i += 2; continue;
    }
    if ('|&;()<>'.includes(ch)) {
      flush(); toks.push({ type: 'op', v: ch }); i++; continue;
    }
    lit(ch, false); i++;
  }
  flush();
  return { toks, unterminated };
}

function wordText(w, { resolveVar } = {}) {
  if (!w || w.type !== 'word') return { text: '', dyn: false, parts: [] };
  let text = '', dyn = false;
  const parts = [];
  for (const p of w.parts) {
    if (p.t === 'lit') { text += p.v; parts.push({ kind: 'lit', v: p.v }); }
    else if (p.t === 'var') {
      if (p.arith) { dyn = true; text += '${' + p.name + '}'; parts.push({ kind: 'var', name: p.name, dyn: true }); continue; }
      let val = null;
      if (resolveVar) val = resolveVar(p.name);
      if (val == null && p.def != null) {
        // default may itself have structure; treat as literal for now
        val = String(p.def).replace(/^["']|["']$/g, '');
      }
      if (val != null) { text += val; parts.push({ kind: 'var', name: p.name, v: val }); }
      else { dyn = true; text += p.raw || ('$' + p.name); parts.push({ kind: 'var', name: p.name, dyn: true }); }
    } else if (p.t === 'sub') {
      dyn = true;
      text += '$(' + p.src + ')';
      parts.push({ kind: 'sub', src: p.src });
    }
  }
  return { text, dyn, parts, quoted: !!w.quoted };
}

function basenameCmd(s) {
  if (!s) return '';
  const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  let base = slash >= 0 ? s.slice(slash + 1) : s;
  // strip busybox applet style and versioned interpreters: python3.11
  base = base.replace(/^busybox$/, 'busybox');
  return base;
}

function splitPipelines(toks) {
  // Split on ; & && || \n (as ops) into lists of pipelines; each pipeline is list of stages split by |
  const statements = [];
  let cur = [];
  const flushStmt = () => { if (cur.length) { statements.push(cur); cur = []; } };
  for (const t of toks) {
    if (t.type === 'op' && [';', '&&', '||', '&', '\n'].includes(t.v)) { flushStmt(); continue; }
    cur.push(t);
  }
  flushStmt();
  return statements.map(stmt => {
    const stages = [];
    let stage = [];
    for (const t of stmt) {
      if (t.type === 'op' && (t.v === '|' || t.v === '|&')) { stages.push(stage); stage = []; continue; }
      stage.push(t);
    }
    stages.push(stage);
    return stages;
  });
}

function parseStage(stageToks, env) {
  const words = [];
  const redirects = [];
  let i = 0;
  while (i < stageToks.length) {
    const t = stageToks[i];
    if (t.type === 'op' && (t.v === '<' || t.v === '>' || t.v === '>>' || t.v === '>&' || t.v === '<&' || t.v === '>|' || t.v === '<<' || t.v === '<<-' || t.v === '<<<')) {
      const target = stageToks[i + 1];
      redirects.push({ op: t.v, target: target && target.type === 'word' ? wordText(target, { resolveVar: (n) => env[n] }) : null });
      i += 2; continue;
    }
    if (t.type === 'word') {
      // assignments FOO=bar at start
      const wt = wordText(t, { resolveVar: (n) => env[n] });
      words.push(wt);
      i++; continue;
    }
    if (t.type === 'op' && (t.v === '(' || t.v === ')')) { i++; continue; }
    i++;
  }
  return { words, redirects };
}

function peelWrappers(argv, flags) {
  // argv: [{text,dyn}], returns {cmd, args, wrappers, envAssigns, dyn}
  const envAssigns = {};
  let i = 0;
  let wrappers = [];
  let dyn = false;
  while (i < argv.length) {
    const a = argv[i];
    if (a.dyn) dyn = true;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(a.text);
    if (m && !a.quoted) { envAssigns[m[1]] = m[2]; i++; continue; }
    break;
  }
  while (i < argv.length) {
    const raw = argv[i].text;
    const base = basenameCmd(raw);
    if (WRAPPERS.has(base) || base === 'busybox') {
      wrappers.push(base);
      i++;
      if (base === 'env') {
        while (i < argv.length) {
          const t = argv[i].text;
          if (t === '-i' || t === '-0' || t === '-u' || t.startsWith('-')) {
            if ((t === '-u' || t === '--unset') && argv[i+1]) { i += 2; continue; }
            i++; continue;
          }
          const mm = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(t);
          if (mm) { envAssigns[mm[1]] = mm[2]; i++; continue; }
          break;
        }
        continue;
      }
      if (base === 'sudo' || base === 'doas') {
        while (i < argv.length && argv[i].text.startsWith('-')) {
          const f = argv[i].text;
          if (['-u','-g','-h','-C','-p','-U'].includes(f) && argv[i+1]) { i += 2; continue; }
          i++;
        }
        continue;
      }
      if (base === 'timeout' || base === 'nice' || base === 'ionice' || base === 'taskset') {
        // skip their own args
        while (i < argv.length && argv[i].text.startsWith('-')) {
          const f = argv[i].text;
          if (!f.includes('=') && argv[i+1] && !argv[i+1].text.startsWith('-') && !/^\d/.test(f.slice(1))) {
            // ambiguous; take next if looks like value for short opts that need it
          }
          i++;
          // timeout DURATION cmd — duration may be bare
        }
        // timeout: next non-option may be duration
        if (base === 'timeout' && i < argv.length && /^[0-9]/.test(argv[i].text)) i++;
        if (base === 'nice' && i < argv.length && /^-?[0-9]+$/.test(argv[i].text)) i++;
        continue;
      }
      if (base === 'xargs') {
        while (i < argv.length && argv[i].text.startsWith('-')) {
          const f = argv[i].text;
          if (['-I','-J','-n','-P','-s','-E','-e','-L','-l'].includes(f) && argv[i+1]) { i += 2; continue; }
          if (f.startsWith('-I') || f.startsWith('-J')) { i++; continue; }
          i++;
        }
        continue;
      }
      if (base === 'busybox' && i < argv.length) continue;
      continue;
    }
    break;
  }
  let cmd = argv[i] ? basenameCmd(argv[i].text) : '';
  let cmdDyn = argv[i] ? argv[i].dyn : false;
  let args = argv.slice(i + 1);
  let outArgv = argv.slice(i);
  // Lone `env` / `printenv` (common in env|curl exfil) — not a wrapper
  if (!cmd && wrappers.length) {
    const last = wrappers[wrappers.length - 1];
    if (last === 'env' || last === 'printenv' || last === 'export') {
      cmd = last;
      wrappers = wrappers.slice(0, -1);
      outArgv = [{ text: cmd, dyn: false }];
      args = [];
    }
  }
  return { cmd, cmdDyn: cmdDyn || dyn, args, wrappers, envAssigns, argv: outArgv };
}

function collectSubs(toks) {
  const subs = [];
  for (const t of toks) {
    if (t.type !== 'word') continue;
    for (const p of t.parts) {
      if (p.t === 'sub') subs.push(p.src);
    }
  }
  return subs;
}

function tryDecodePayload(text) {
  const out = [];
  // base64 blobs (long-ish)
  const b64re = /(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?:[^A-Za-z0-9+/=]|$)/g;
  let m;
  while ((m = b64re.exec(text))) {
    try {
      const buf = Buffer.from(m[1], 'base64');
      if (buf.length >= 4) {
        const s = buf.toString('utf8');
        if (!/[\x00-\x08\x0e-\x1f]/.test(s)) out.push({ kind: 'base64', text: s });
      }
    } catch (_) { /* ignore */ }
  }
  // printf octal/hex sequences commonly used for obfuscation
  const printfRe = /printf\s+(?:--\s+)?['"]((?:\\[0-7]{1,3}|\\x[0-9a-fA-F]{2}|\\n|\\t|\\\\|.)+)['"]/g;
  while ((m = printfRe.exec(text))) {
    try {
      const s = decodeAnsiC(m[1]);
      if (s) out.push({ kind: 'printf', text: s });
    } catch (_) { /* ignore */ }
  }
  // echo -e with octals
  const echoRe = /echo\s+-e\s+['"]((?:\\[0-7]{1,3}|\\x[0-9a-fA-F]{2}|.)+)['"]/g;
  while ((m = echoRe.exec(text))) {
    try {
      const s = decodeAnsiC(m[1]);
      if (s) out.push({ kind: 'echo', text: s });
    } catch (_) { /* ignore */ }
  }
  return out;
}

function analyzeCommand(src, opts = {}) {
  const depth = opts.depth || 0;
  const env = Object.assign({}, opts.env || {});
  const findings = [];
  const commands = []; // peeled command records
  const raw = String(src == null ? '' : src);
  if (!raw.trim()) return { raw, commands, findings, subs: [], decoded: [], dyn: false, unterminated: false };

  const { toks, unterminated } = lex(raw);
  const pipelines = splitPipelines(toks);
  const allSubs = collectSubs(toks);
  const decoded = tryDecodePayload(raw);
  let anyDyn = unterminated;

  function considerShellString(str, via) {
    if (!str || depth >= MAX_DEPTH) return;
    const inner = analyzeCommand(str, { depth: depth + 1, env });
    for (const c of inner.commands) commands.push({ ...c, via });
    findings.push(...inner.findings);
    allSubs.push(...inner.subs);
    decoded.push(...inner.decoded);
    if (inner.dyn) anyDyn = true;
  }

  for (const stages of pipelines) {
    const stageInfos = stages.map(st => parseStage(st, env));
    // look at pipe graph for curl|sh etc.
    const peeled = stageInfos.map(si => {
      const argv = si.words;
      // apply env assigns into env for subsequent
      for (const w of argv) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(w.text);
        if (m && !w.quoted) env[m[1]] = m[2];
        else break;
      }
      return peelWrappers(argv, {});
    });

    for (let si = 0; si < peeled.length; si++) {
      const p = peeled[si];
      if (p.cmdDyn) anyDyn = true;
      const rec = {
        cmd: p.cmd,
        args: p.args.map(a => a.text),
        argsDyn: p.args.map(a => !!a.dyn),
        wrappers: p.wrappers,
        envAssigns: p.envAssigns,
        redirects: stageInfos[si].redirects,
        argvText: p.argv.map(a => a.text),
        dyn: p.cmdDyn,
        via: null,
      };
      commands.push(rec);

      // sh -c / bash -c / eval / source
      if (SHELLS.has(p.cmd) || p.cmd === 'busybox') {
        const args = p.args.map(a => a.text);
        let idx = 0;
        // skip shell flags until -c or script
        while (idx < args.length && args[idx].startsWith('-') && args[idx] !== '-c' && args[idx] !== '-s') {
          // -o opt, -O opt take values sometimes
          if (['-o','-O','-c'].includes(args[idx])) break;
          idx++;
        }
        if (args[idx] === '-c' && args[idx + 1] != null) {
          considerShellString(args[idx + 1], p.cmd + ' -c');
        } else if (args[idx] === '-s') {
          // reads stdin — mark dyn
          anyDyn = true;
        }
      }
      if (p.cmd === 'eval') {
        considerShellString(p.args.map(a => a.text).join(' '), 'eval');
      }
      if (p.cmd === 'source' || p.cmd === '.') {
        // sourcing local file — not expanding here
      }
      if (p.cmd === 'xargs' && p.args.length) {
        // already peeled; remaining is command
      }
      // node -e / python -c
      if (INTERPRETERS.has(p.cmd)) {
        const args = p.args.map(a => a.text);
        for (let k = 0; k < args.length; k++) {
          if ((args[k] === '-c' || args[k] === '-e' || args[k] === '--eval') && args[k + 1] != null) {
            findings.push({ kind: 'interpreter_inline', cmd: p.cmd, code: args[k + 1] });
            // also try to see shell-looking strings inside
            const shellish = args[k + 1].match(/(?:exec|spawn|system|popen|os\.system|child_process|subprocess)\s*\(/);
            if (shellish) findings.push({ kind: 'interpreter_exec', cmd: p.cmd, code: args[k + 1] });
          }
        }
      }
    }

    // pipe-based: fetcher | shell, decoder | shell
    for (let i = 0; i < peeled.length - 1; i++) {
      const a = peeled[i], b = peeled[i + 1];
      if ((FETCHERS.has(a.cmd) || DECODERS.has(a.cmd) || a.cmd === 'echo' || a.cmd === 'printf' || a.cmd === 'cat') &&
          (SHELLS.has(b.cmd) || b.cmd === 'eval' || INTERPRETERS.has(b.cmd) || b.cmd === 'sh' || b.wrappers.includes('sh'))) {
        findings.push({ kind: 'pipe_to_shell', from: a.cmd, to: b.cmd });
      }
      if (FETCHERS.has(a.cmd) && (SHELLS.has(b.cmd) || b.cmd === 'eval')) {
        findings.push({ kind: 'curl_pipe_shell', from: a.cmd, to: b.cmd });
      }
    }
  }

  for (const sub of allSubs.slice()) {
    if (depth < MAX_DEPTH) {
      const inner = analyzeCommand(sub, { depth: depth + 1, env });
      for (const c of inner.commands) commands.push({ ...c, via: 'subshell' });
      findings.push(...inner.findings);
      if (inner.dyn) anyDyn = true;
      decoded.push(...inner.decoded);
    }
  }

  for (const d of decoded.slice()) {
    if (depth < MAX_DEPTH && /[;&|`$]|sh\b|bash\b|curl\b|wget\b|rm\b/.test(d.text)) {
      considerShellString(d.text, 'decoded:' + d.kind);
    }
  }

  return { raw, commands, findings, subs: allSubs, decoded, dyn: anyDyn, unterminated, env };
}

function looksLikeUrl(s) {
  return /^(https?|ftp|file):\/\//i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}\//i.test(s);
}

module.exports = {
  lex, wordText, analyzeCommand, basenameCmd, SECRET_VAR_RE, SHELLS, INTERPRETERS, FETCHERS, DECODERS, WRAPPERS, looksLikeUrl, tryDecodePayload, decodeAnsiC,
};
