'use strict';
const { evaluate } = require('../engine');

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', c => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
    if (process.stdin.isTTY) resolve('');
  });
}

function parseStdinJson(raw) {
  const s = String(raw || '').trim();
  if (!s) return {};
  return JSON.parse(s);
}

function extractClaudeOrCodex(input) {
  const tool = input.tool_name || input.toolName || '';
  const toolInput = input.tool_input || input.toolInput || {};
  let command = null;
  let filePath = null;
  let content = null;

  const t = String(tool);
  if (/bash/i.test(t) || /shell/i.test(t) || t === 'Bash' || t === 'Shell') {
    command = toolInput.command || toolInput.cmd || null;
  } else if (/apply_patch/i.test(t)) {
    command = toolInput.command || null;
    // apply_patch may embed paths; leave to scope via content later
  } else if (/edit|write|create_file|notebook/i.test(t)) {
    filePath = toolInput.file_path || toolInput.path || toolInput.filePath || toolInput.target_notebook || null;
    content = toolInput.content || toolInput.new_string || toolInput.new_str || null;
    if (toolInput.command) command = toolInput.command;
  } else {
    command = toolInput.command || null;
    filePath = toolInput.file_path || toolInput.path || null;
    content = toolInput.content || null;
  }

  return {
    tool: t,
    command,
    filePath,
    content,
    cwd: input.cwd || process.env.CLAUDE_PROJECT_DIR || process.env.CURSOR_PROJECT_DIR || process.cwd(),
    event: input.hook_event_name || input.hookEventName || 'PreToolUse',
  };
}

function extractCursor(input, kind) {
  // kind: shell | edit | tool
  if (kind === 'shell' || input.command) {
    return {
      tool: 'Shell',
      command: input.command || (input.tool_input && input.tool_input.command) || null,
      filePath: null,
      content: null,
      cwd: input.cwd || process.env.CURSOR_PROJECT_DIR || process.cwd(),
      event: input.hook_event_name || 'beforeShellExecution',
    };
  }
  if (kind === 'edit') {
    return {
      tool: 'Write',
      command: null,
      filePath: input.file_path || input.path,
      content: (input.edits || []).map(e => e.new_string || e.new_line || '').join('\n') || input.content || null,
      cwd: (input.workspace_roots && input.workspace_roots[0]) || process.env.CURSOR_PROJECT_DIR || process.cwd(),
      event: 'afterFileEdit',
    };
  }
  // generic preToolUse
  const tool = input.tool_name || '';
  const toolInput = input.tool_input || {};
  return {
    tool,
    command: toolInput.command || input.command || null,
    filePath: toolInput.file_path || toolInput.path || null,
    content: toolInput.content || null,
    cwd: input.cwd || process.env.CURSOR_PROJECT_DIR || process.cwd(),
    event: input.hook_event_name || 'preToolUse',
  };
}

function denyClaude(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

function denyCodex(reason) {
  // Codex accepts Claude-shaped or legacy decision:block
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

function denyCursor(reason, { ask } = {}) {
  return {
    continue: true,
    permission: ask ? 'ask' : 'deny',
    user_message: reason,
    agent_message: reason,
  };
}

function allowCursor() {
  return { continue: true, permission: 'allow' };
}

function runAs(agent, extracted, extras = {}) {
  return evaluate({
    agent,
    tool: extracted.tool,
    command: extracted.command,
    filePath: extracted.filePath,
    content: extracted.content,
    cwd: extracted.cwd,
    event: extracted.event,
    projectRoot: extras.projectRoot || extracted.cwd,
    profile: extras.profile || process.env.TALOS_PROFILE || process.env.AGENT_GUARD_PROFILE,
    licenseKey: extras.licenseKey,
    forceAudit: extras.forceAudit,
  });
}

module.exports = {
  readStdin,
  parseStdinJson,
  extractClaudeOrCodex,
  extractCursor,
  denyClaude,
  denyCodex,
  denyCursor,
  allowCursor,
  runAs,
};
