'use strict';
const { checkDestructive } = require('./destructive');
const { checkSecretsWrite } = require('./secrets');
const { checkExfil } = require('./exfil');
const { checkForcePush } = require('./forcepush');
const { checkScope } = require('./scope');
const { analyzeCommand } = require('../shell');

const FREE_GUARDS = ['destructive', 'secrets', 'exfil', 'forcepush', 'scope'];

function runFreeGuards(ctx) {
  const hits = [];
  const analysis = ctx.command != null ? analyzeCommand(ctx.command, { env: ctx.env }) : null;
  if (ctx.command != null || analysis) {
    const a = analysis;
    if (ctx.guardsEnabled.destructive !== false) hits.push(...checkDestructive(a || ctx.command, ctx));
    if (ctx.guardsEnabled.exfil !== false) hits.push(...checkExfil(a || ctx.command, ctx));
    if (ctx.guardsEnabled.forcepush !== false) hits.push(...checkForcePush(a || ctx.command, ctx));
    if (ctx.guardsEnabled.secrets !== false) hits.push(...checkSecretsWrite({ command: a || ctx.command }, ctx));
  }
  if (ctx.filePath != null || ctx.content != null) {
    if (ctx.guardsEnabled.secrets !== false) {
      hits.push(...checkSecretsWrite({ filePath: ctx.filePath, content: ctx.content, command: ctx.command }, ctx));
    }
    if (ctx.guardsEnabled.scope !== false && ctx.filePath) {
      hits.push(...checkScope({
        filePath: ctx.filePath,
        cwd: ctx.cwd,
        projectRoot: ctx.projectRoot,
        allowPaths: ctx.allowPaths,
      }));
    }
  }
  return hits;
}

module.exports = {
  FREE_GUARDS,
  runFreeGuards,
  checkDestructive,
  checkSecretsWrite,
  checkExfil,
  checkForcePush,
  checkScope,
};
