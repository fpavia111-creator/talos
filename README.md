# Talos of Humans

*Formerly **agent-guard**. The npm package is now `@kurtfrancisco/talos` and the command is `talos`; `agent-guard`, the `AGENT_GUARD_*` environment variables, `agent-guard.config.json` / `.agent-guard.json` and the `.agent-guard/` audit folder all keep working.*

**Runtime guardrails for AI coding agents.** Hooks for [Claude Code](https://code.claude.com/docs/en/hooks), [Cursor](https://cursor.com/docs/agent/hooks), and [Codex](https://learn.chatgpt.com/docs/hooks) that block dangerous actions before they run.

> Package: **`@kurtfrancisco/talos`** (the old `@kurtfrancisco/talos` is deprecated).

Free MIT core · Pro **launch price $11** one-time (will rise later)

## What it blocks (free core — 5 guards)

| Guard | Examples |
| --- | --- |
| **destructive** | `rm -rf /`, `rm -rf ~`, `dd of=/dev/sda`, `mkfs`, wipefs on disks |
| **secrets** | Writing private keys / AWS keys / `.env` credential values into files |
| **exfil** | `curl | sh`, `wget | bash`, posting `env`/tokens to URLs, scp of `.env` |
| **forcepush** | `git push --force` to `main` / `master` / `production` |
| **scope** | Edit/Write outside the project root |

Deterministic. No LLM calls. **Zero runtime dependencies** (Node ≥ 18).

## Install

```bash
npm i -D @kurtfrancisco/talos
npx talos init --agent all
```

Or one-shot:

```bash
npx @kurtfrancisco/talos init --agent claude
```

`init` writes the correct hook config for each agent:

- Claude Code → `.claude/settings.json` (`PreToolUse`)
- Cursor → `.cursor/hooks.json` (`beforeShellExecution` / `preToolUse`)
- Codex → `.codex/hooks.json` (`PreToolUse`) — trust via `/hooks` after install

## CLI

```bash
talos init [--agent claude|cursor|codex|all] [--profile solo|strict|ci]
talos check --command 'rm -rf /'
talos check --file .env
talos report          # Pro: HTML audit report
talos license        # verify SKS2 key
talos profiles
```

## Profiles (Pro)

| Profile | Intent |
| --- | --- |
| `solo` | Free-friendly defaults (also the free-tier behavior) |
| `strict` | Extra guards + audit log |
| `ci` | Fail-closed for CI / policy enforcement |

```bash
export TALOS_LICENSE_KEY='SKS2-....'   # AGENT_GUARD_LICENSE_KEY also works
talos init --agent all --profile strict
```

## Pro (launch price $11)

**$11 one-time** at launch (will rise later).

**[Buy Talos Pro: $11 one-time →](https://buy.stripe.com/9B614p8XLe7E7Oj0md5AQ03)**
Payment is handled by Stripe. Your license key arrives by email; set `TALOS_LICENSE_KEY` (`AGENT_GUARD_LICENSE_KEY` still works).

Includes:

- Extra guards (`sudo`, privileged Docker, world-writable `chmod`, symlink escape, download-then-exec, `git config` hooksPath)
- Profiles `strict` / `ci`
- Tamper-evident JSONL audit log (hash-chained)
- HTML report (`talos report`)
- Multi-agent support in one installer

License scheme matches Hephaestus of Skills Pro (formerly skill-shipper Pro) (Ed25519 `SKS2-` keys, product id `agent-guard-pro`). Offline verify. Dev override: `TALOS_LICENSE_DEV=1` (or `AGENT_GUARD_LICENSE_DEV=1`). Existing agent-guard Pro keys keep working.

## Honest limits

- Under Claude Code `--dangerously-skip-permissions`, some hooks may run asynchronously — do not treat hooks as a hard sandbox.
- Agents can still be told to disable hooks; this is a **guardrail**, not DRM or a seccomp jail.
- Obfuscation coverage is strong for common bypasses (quoting, env defaults, `sh -c`, base64, subshells) but not infinite.

## Competitors

Inspired by the demand shown by tools like **nah** and **Railguard**. Talos focuses on ready-made policy profiles, multi-agent hooks, an audit report teams can show a lead, and thorough bypass tests.

## License

MIT © Kurt Francisco
