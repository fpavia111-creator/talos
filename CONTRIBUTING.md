# Contributing

Thanks for helping make Talos safer.

## Setup

```bash
git clone https://github.com/fpavia111-creator/talos.git
cd talos
npm test
```

No install step — zero dependencies.

## Tests

```bash
npm test
```

Add bypass attempts as regression tests under `test/`. Prefer false-negative fixes that do **not** create noisy false positives on normal agent work (`npm test`, `git status`, `rm dist/file`, etc.).

## Scope

- Free core lives in `src/` and must stay dependency-free.
- Pro extras live under `pro/` and are not published in the public npm tarball.
- Do not commit license private keys.

## Code of conduct

Be kind. Security reports: open a private GitHub security advisory or email the maintainer listed in package.json.
