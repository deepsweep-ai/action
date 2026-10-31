# AGENTS.md

Instructions for coding agents (Codex, Claude Code, Copilot) working in `deepsweep-ai/action`.

## What this repo is

The DeepSweep GitHub Action. A composite action (`action.yml`) that runs the bundled
engine in `engine/` and reports an agent-environment review on each PR. Read
`RELEASING.md` before touching `engine/` or adding files.

## Rules that are easy to break

- `engine/` is vendored by `vendor-engine.sh` from `deepsweep-team`. Never edit it by
  hand. Detection changes belong in `deepsweep-team`, then get re-vendored.
- No `.gitignore` in this repo. It once hid `engine/` from a release.
- No `pip`, `pipx`, `npm`, `brew`, `curl | sh` installs and no user-facing
  `deepsweep validate|review|scan|verify` command (PLAT-ADR-027).
- Never render the posture score without its band and attestation (ADR-007), e.g.
  `77/100 (good) — identity claimed, not verified`.
- Fail closed. A gate that cannot be evaluated errors; it never passes.
- The review step embeds Python inside a single-quoted `python3 -c '...'`. Use no
  single quotes in it, and no quotes nested inside f-strings: those need Python 3.12,
  and ubuntu-22.04, older macOS and most self-hosted runners have less.
- Never render repository-controlled text (hook commands, server names, file
  contents) as markdown in the PR comment. Render only engine-authored fields.
- Copy style: no emoji; status markers are `[PASS]`, `[FAIL]`, `[WARN]`; write
  "How to address", not "Fix this"; do not call the product a scanner.

## Test

```bash
node --test tests/*.test.mjs
```

The review-step tests execute the step's own bash and Python text, so run them under
Python 3.11 as well as 3.12+ before merging anything that touches `action.yml`.

## Current priorities (2026-10-31)

Measured by running the vendored engine against repos with planted threats. Full
write-up: https://claude.ai/artifact/LBYxELen8D2VuudnxEzNi9 (private to the owner).

1. **Content detection (in `deepsweep-team`).** The engine records that instruction
   files exist but never reads them. It missed a prompt injection and hidden Unicode in
   `.cursorrules`, an exfiltration instruction in `AGENTS.md`/`CLAUDE.md`, injection in
   `.claude/skills/*/SKILL.md`, and a hardcoded API key in an MCP server's `env`. The
   16 patterns in the retired Python CLI (git history, `src/deepsweep/`) are a start.
2. **PR comment.** PR #7 lists each boundary gap with how to address it. Next: a
   copy-paste prompt the user can give their own agent, and stop counting
   `identity.missingOwner` as HIGH on repos that never opted in. Today a benign repo
   shows "Findings: 3".
3. **Change-first comments.** The engine keeps a baseline and ledger. Lead the comment
   with what this PR changed about agent reach (new `Bash(*)` allow, changed MCP tool
   description).
4. **Gate and Security tab.** Add a "fail on critical gaps" option beside
   `fail-below-score`, and bring back SARIF upload.
5. **README accuracy.** The FAQ says the check fails when no agent configuration is
   found. It only fails when `fail-below-score` is set.

Outside this repo: PyPI `deepsweep-ai` 1.0.2 is still installable. It prints a
telemetry banner on stdout in `--format json`, caps users at 3 checks a month, and
unlocks for any non-empty `DEEPSWEEP_API_KEY` because the billing check is a TODO.
