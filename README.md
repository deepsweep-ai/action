# DeepSweep — Agent Environment Review for CI

**Know what your AI coding agents can reach in this repository — and where the gaps are —
on every pull request.**

AI assistants read your repo, run your tools, and touch your secrets. This action reviews
what they are actually able to do, scores it, and comments the result on the PR.

```yaml
- uses: deepsweep-ai/action@v1
```

That's the whole setup. No account, no API key, no install step.

---

## What it checks

Your agents' **capabilities** and **boundary gaps** — what an agent configuration permits
versus what it needs: MCP servers and their tool descriptions, editor agent configs, shell
and deploy reach, git write access, and where credentials sit relative to all of it.

It reviews the *environment your agents run in*, not your application code. Existing SAST
tools do not look at this, because it did not exist as an attack surface until agents did.

## Which editors and agents does it cover?

Every file below is read on the runner and never leaves it. The list is the detector
registry, not a roadmap — if a path is named here, this action reads it today.

| Agent / editor | Configuration it reviews |
|---|---|
| **Cursor** | `.cursorrules`, `.cursor/rules` (one nested level), `.cursor/hooks.json`, `.cursor/mcp.json` |
| **Antigravity** (Gemini) | `.agents/mcp_config.json`, `GEMINI.md`, `~/.gemini/config/mcp_config.json`, and the presence of `~/.gemini/antigravity/mcp_oauth_tokens.json` — flagged by directory listing, never opened |
| **Trae** | `.trae/rules`, `.trae/mcp.json`, `~/.trae/mcp.json`, `~/.trae/user_rules` |
| **Windsurf** (Codeium) | `.windsurfrules`, `.windsurf/rules`, `.windsurf/workflows`, `.windsurf/mcp_config.json`, `~/.codeium/windsurf/mcp_config.json` |
| **Claude Code** | `.claude/settings.json`, `.claude/settings.local.json` — allow/deny lists, hooks-as-capabilities, `additionalDirectories` |
| **GitHub Copilot** | `.github/copilot-instructions.md`, `.github/instructions/**`, `AGENTS.md`, `copilot-setup-steps` workflows, `github.copilot.chat.*` keys in `.vscode/settings.json` |
| **VS Code / VSCodium / Kiro / code-server** | `.vscode/mcp.json`, `.vscode/settings.json` |
| **Any MCP client** | `.mcp.json` and every server's command, args and tool descriptions |
| **Dev containers** | `.devcontainer/devcontainer.json`, `.devcontainer.json` |
| **The repository itself** | `.git` write reach, and `.env` / `.env.local` / `.env.production` — **key names only, never values** |

Editors that read a shared standard are covered by that standard: anything speaking MCP is
covered by the MCP row, and anything using `AGENTS.md` is covered by the Copilot row —
including Zed, Amp and JetBrains AI Assistant when they write those files.

### What a user-scope path means

Four of the rows reach outside the repository, into the home directory — that is where
Windsurf, Antigravity and Trae keep the MCP servers a developer has installed *globally*.
Those servers are reachable from every repository on the machine, including this one, which
is exactly why a repo-only review misses them. They are reported with their scope labelled
`user`, so you can tell a project decision from a machine-wide one.

The Antigravity OAuth token store is the one path deliberately never opened. Its **presence**
is the finding; its contents are none of our business.

---

## Questions people actually ask

**Does this send my code anywhere?**
No. The review runs on your runner using an engine bundled in the action. No source, no
diff, no file contents, no repository name is transmitted. There is nothing to opt out of.

**Do I need an account or an API key?**
No. `- uses: deepsweep-ai/action@v1` is the entire setup.

**Is this a vulnerability scanner?**
No, and it does not overlap with one. SAST reads your application code. This reads the
*environment your agents run in* — what they are permitted to reach. Neither sees what the
other sees.

**What is a posture score?**
A number out of 100 describing protections observed in your agent-writable environment at
review time, always shown with its attestation tier. It is not a verified safety result and
not identity verification, and it is never presented as one.

**What happens if there is no agent configuration to review?**
The check **fails**, rather than passing. A gate that cannot be evaluated is never treated
as a pass.

**Can I run it on a schedule instead of on pull requests?**
Yes — it is an ordinary action. `on: schedule` works, as does `workflow_dispatch`.

**Does it work on self-hosted runners?**
Yes. It needs a filesystem and Node; it makes no outbound calls of its own.

---

## Usage

```yaml
name: Agent Environment Review
on: [pull_request]

permissions:
  contents: read
  pull-requests: write      # only needed for the PR comment

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: deepsweep-ai/action@v1
        with:
          fail-below-score: 70   # optional — fail the check below this posture
```

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | directory to review |
| `fail-below-score` | *(none)* | fail the check when posture is below this number (0–100). Omit to report without blocking. |
| `comment-on-pr` | `true` | post the result as a PR comment (updated in place, never appended) |
| `api-key` | *(none)* | optional, for authenticated features |
| `fail-on-grade` | *(none)* | **deprecated.** DeepSweep scores posture 0–100 and issues no letter grade. Setting it fails the run rather than passing a gate that cannot be evaluated. Use `fail-below-score`. |

### Outputs

| Output | Example |
|---|---|
| `score` | `77` — posture, 0–100. Empty when no agent configuration was found to review. |
| `posture-band` | `good` — one of `weak`, `fair`, `good`, `strong` |
| `attestation` | `claimed` — the identity tier the score was computed under |
| `findings` | `3` |
| `badge-markdown` | a README badge for your repo |
| `grade` | *deprecated, always empty* |

Posture is always reported with its attestation tier, never as a bare number: a score
describes the protections observed in your agent-writable environment at review time. It
is not a safety certification and not identity verification.

### Gate a merge on it

```yaml
      - uses: deepsweep-ai/action@v1
        with:
          fail-below-score: 70
```

Below 70, the check fails. At or above it, the comment still posts.

If no agent configuration is found to review, the check **fails rather than passes** — a
gate that cannot be evaluated is never treated as a pass.

---

## How it runs — and what leaves your runner

**Nothing.** The review executes entirely on the GitHub runner using an engine bundled
inside this action. No source, no diff, no file contents, and no repository name are
transmitted anywhere.

There is no `pip install`, no `npm install -g`, and nothing placed on `PATH`. The action
executes the **same engine binary the DeepSweep Governance Studio desktop app runs**, so a
review means the same thing in CI as it does on a developer's machine.

It **fails closed**: a malformed response, a protocol mismatch, or a missing engine fails the
step. None of them can quietly become a passing review.

## Also available

- **Editor extension** — the same review inside VS Code, Cursor, Windsurf, Trae and
  Antigravity: <https://open-vsx.org/extension/deepsweep-ai/deepsweep>
- **Governance Studio** — the desktop app: <https://deepsweep.ai/download>

## Licence & support

Proprietary. Issues and questions: <https://deepsweep.ai>
