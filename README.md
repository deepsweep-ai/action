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
