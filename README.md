# DeepSweep Security Action

**Validate AI coding assistant configurations in your CI/CD pipeline.**

You don't need to understand the code to secure it.

## Features

- Validates Cursor, Copilot, Claude Code, Windsurf, MCP configs
- Uploads results to GitHub Security tab (SARIF)
- Comments on PRs with findings
- Configurable fail thresholds
- Plain English remediation guidance

## Usage

### Basic

```yaml
name: Security

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: deepsweep-ai/action@v1
```

### With Options

```yaml
- uses: deepsweep-ai/action@v1
  with:
    path: './src'
    fail-on: 'critical'      # Only fail on critical
    upload-sarif: 'true'     # Upload to Security tab
    comment-on-pr: 'true'    # Comment on PRs
```

### Fail Thresholds

| Value | Behavior |
|-------|----------|
| `critical` | Only fail on critical findings |
| `high` | Fail on critical or high (default) |
| `medium` | Fail on critical, high, or medium |
| `low` | Fail on any finding |
| `none` | Never fail (report only) |

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to validate |
| `fail-on` | `high` | Minimum severity to fail |
| `upload-sarif` | `true` | Upload to Security tab |
| `comment-on-pr` | `true` | Post PR comment |
| `version` | `latest` | CLI version |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `grade` | Security grade (A-F) |
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `sarif-file` | Path to SARIF file |

## Example Workflow with Outputs

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: deepsweep-ai/action@v1
        id: deepsweep

      - name: Check score
        run: |
          echo "Score: ${{ steps.deepsweep.outputs.score }}"
          echo "Grade: ${{ steps.deepsweep.outputs.grade }}"

          if [ "${{ steps.deepsweep.outputs.score }}" -lt 70 ]; then
            echo "Score below 70, consider reviewing"
          fi
```

## What Gets Validated

| File | Description |
|------|-------------|
| `.cursorrules` | Cursor AI rules |
| `.cursor/rules/*` | Cursor project rules |
| `copilot-instructions.md` | GitHub Copilot |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `claude_desktop_config.json` | Claude Code |
| `.windsurfrules` | Windsurf |
| `mcp.json` | MCP server configs |

## Permissions

For full functionality, add these permissions:

```yaml
permissions:
  contents: read
  security-events: write  # SARIF upload
  pull-requests: write    # PR comments
```

## Branch Protection

To require DeepSweep validation before merge:

1. Go to Settings > Branches
2. Add branch protection rule for `main`
3. Enable "Require status checks"
4. Search for "DeepSweep Validation"
5. Enable "Require branches to be up to date"

## Security

Results are uploaded to GitHub's Security tab using SARIF format.
Your code never leaves your GitHub Actions runner.

## Links

- [DeepSweep Documentation](https://docs.deepsweep.ai)
- [CLI Installation](https://pypi.org/project/deepsweep-ai/)
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=deepsweep.deepsweep)

---

Ship with vibes. Ship secure.
