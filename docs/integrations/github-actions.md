# GitHub Actions Integration

Validate AI assistant configurations in your CI/CD pipeline.

## Quick Start

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

## Features

| Feature | Description |
|---------|-------------|
| SARIF Upload | Results appear in GitHub Security tab |
| PR Comments | Findings posted as PR comments |
| Fail Thresholds | Configure when to fail the check |
| Score Output | Access score/grade in subsequent steps |

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
| `grade` | Grade (A-F) |
| `findings-count` | Total findings |
| `critical-count` | Critical findings |

## Permissions

For full functionality, add these permissions:

```yaml
permissions:
  contents: read
  security-events: write  # SARIF upload
  pull-requests: write    # PR comments
```

## Fail Thresholds

Configure when the action should fail:

| Value | Behavior |
|-------|----------|
| `critical` | Only fail on critical findings |
| `high` | Fail on critical or high (default) |
| `medium` | Fail on critical, high, or medium |
| `low` | Fail on any finding |
| `none` | Never fail (report only) |

Example:

```yaml
- uses: deepsweep-ai/action@v1
  with:
    fail-on: 'critical'  # Only fail on critical items
```

## Using Outputs

Access validation results in subsequent steps:

```yaml
- uses: deepsweep-ai/action@v1
  id: deepsweep

- name: Check results
  run: |
    echo "Score: ${{ steps.deepsweep.outputs.score }}"
    echo "Grade: ${{ steps.deepsweep.outputs.grade }}"
    echo "Findings: ${{ steps.deepsweep.outputs.findings-count }}"
    echo "Critical: ${{ steps.deepsweep.outputs.critical-count }}"
```

## Branch Protection

To require DeepSweep validation before merge:

1. Go to Settings > Branches
2. Add branch protection rule for `main`
3. Enable "Require status checks"
4. Search for "DeepSweep Validation"
5. Enable "Require branches to be up to date"

## PR Comments

When `comment-on-pr: 'true'` (default), the action posts a comment on PRs:

```
## DeepSweep Security Validation

[PASS] **Score: 95/100 (Grade: A)**

No issues found. Your AI assistant configurations look good!

---
Validated by DeepSweep - You don't need to understand the code to secure it.
```

Or with findings:

```
## DeepSweep Security Validation

[WARN] **Score: 72/100 (Grade: C)**

### 3 item(s) to review

| Severity | File | Issue |
|----------|------|-------|
| HIGH | `.cursorrules:15` | Instruction override pattern detected |
| MEDIUM | `mcp.json:42` | Broad file system access |
| LOW | `.windsurfrules:8` | Verbose error messages enabled |

---
Validated by DeepSweep - You don't need to understand the code to secure it.
```

## SARIF Integration

When `upload-sarif: 'true'` (default), results appear in the GitHub Security tab:

1. Go to Security > Code scanning alerts
2. Filter by "DeepSweep" tool
3. View findings with file locations and remediation guidance

## Examples

See the `/docs/examples/` directory for complete workflow examples:

- **Basic** - Simple setup for most projects
- **Advanced** - With outputs, conditional steps, and scheduling
- **Monorepo** - Matrix builds for multiple paths
- **Required Check** - Branch protection configuration

## Troubleshooting

### SARIF upload fails

Ensure you have the correct permissions:

```yaml
permissions:
  security-events: write
```

### PR comment not appearing

Check permissions and event type:

```yaml
permissions:
  pull-requests: write

on:
  pull_request:  # Not push
```

### Need specific CLI version

Pin to a specific version:

```yaml
- uses: deepsweep-ai/action@v1
  with:
    version: '1.2.0'
```

## Security

- Your code never leaves the GitHub Actions runner
- SARIF results are uploaded to GitHub's Security tab
- No external services are contacted during validation
