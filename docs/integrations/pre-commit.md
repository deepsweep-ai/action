# Pre-commit Hook

Validate AI assistant configurations before every commit.

## Setup

1. Install pre-commit:

```bash
pip install pre-commit
```

2. Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/deepsweep-ai/deepsweep
    rev: v1.2.0
    hooks:
      - id: deepsweep
```

3. Install the hook:

```bash
pre-commit install
```

## Usage

The hook runs automatically on `git commit`. To run manually:

```bash
pre-commit run deepsweep --all-files
```

## Configuration

### Skip on specific commits

```bash
SKIP=deepsweep git commit -m "WIP"
```

### Fail threshold

Add args to customize:

```yaml
- repo: https://github.com/deepsweep-ai/deepsweep
  rev: v1.2.0
  hooks:
    - id: deepsweep
      args: ['--fail-on', 'critical']
```

### Validate specific paths

```yaml
- repo: https://github.com/deepsweep-ai/deepsweep
  rev: v1.2.0
  hooks:
    - id: deepsweep
      args: ['./config']
```

## Output

```
DeepSweep Security Validation.......................................Passed
```

Or with findings:

```
DeepSweep Security Validation.......................................Failed
- hook id: deepsweep
- exit code: 1

[CRITICAL] config.py:42 - Anyone who sees your code can log into your database
           How to address: Move password to environment variable

1 item(s) to review. Validation failed.
```

## Files Validated

The hook validates these file patterns:

| Pattern | Description |
|---------|-------------|
| `.cursorrules` | Cursor AI rules |
| `*.rules` | Rule files |
| `.windsurfrules` | Windsurf rules |
| `mcp.json` | MCP server configs |
| `copilot-instructions.md` | GitHub Copilot instructions |
| `claude_desktop_config.json` | Claude Code config |

## Troubleshooting

### Hook not running

Ensure pre-commit is installed:

```bash
pre-commit install
```

### Validation too slow

Run only on changed files (default behavior) rather than all files.

### Need to bypass temporarily

```bash
git commit --no-verify -m "Emergency fix"
```

Note: Use sparingly. The hook exists to protect your codebase.
