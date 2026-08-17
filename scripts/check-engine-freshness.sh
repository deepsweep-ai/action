#!/usr/bin/env bash
#
# Is the committed engine still current with the engine source?
#
# GitHub resolves `uses: deepsweep-ai/action@v1` by checking this repo out at
# that ref and running it as-is. There is no build step, so `engine/` IS the
# product. It can silently fall behind its source and nothing in a CI run will
# say so — the action still works, still reports, and simply cannot see what
# the newer engine can.
#
# That is not hypothetical. Measured 2026-08-17: the engine was vendored on
# 08-15, the Antigravity and Trae detectors landed 08-16, and for two days —
# across a Marketplace launch — every CI user ran a review that could not open
# `.agents/mcp_config.json` or `.trae/mcp.json` at all. A review that completes,
# reports nothing, and reads as safe.
#
# Usage:
#   scripts/check-engine-freshness.sh                 # compare against GitHub
#   scripts/check-engine-freshness.sh ../deepsweep-team   # against a local clone
#
# Exit: 0 current  ·  1 stale (or unstamped)  ·  2 could not check

set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$DIR/engine/PROVENANCE.json"
SOURCE_REPO="${1:-}"

if [ ! -f "$STAMP" ]; then
  echo "FAIL: engine/PROVENANCE.json is missing."
  echo "      An unstamped engine cannot be checked, which is the state that let"
  echo "      it drift two days behind unnoticed. Re-run vendor-engine.sh."
  exit 1
fi

vendored_sha="$(python3 -c "import json,sys; print(json.load(open('$STAMP')).get('sourceCommit',''))" 2>/dev/null || echo '')"

if [ -z "$vendored_sha" ] || [ "$vendored_sha" = "unknown" ]; then
  echo "FAIL: the stamp records no source commit (got '${vendored_sha:-empty}')."
  echo "      Vendor from a git checkout so the provenance is real."
  exit 1
fi

if [ -n "$SOURCE_REPO" ]; then
  if [ ! -d "$SOURCE_REPO/.git" ]; then
    echo "FAIL: $SOURCE_REPO is not a git repository."
    exit 2
  fi
  head_sha="$(cd "$SOURCE_REPO" && git rev-parse HEAD 2>/dev/null || true)"
else
  command -v gh >/dev/null 2>&1 || { echo "FAIL: gh not found and no local path given."; exit 2; }
  head_sha="$(gh api repos/deepsweep-ai/deepsweep-team/commits/main -q '.sha' 2>/dev/null || true)"
fi

if [ -z "$head_sha" ]; then
  echo "FAIL: could not read the engine source HEAD (network, auth, or path)."
  echo "      Not treating that as 'current' — an unanswered question is not a pass."
  exit 2
fi

echo "  vendored from: ${vendored_sha:0:12}"
echo "  source HEAD:   ${head_sha:0:12}"

if [ "$vendored_sha" = "$head_sha" ]; then
  echo "OK: the committed engine matches the engine source."
  exit 0
fi

echo
echo "STALE: the committed engine is not built from the current engine source."
echo "       Every consumer of @v1 is running the older one. Re-vendor:"
echo
echo "         (cd <engine-source> && npm run build)"
echo "         ./vendor-engine.sh <engine-source>/dist"
echo "         git commit -am 'chore(engine): re-vendor' && move the v1 tag"
echo
echo "       Moving the tag matters: a fix on main does not fix a tag-resolved action."
exit 1
