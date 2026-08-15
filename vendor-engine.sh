#!/usr/bin/env bash
# Vendor the headless engine into the action — the release-time half of PLAT-ADR-027.
#
# The action EXECUTES the engine; it never installs it. That is the sanctioned
# path, stated in engine-host.js itself: "Two consumers, both of which BUNDLE
# this artifact rather than install it: (a) the Governance Studio desktop app
# ... (b) the CI runner, which executes the same file."
#
# studio-desktop already does this for its Tauri sidecar. This is the same
# mechanism for the CI consumer, so both run byte-identical code and a review
# means the same thing in CI as on a desktop.
#
# FAILS LOUDLY, ALWAYS. A missing or partial engine must never ship: the action
# would then either error on every run, or — far worse — appear to work while
# reviewing nothing.
set -euo pipefail

SOURCE="${1:-}"
DEST="$(cd "$(dirname "$0")" && pwd)/engine"

if [ -z "$SOURCE" ]; then
  echo "usage: vendor-engine.sh <path-to-engine-build>" >&2
  echo "  e.g. vendor-engine.sh ../../studio-desktop/sidecar" >&2
  exit 2
fi

if [ ! -f "$SOURCE/engine-host.js" ]; then
  echo "[FAIL] $SOURCE/engine-host.js not found — that is not an engine build." >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SOURCE"/. "$DEST"/

# Verify what we produced, not what we intended to produce.
if [ ! -f "$DEST/engine-host.js" ]; then
  echo "[FAIL] vendoring produced no engine-host.js at $DEST" >&2
  exit 1
fi

if ! node --check "$DEST/engine-host.js" 2>/dev/null; then
  echo "[FAIL] vendored engine-host.js is not parseable by node" >&2
  exit 1
fi

# The protocol handshake is the real contract. If --help does not answer, the
# bundle is incomplete (a missing transitive import fails here, not in a user's CI).
if ! node "$DEST/engine-host.js" --help >/dev/null 2>&1; then
  echo "[FAIL] vendored engine did not respond to --help — bundle is incomplete" >&2
  exit 1
fi

FILES=$(find "$DEST" -type f | wc -l | tr -d ' ')
echo "[PASS] engine vendored into action/engine ($FILES files)"
echo "       source: $SOURCE"
