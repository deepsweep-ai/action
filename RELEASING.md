# Releasing this action

Internal. Not user-facing.

## The engine MUST be committed. It is not built, fetched, or installed.

GitHub Actions resolves `uses: deepsweep-ai/action@v1` by checking this repository
out at that ref and running `action.yml` **as-is**. There is no build step, no
dependency install, and no network fetch of our engine.

So `engine/` has to be **in the tag**. If it is not, every consumer hits:

```
::error::Bundled engine missing at engine/engine-host.js.
```

on every run — a listing that is dead on arrival.

**This was nearly shipped.** The copy of this action inside `deepsweep-platform`
carries `.gitignore` containing `engine/`, which is correct *there* (the engine is
vendored at CI time and must not pollute the platform repo). Carried across to this
repo it would have gitignored the one file the action cannot run without. There is
deliberately **no `.gitignore` here**.

## Refreshing the engine before a release

```bash
# 1. Build the engine in deepsweep-team, then vendor its dist/ in:
./vendor-engine.sh ../studio-desktop/sidecar     # or deepsweep-team/dist

# 2. Confirm it actually runs from the vendored location — never assume:
printf '%s' '{"protocolVersion":1,"command":"review","correlationId":"c1",
  "nowIso":"2026-01-01T00:00:00Z","params":{"workspaceRoot":"/some/repo"}}' \
  | node engine/engine-host.js | head -c 200

# 3. Commit engine/ — yes, all of it.
git add engine && git commit -m "chore(engine): refresh vendored engine"
```

`vendor-engine.sh` already refuses to succeed unless `engine-host.js` exists, parses
under `node --check`, and answers `--help`. A missing or broken engine fails the
vendoring, never the review.

The Studio vendors the identical artifact into `studio-desktop/sidecar/`, so a review
means the same thing in CI as it does on a desktop. Keep them on the same build.

## What must never come back

`PLAT-ADR-027` bans `pip`/`pipx`/`npm`/`brew`/`curl | sh` and any user-facing
`deepsweep validate|review|scan|verify` command on a shipped surface. Until
2026-08-15 this repo carried all of them: a `pip install deepsweep-ai` action, a
`.pre-commit-hooks.yaml` whose entry was `deepsweep validate`, and a Python package
under `src/deepsweep/`. All removed. They remain in git history if the SARIF reporter
under `src/deepsweep/reporters/` is ever wanted as a reference.

The engine bundled here is plumbing: never on `PATH`, never symlinked, never a
command a human is told to type. That is what keeps it on the right side of the line.
