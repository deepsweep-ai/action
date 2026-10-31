// Run with: node --test tests/*.test.mjs
// Runs the "Run the review" step from action.yml under bash, exactly as the
// runner receives it, against a PHP fixture and the vendored engine.
//
// Why: from 6f3ca20 (2026-08-15) the step's embedded Python carried `else ''`
// inside a single-quoted `python3 -c '...'`. Bash closed and reopened the
// quote, Python saw `else }`, nothing was written, and `set -u` failed the
// step on $GRADE, on every run of @v1. The YAML, the engine and the bulletins
// tests were all green; only executing the step's own text could see it.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// The step's `run: |` block, dedented. No YAML dependency: the block is the
// lines after `run: |` that are indented deeper than the `run:` key.
export function stepScript(actionYml, stepName) {
  const lines = actionYml.split("\n");
  const start = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  assert.notEqual(start, -1, `step "${stepName}" not found in action.yml`);
  const runAt = lines.findIndex((l, i) => i > start && /^\s*run: \|\s*$/.test(l));
  assert.notEqual(runAt, -1, `step "${stepName}" has no run: | block`);
  const keyIndent = lines[runAt].search(/\S/);
  const body = [];
  for (const l of lines.slice(runAt + 1)) {
    if (l.trim() !== "" && l.search(/\S/) <= keyIndent) break;
    body.push(l);
  }
  const indent = Math.min(...body.filter((l) => l.trim()).map((l) => l.search(/\S/)));
  return body.map((l) => l.slice(indent)).join("\n");
}

const DEFAULTS = { path: ".", "fail-below-score": "", "fail-on-grade": "" };

function runReviewStep(actionYml) {
  const script = stepScript(actionYml, "Run the review").replace(
    /\$\{\{\s*inputs\.([\w-]+)\s*\}\}/g,
    (_, k) => DEFAULTS[k] ?? "",
  );
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "ds-review-step-"));
  const repo = path.join(work, "repo");
  fs.mkdirSync(path.join(repo, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(repo, "composer.json"), '{"require":{"php":">=8.2"}}');
  fs.writeFileSync(path.join(repo, ".claude", "settings.json"), '{"permissions":{"allow":["Bash(*)"]}}');
  fs.writeFileSync(
    path.join(repo, ".mcp.json"),
    '{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}',
  );
  const out = path.join(work, "output");
  const summary = path.join(work, "summary");
  fs.writeFileSync(out, "");
  fs.writeFileSync(summary, "");
  const r = spawnSync("bash", ["-eu", "-c", script], {
    cwd: repo,
    encoding: "utf8",
    env: {
      ...process.env,
      engine: path.join(ROOT, "engine", "engine-host.js"),
      GITHUB_OUTPUT: out,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_REPOSITORY: "local/fixture",
    },
  });
  const outputs = Object.fromEntries(
    fs.readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i), l.slice(i + 1)];
    }),
  );
  return { status: r.status, stderr: r.stderr, outputs, summary: fs.readFileSync(summary, "utf8") };
}

test("the review step runs under bash and writes its outputs", () => {
  const yml = fs.readFileSync(path.join(ROOT, "action.yml"), "utf8");
  const r = runReviewStep(yml);
  assert.equal(r.status, 0, `review step exited ${r.status}:\n${r.stderr}`);
  assert.ok("grade" in r.outputs, "grade output (GRADE) was never written");
  assert.match(r.outputs.score, /^\d+$/, "score is a whole number");
  assert.match(r.outputs["posture-band"], /^(weak|fair|good|strong)$/);
  assert.equal(r.outputs.attestation, "claimed");
  assert.match(r.outputs.findings, /^\d+$/);
  assert.match(r.summary, /DeepSweep Agent Environment Review/);
});

test("the summary names each boundary gap and how to address it", () => {
  const r = runReviewStep(fs.readFileSync(path.join(ROOT, "action.yml"), "utf8"));
  assert.equal(r.status, 0, `review step exited ${r.status}:\n${r.stderr}`);
  assert.match(r.summary, /### Boundary gaps/);
  assert.match(r.summary, /\| Severity \| Gap \| How to address \|/);
  assert.match(r.summary, /\| CRITICAL \| Broad pre-approved permission patterns/);
  const gaps = fs.readFileSync("/tmp/deepsweep-gaps.md", "utf8");
  assert.doesNotMatch(gaps, /server-filesystem|Bash\(\*\)/, "repository content must not be rendered");
});

test("the step's embedded python parses on Python 3.8+ (no quotes nested in f-strings)", () => {
  const script = stepScript(fs.readFileSync(path.join(ROOT, "action.yml"), "utf8"), "Run the review");
  const nested = script.split("\n").filter((l) => /f"[^"]*\{[^}]*"/.test(l));
  assert.deepEqual(nested, [], "nested quotes inside an f-string need Python 3.12");
});

test("the step's embedded python never uses '' inside the single-quoted program", () => {
  const script = stepScript(fs.readFileSync(path.join(ROOT, "action.yml"), "utf8"), "Run the review");
  assert.doesNotMatch(script, /else ''/);
});
