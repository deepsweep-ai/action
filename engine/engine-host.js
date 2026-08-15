#!/usr/bin/env node
/**
 * DeepSweep headless engine host — INTERNAL COMPONENT, NOT A USER INTERFACE.
 *
 * Two consumers, both of which BUNDLE this artifact rather than install it:
 *   (a) the Governance Studio desktop app, which spawns it as a sidecar;
 *   (b) the CI runner, which executes the same file.
 * It is never placed on PATH, never symlinked, and never documented as a
 * command a person types.
 *
 * Process contract: ONE JSON request on stdin, ONE canonical JSON response on
 * stdout, diagnostics on stderr, the capability's own exit code. No prompts,
 * no TTY detection, no colors, no spinners, no banner, no upsell, no
 * auto-updater, no telemetry of its own — the host passes a correlation id
 * and owns all analytics.
 *
 * Coverage note (vitest.config.ts): like src/cli.ts this file is a process
 * wrapper — argv/stdin/stdout/exit plumbing only. Every behavioural decision
 * lives in src/api/host.ts, which is unit-tested exhaustively; the wrapper
 * itself is covered at the process boundary by tests/engine-host.test.ts.
 */
import { handleHostRequest, HOST_HELP_LINE, MAX_REQUEST_BYTES, oversizeRequestOutcome, } from "./api/host.js";
import { renderCanonicalJson, renderErrorLine, renderNoticeLine } from "./review/report.js";
if (process.argv.includes("--help") || process.argv.includes("-h")) {
    // ONE line. The headless host has no marketing surface by construction.
    console.log(renderNoticeLine(HOST_HELP_LINE));
    process.exit(0);
}
const chunks = [];
let received = 0;
let overflowed = false;
let emitted = false;
const emit = (outcome) => {
    if (emitted)
        return;
    emitted = true;
    for (const line of outcome.diagnostics)
        console.error(renderErrorLine(line));
    console.log(renderCanonicalJson(outcome.body));
    // exitCode, never process.exit(): a forced exit races the async flush of a
    // piped stdout and would truncate a large canonical body mid-byte.
    process.exitCode = outcome.exitCode;
};
process.stdin.on("data", (c) => {
    received += c.length;
    if (received > MAX_REQUEST_BYTES) {
        // Fail closed at the edge too: stop buffering a runaway writer.
        overflowed = true;
        process.stdin.destroy();
        emit(oversizeRequestOutcome());
        return;
    }
    chunks.push(c);
});
process.stdin.on("end", () => {
    if (!overflowed)
        emit(handleHostRequest(Buffer.concat(chunks).toString("utf8")));
});
process.stdin.on("error", () => {
    console.error(renderErrorLine("stdin could not be read"));
    process.exitCode = 1;
});
