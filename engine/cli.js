#!/usr/bin/env node
/**
 * LEGACY COMPATIBILITY SHIM — the DeepSweep CLI is retired as a product
 * surface (TEAM-ADR-027). The Governance Studio is the supported interface;
 * the headless engine host (src/engine-host.ts) is the machine one.
 *
 * This file exists for exactly one reason: an early user who already pinned
 * an install must never have it break. Every verb keeps its behaviour and its
 * exit-code contract byte-for-byte (ADR-006/008/012/021 are frozen contracts,
 * and a CI gate that started exiting 0 on a poisoned environment would be a
 * fail-open regression far worse than the deprecation it announced). What the
 * shim adds is ONE stderr line pointing at the download page — then it does
 * the requested work, unchanged.
 *
 * It holds NO logic of its own: every verb delegates to the engine library in
 * src/api/, the same functions the Studio calls over IPC. What remains here is
 * argument plumbing, the ONE sanctioned ambient-clock read, the ONE sanctioned
 * user-profile lookup, and the rendering of human output.
 *
 * Usage: deepsweep review [path] [--json] [--watch] [--update-baseline]
 *                        [--fail-on critical|high|none] [--fail-on-drift]
 *                        [--require-baseline] [--format md|html]
 *        deepsweep studio [path] [--out <file>] [--open] [--serve]
 *        deepsweep export [path] [--since-size <n>] [--sign-with <key>]
 *        deepsweep verify <bundle.json> [--keys <policy-keys.json>]
 *        deepsweep authorize --principal <id|none> --action <verb>
 *                        --resource <target> [path]
 */
import { resolve } from "node:path";
import { renderAuthorizationSection, renderAuthorizeDecision, renderBaselineSection, renderDecisionSection, renderErrorLine, renderIdentitySection, renderJsonReport, renderJsonValue, renderNoticeLine, renderReport, renderTrustSection, } from "./review/report.js";
import { renderArtifact, toolVersion } from "./review/artifact.js";
import { BaselineRefusalError } from "./review/baseline.js";
import { IdentityRefusalError, readClaimedOwner } from "./review/identity.js";
import { LedgerRefusalError } from "./review/ledger.js";
import { PolicyRefusalError, ACTION_VOCABULARY } from "./review/policy.js";
import { homedir } from "node:os";
import { authorizeAction, EvidenceMaterialError, exportEvidenceBundle, generateStudioArtifact, parseTrustedKeys, reviewWorkspace, startWatch, verifyEvidence, writeStudioArtifact, } from "./api/index.js";
import { startStudioServer } from "./review/studio-server.js";
import { readFileSync as readFileSyncNode, writeFileSync } from "node:fs";
import { execFile } from "node:child_process";
const argv = process.argv.slice(2);
const cmd = argv[0];
// ADR-014/ADR-005: the ONE sanctioned user-profile lookup in the codebase —
// composition root only; the engine cannot locate the profile itself.
const USER_CONFIG_ROOT = homedir();
// The ONE sanctioned ambient-clock read on this surface. Everything downstream
// receives it as an injected `nowIso` (determinism invariant).
const NOW_ISO = new Date().toISOString();
/**
 * TEAM-ADR-027 — the single deprecation line. Emitted once, on stderr (so it
 * can never corrupt a piped --json/--format/export payload on stdout), BEFORE
 * the work. It never changes an exit code and never turns a verb into a
 * no-op: a pinned install keeps working exactly as it did.
 */
console.error(renderNoticeLine("the command line is no longer a supported DeepSweep interface — this build still works; the Governance Studio is at https://deepsweep.ai/download"));
if (cmd === "authorize") {
    // ADR-021 exit vocabulary: 0 allow (or observe MODE) · 1 usage ·
    // 3 require-approval (incl. the ADR-010 safe default) · 4 deny.
    const flags = new Map();
    const positional = [];
    const rest = argv.slice(1);
    for (let i = 0; i < rest.length; i++) {
        const a = rest[i] ?? "";
        if (a === "--principal" || a === "--action" || a === "--resource") {
            const value = rest[++i];
            if (value === undefined || value.startsWith("--")) {
                console.error(renderErrorLine(`${a} requires a value`));
                process.exit(1);
            }
            flags.set(a, value);
        }
        else if (!a.startsWith("--")) {
            positional.push(a);
        }
        else {
            console.error(renderErrorLine(`unknown authorize flag ${a} — usage: deepsweep authorize --principal <id|none> --action <verb> --resource <pattern-target> [path]`));
            process.exit(1);
        }
    }
    const actionArg = flags.get("--action");
    const resourceArg = flags.get("--resource");
    // CLI sentinel parsing ("none" -> unattributed) on a neutral identifier:
    // argument plumbing at the composition root, not an authority branch. The
    // library takes `string | null` and never knows the sentinel exists.
    const whoArg = flags.get("--principal");
    if (actionArg === undefined || resourceArg === undefined || whoArg === undefined) {
        console.error(renderErrorLine("authorize requires --principal, --action, and --resource"));
        process.exit(1);
    }
    if (!ACTION_VOCABULARY.includes(actionArg)) {
        console.error(renderErrorLine(`--action must be one of: ${ACTION_VOCABULARY.join(" | ")}`));
        process.exit(1);
    }
    const decided = authorizeAction({
        workspaceRoot: resolve(positional[0] ?? "."),
        principal: whoArg === "none" ? null : whoArg,
        action: actionArg,
        resource: resourceArg,
        userConfigRoot: USER_CONFIG_ROOT,
        nowIso: NOW_ISO,
    });
    for (const r of decided.refusals) {
        // One clear line per refused layer; the layer contributed zero rules.
        console.error(renderErrorLine(`policy layer "${r.layer}" refused (${r.source}): ${r.reason}`));
    }
    console.log(renderAuthorizeDecision({
        who: decided.principal,
        action: decided.action,
        resource: decided.resource,
        explanation: decided.explanation,
        layers: decided.layersLoaded,
        mode: decided.mode,
        ruleLabel: decided.ruleLabel,
        outcome: decided.outcome,
        actedOn: decided.actedOn,
    }));
    if (!decided.ledgerAppended) {
        console.error(renderErrorLine("audit ledger is malformed — decision NOT recorded; verify against your latest anchor"));
    }
    process.exit(decided.exitCode);
}
if (cmd === "verify") {
    // ADR-DS-006 — the auditor's offline check. Exit 0 verified · 1 usage ·
    // 4 refused (an unsigned bundle is UNATTRIBUTED, not verified).
    const vArgs = argv.slice(1);
    const vPos = [];
    let keysPath;
    for (let i = 0; i < vArgs.length; i++) {
        const a = vArgs[i] ?? "";
        if (a === "--keys" || a.startsWith("--keys=")) {
            const v = a === "--keys" ? vArgs[++i] : a.slice("--keys=".length);
            if (v === undefined || v.startsWith("--")) {
                console.error(renderErrorLine("--keys requires a path to a policy-keys.json trust file"));
                process.exit(1);
            }
            keysPath = v;
        }
        else if (!a.startsWith("--")) {
            vPos.push(a);
        }
        else {
            console.error(renderErrorLine(`unknown verify flag ${a} — usage: deepsweep verify <bundle.json> [--keys <policy-keys.json>]`));
            process.exit(1);
        }
    }
    const bundlePath = vPos[0];
    if (bundlePath === undefined) {
        console.error(renderErrorLine("verify requires a bundle path — usage: deepsweep verify <bundle.json> [--keys <policy-keys.json>]"));
        process.exit(1);
    }
    let parsedBundle;
    try {
        parsedBundle = JSON.parse(readFileSyncNode(resolve(bundlePath), "utf8"));
    }
    catch {
        console.error(renderErrorLine("bundle could not be read as JSON"));
        process.exit(1);
    }
    let trusted = [];
    if (keysPath !== undefined) {
        try {
            trusted = parseTrustedKeys(JSON.parse(readFileSyncNode(resolve(keysPath), "utf8")));
        }
        catch {
            console.error(renderErrorLine("--keys file could not be read as a trust config"));
            process.exit(1);
        }
    }
    const verified = verifyEvidence({ bundle: parsedBundle, trustedKeys: trusted });
    console.log(renderJsonValue(verified.result));
    process.exit(verified.exitCode);
}
if (cmd === "export") {
    // ADR-DS-005: evidence records + RFC 6962 proofs. Read-only; JSON on
    // stdout. Exit 0 ok · 1 usage · 3 unverifiable (fail-closed).
    const eArgs = argv.slice(1);
    const ePos = [];
    let sinceSize;
    let signWith;
    for (let i = 0; i < eArgs.length; i++) {
        const a = eArgs[i] ?? "";
        if (a === "--since-size" || a.startsWith("--since-size=")) {
            const raw = a === "--since-size" ? eArgs[++i] : a.slice("--since-size=".length);
            const parsed = Number(raw);
            if (raw === undefined || !Number.isInteger(parsed) || parsed < 1) {
                console.error(renderErrorLine("--since-size requires a positive integer (a previously published tree size)"));
                process.exit(1);
            }
            sinceSize = parsed;
        }
        else if (a === "--sign-with" || a.startsWith("--sign-with=")) {
            const v = a === "--sign-with" ? eArgs[++i] : a.slice("--sign-with=".length);
            if (v === undefined || v.startsWith("--")) {
                console.error(renderErrorLine("--sign-with requires a path to an Ed25519 private key"));
                process.exit(1);
            }
            signWith = v;
        }
        else if (!a.startsWith("--")) {
            ePos.push(a);
        }
        else {
            console.error(renderErrorLine(`unknown export flag ${a} — usage: deepsweep export [path] [--since-size <n>] [--sign-with <key>]`));
            process.exit(1);
        }
    }
    // Operator credential, deliberately OUTSIDE workspace containment: a
    // signing key must never live in the reviewed tree. Read once at the
    // composition root, never logged, never echoed (ADR-DS-006) — the library
    // takes PEM TEXT, so it holds no file-read oracle.
    let signPem;
    if (signWith !== undefined) {
        try {
            signPem = readFileSyncNode(resolve(signWith), "utf8");
        }
        catch {
            console.error(renderErrorLine("--sign-with could not read an Ed25519 private key at that path"));
            process.exit(1);
        }
    }
    let exported;
    try {
        exported = exportEvidenceBundle({
            workspaceRoot: resolve(ePos[0] ?? "."),
            nowIso: NOW_ISO,
            ...(sinceSize !== undefined ? { sinceSize } : {}),
            ...(signPem !== undefined ? { signWithPem: signPem } : {}),
        });
    }
    catch (e) {
        if (e instanceof EvidenceMaterialError) {
            console.error(renderErrorLine("--sign-with could not read an Ed25519 private key at that path"));
            process.exit(1);
        }
        throw e;
    }
    if (exported.bundle.status === "unverifiable") {
        console.error(renderErrorLine(`evidence export refused: ${exported.bundle.reason}`));
        process.exit(exported.exitCode);
    }
    console.log(renderJsonValue(exported.bundle));
    process.exit(0);
}
if (cmd === "studio") {
    // ADR-022 artifact / ADR-023 live mode.
    const sArgs = argv.slice(1);
    const sPos = [];
    let outPath;
    let openAfter = false;
    let serveMode = false;
    for (let i = 0; i < sArgs.length; i++) {
        const a = sArgs[i] ?? "";
        if (a === "--out") {
            const v = sArgs[++i];
            if (v === undefined || v.startsWith("--")) {
                console.error(renderErrorLine("--out requires a file path"));
                process.exit(1);
            }
            outPath = v;
        }
        else if (a === "--open") {
            openAfter = true;
        }
        else if (a === "--serve") {
            serveMode = true;
        }
        else if (!a.startsWith("--")) {
            sPos.push(a);
        }
        else {
            console.error(renderErrorLine(`unknown studio flag ${a} — usage: deepsweep studio [path] [--out <file>] [--open]`));
            process.exit(1);
        }
    }
    const sRoot = resolve(sPos[0] ?? ".");
    if (serveMode) {
        // ADR-023 live mode: local-only, token-guarded; runs until Ctrl-C.
        const studioServer = await startStudioServer({
            initialRoot: sRoot,
            toolVersion: toolVersion(),
            userConfigRoot: USER_CONFIG_ROOT,
        });
        console.log(renderNoticeLine(`Governance Studio live at ${studioServer.url} (local-only, this session's token in the URL) — Ctrl-C to stop`));
        if (openAfter) {
            const opener = process.platform === "darwin" ? "open" : "xdg-open";
            execFile(opener, [studioServer.url], () => {
                /* fire-and-forget */
            });
        }
        process.on("SIGINT", () => {
            void studioServer.close().then(() => process.exit(0));
        });
        await new Promise(() => {
            /* serve until signaled */
        });
    }
    const artifact = generateStudioArtifact({
        workspaceRoot: sRoot,
        toolVersion: toolVersion(),
        userConfigRoot: USER_CONFIG_ROOT,
        nowIso: NOW_ISO,
    });
    // `--out` writes wherever the OPERATOR typed. That arbitrary-path write
    // exists only here, at a composition root a human drove; it is deliberately
    // NOT a library capability and NOT reachable over IPC (TEAM-ADR-027).
    let written;
    if (outPath === undefined) {
        written = writeStudioArtifact(sRoot, artifact.html);
    }
    else {
        written = resolve(outPath);
        writeFileSync(written, artifact.html);
    }
    console.log(renderNoticeLine(`Governance Studio written: ${written} — open it in any browser; it works offline`));
    if (openAfter) {
        const opener = process.platform === "darwin" ? "open" : "xdg-open";
        execFile(opener, [written], () => {
            /* fire-and-forget at the composition root; the artifact is on disk either way */
        });
    }
    process.exit(0);
}
if (cmd !== "review") {
    // Operator reference only — no banner art, no taglines, no upsell, no
    // pricing, no install instructions (TEAM-ADR-027 forbids reintroducing any
    // of them here). Static text only, no interpolation (S1.9 guard).
    console.log(`Retired interface. The Governance Studio is the supported DeepSweep interface: https://deepsweep.ai/download

Usage: deepsweep review [path] [--json] [--watch] [--update-baseline]
                       [--fail-on critical|high|none] [--fail-on-drift]
                       [--require-baseline] [--format md|html]
       deepsweep studio [path] [--out <file>] [--open] [--serve]
       deepsweep export [path] [--since-size <n>] [--sign-with <key>]
       deepsweep verify <bundle.json> [--keys <policy-keys.json>]
       deepsweep authorize --principal <id|none> --action <verb>
                       --resource <target> [path]

Exit codes (exit 0 is the ONLY pass — treat every non-zero exit as a failed
pipeline, and branch on specific codes only to pick a playbook):
  0  passed: no gated finding under the active flags
  1  usage error: unknown command or invalid flag combination
  2  boundary gaps at or above the --fail-on threshold (default: critical;
     applies to every one-shot output format — use --fail-on high to also
     gate high-severity gaps, or --fail-on none to disable gap gating)
  3  baseline containment refusal
  4  drift gated by --fail-on-drift: a pinned entity changed or conflicts —
     review the change, then re-pin via --update-baseline
  5  trust-anchor divergence: the baseline was regenerated from an invalid
     file, or is absent under --require-baseline — investigate before
     trusting this environment; do NOT re-pin
Precondition for drift gating: a persistent baseline — commit
.deepsweep/baseline.json (or restore it between runs) and keep the checkout
folder name stable. The gating flags apply to one-shot runs only; combined
with --watch they refuse loudly (exit 1) instead of gating nothing silently.`);
    process.exit(cmd === undefined || cmd === "--help" ? 0 : 1);
}
const json = argv.includes("--json");
const watchMode = argv.includes("--watch");
const updateBaseline = argv.includes("--update-baseline");
const failOnDrift = argv.includes("--fail-on-drift");
const requireBaseline = argv.includes("--require-baseline");
// --format takes a value (md | html); it is parsed out here so its value is
// never mistaken for the [path] positional. An invalid or missing value
// refuses loudly (exit 1) — a silently ignored flag is the same failure mode
// as a silently ignored gate (ADR-006 flag discipline).
let format;
let formatError;
// --fail-on (ADR-012): severity threshold for exit 2, format-independent.
let failOn = "critical";
let failOnExplicit = false;
let failOnError;
const positionals = [];
const rest = argv.slice(1);
for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";
    if (a === "--format" || a.startsWith("--format=")) {
        const value = a === "--format" ? rest[++i] : a.slice("--format=".length);
        if (value === "md" || value === "html") {
            format = value;
        }
        else {
            formatError = "--format requires a value of md or html (e.g. --format md)";
        }
    }
    else if (a === "--fail-on" || a.startsWith("--fail-on=")) {
        const value = a === "--fail-on" ? rest[++i] : a.slice("--fail-on=".length);
        if (value === "critical" || value === "high" || value === "none") {
            failOn = value;
            failOnExplicit = true;
        }
        else {
            failOnError = "--fail-on requires a value of critical, high, or none (e.g. --fail-on high)";
        }
    }
    else if (!a.startsWith("--")) {
        positionals.push(a);
    }
}
const root = resolve(positionals[0] ?? ".");
if (formatError !== undefined) {
    console.error(renderErrorLine(formatError));
    process.exit(1);
}
if (failOnError !== undefined) {
    console.error(renderErrorLine(failOnError));
    process.exit(1);
}
// Gap gating is one-shot only (ADR-004: watch exit codes are process
// lifecycle). An explicit threshold combined with --watch refuses loudly.
if (failOnExplicit && watchMode) {
    console.error(renderErrorLine("--fail-on gates one-shot runs only and cannot be combined with --watch — remove --watch to gate this review"));
    process.exit(1);
}
// The artifact is a one-shot output surface: --watch exit codes reflect the
// process lifecycle and its streams are already spoken for (ADR-004), and
// --json is a competing output format — both refuse loudly instead of
// silently preferring one surface.
if (format !== undefined && watchMode) {
    console.error(renderErrorLine("--format renders one-shot artifacts only and cannot be combined with --watch — remove --watch to emit an artifact"));
    process.exit(1);
}
if (format !== undefined && json) {
    console.error(renderErrorLine("--format and --json are mutually exclusive output formats — choose one"));
    process.exit(1);
}
// ADR-006: watch exit codes reflect process lifecycle, not findings — a CI
// gate that would be silently ignored must refuse loudly instead.
if (watchMode && (failOnDrift || requireBaseline)) {
    console.error(renderErrorLine("--fail-on-drift and --require-baseline gate one-shot runs only and cannot be combined with --watch — remove --watch to gate this review"));
    process.exit(1);
}
// --require-baseline is a companion assertion; standalone it would gate
// nothing, so it fails loudly rather than pretending to protect the run.
if (requireBaseline && !failOnDrift) {
    console.error(renderErrorLine("--require-baseline is a companion flag — add --fail-on-drift to gate this review"));
    process.exit(1);
}
try {
    if (watchMode) {
        // Foreground-only (ADR-004): the session keeps the process alive via its
        // fs watchers; SIGINT/SIGTERM close all watchers and exit 0.
        await startWatch({ workspaceRoot: root, json, updateBaseline });
    }
    else {
        const result = reviewWorkspace({
            workspaceRoot: root,
            updateBaseline,
            userConfigRoot: USER_CONFIG_ROOT,
            failOn,
            failOnDrift,
            requireBaseline,
            nowIso: NOW_ISO,
        });
        if (json) {
            // QA defect D3: the dump is a rendered surface — it must be produced
            // by the sanctioned renderJsonReport funnel, never a raw JSON.stringify.
            // The transient claimed owner (ADR-005 F1) is deliberately NOT read
            // here — it exists on local human display surfaces only.
            console.log(renderJsonReport(result.report, result.provenance, [...result.events], result.identity, result.trust, result.authorization, result.decisions));
        }
        else if (format !== undefined) {
            // S1.6 shareable artifact — produced ONLY by the sanctioned renderer.
            console.log(renderArtifact({
                report: result.report,
                provenance: result.provenance,
                findings: [...result.findings],
                repinned: result.repinned,
                generatedAt: NOW_ISO,
                toolVersion: toolVersion(),
                identity: result.identity,
                trust: result.trust,
                authorization: result.authorization,
                decisions: result.decisions,
            }, format));
        }
        else {
            console.log(renderReport(result.report));
            console.log("");
            // Attributed identity line (S2.1 AC8). The claimed owner is read HERE,
            // for this local display only (ADR-005 F1).
            console.log(renderIdentitySection(result.identity, readClaimedOwner(root)));
            console.log("");
            console.log(renderTrustSection(result.trust));
            console.log("");
            console.log(renderAuthorizationSection(result.authorization));
            console.log("");
            console.log(renderDecisionSection(result.decisions));
            console.log("");
            console.log(renderBaselineSection(result.provenance, [...result.findings], result.repinned));
        }
        // exitCode, NEVER process.exit() here: a forced exit races the async
        // flush of a piped stdout, truncating large --json/artifact payloads
        // mid-byte (ADR-006 requires the JSON body be the complete record).
        if (result.exitCode !== 0)
            process.exitCode = result.exitCode;
    }
}
catch (e) {
    if (e instanceof BaselineRefusalError ||
        e instanceof IdentityRefusalError ||
        e instanceof PolicyRefusalError ||
        e instanceof LedgerRefusalError) {
        // Same `.deepsweep/` containment-refusal class (ADR-003 invariants,
        // inherited by the identity and policy stores per ADR-005/ADR-009) →
        // same exit code 3. Error messages are a rendered surface (S1.9).
        console.error(renderErrorLine(e.message));
        process.exit(3);
    }
    throw e;
}
