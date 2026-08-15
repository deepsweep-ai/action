/**
 * `deepsweep review --watch` — foreground watch loop (CLI shell; ADR-004).
 * The review core stays pure (review / extractPins / diffReports); this
 * module owns the process model:
 *  - node:fs.watch on the parent directories of allowlisted paths only
 *    (workspace root non-recursively + fixed config dirs + .deepsweep/),
 *    bounding watchers to O(allowlist) — no node_modules/.git storms.
 *  - Quiet-period debounce (300 ms) with a 2 s hard ceiling; single-flight
 *    full re-reviews (at most one running + one pending trigger).
 *  - The session baseline is held immutable in memory; the watch loop NEVER
 *    rewrites the baseline (ADR-003 re-pin policy) — pin.drift is sticky.
 *  - Tamper check (ADR-003 mitigation 3): the SHA-256 of the baseline as
 *    loaded/last written by this session is kept in memory and compared
 *    against the on-disk file on every re-review trigger, on .deepsweep/
 *    events, and at session end; divergence emits baseline.tampered.
 *  - `--json`: JSON Lines on stdout (JSON.stringify only), human on stderr;
 *    stdout backpressure respected. SIGINT/SIGTERM close all watchers and
 *    exit 0.
 */
import { existsSync, watch as fsWatch } from "node:fs";
import { basename, join, resolve } from "node:path";
import { review } from "./review/engine.js";
import { extractPins, PIN_SOURCES } from "./review/pins.js";
import { diffReports } from "./review/diff.js";
import { BASELINE_DIR, BASELINE_REL_PATH, baselineCreatedFinding, baselineRegeneratedFinding, baselineTamperedFinding, buildBaseline, hashBaselineOnDisk, loadBaseline, writeBaseline, } from "./review/baseline.js";
import { buildEvent, eventLine } from "./review/events.js";
import { claimedIdentityClaim, observeIdentities, principalFor, readClaimedOwner, } from "./review/identity.js";
import { computeTrustScores, factorLine, POSTURE_ASSURANCE_NOTE, POSTURE_HONEST_LIMIT_NOTE, qualifiedPostureLine, } from "./review/score.js";
import { loadPolicy } from "./review/policy.js";
import { buildAuthorizationGapView } from "./review/authgap.js";
import { buildDecisionView } from "./review/evaluate.js";
import { OUTCOME_LABEL } from "./review/evaluate.js";
import { sanitizeField, sanitizeFieldKeepEnding } from "./review/sanitize.js";
import { countNoun } from "./review/text.js";
export const DEBOUNCE_QUIET_MS = 300;
export const DEBOUNCE_CEILING_MS = 2000;
/** Parent directories watched non-recursively ("" = workspace root). */
export const WATCHED_PARENT_DIRS = Object.freeze([
    "",
    ".cursor",
    ".cursor/rules",
    ".claude",
    ".vscode",
    ".devcontainer",
    ".github",
    ".github/instructions",
    ".github/workflows",
    ".windsurf",
    ".windsurf/rules",
    ".windsurf/workflows",
    BASELINE_DIR,
]);
/** Allowlisted files whose changes trigger a re-review. */
const FILE_ALLOWLIST = new Set([
    ...PIN_SOURCES,
    ".cursorrules",
    ".cursor/hooks.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".devcontainer/devcontainer.json",
    ".devcontainer.json",
    ".github/copilot-instructions.md",
    ".github/workflows/copilot-setup-steps.yml",
    ".github/workflows/copilot-setup-steps.yaml",
    "AGENTS.md",
    ".windsurfrules",
    ".env",
    ".env.local",
    ".env.production",
    BASELINE_REL_PATH,
]);
/** Directories whose creation/removal (as a root/parent entry) is relevant. */
const DIR_TRIGGERS = new Set([
    ".cursor",
    ".cursor/rules",
    ".claude",
    ".vscode",
    ".devcontainer",
    ".github",
    ".github/instructions",
    ".github/workflows",
    ".windsurf",
    ".windsurf/rules",
    ".windsurf/workflows",
    ".git",
    BASELINE_DIR,
]);
/** Directories whose file contents (names) feed detectors. */
const CONTENT_DIR_PREFIXES = [
    ".cursor/rules/",
    ".github/instructions/",
    ".windsurf/rules/",
    ".windsurf/workflows/",
];
export function isRelevantPath(rel) {
    if (FILE_ALLOWLIST.has(rel))
        return true;
    if (DIR_TRIGGERS.has(rel))
        return true;
    return CONTENT_DIR_PREFIXES.some((p) => rel.startsWith(p));
}
function writeLine(stream, line) {
    return new Promise((done) => {
        if (stream.write(`${line}\n`))
            done();
        else
            stream.once("drain", done);
    });
}
const SEV_TAG = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    warning: "WARNING",
    info: "INFO",
};
/**
 * Human render of one drift finding (stderr in --json mode, stdout otherwise).
 * The explanation uses the keep-ending sanitizer (QA defect D2, generalized
 * by S1.12): pin.drift, pin.conflict, identity.regenerated, and
 * baseline.tampered copy all end with their remediation/disclosure, which a
 * tail truncation would cut off. Exported for the D2/S1.12 regression tests.
 */
export function humanLine(f) {
    const s = sanitizeField;
    return `[${SEV_TAG[f.severity] ?? "INFO"}] ${f.kind} ${s(f.resource)} — ${sanitizeFieldKeepEnding(f.explanation)} (${s(f.source)})`;
}
function delay(ms) {
    return new Promise((done) => setTimeout(done, ms));
}
/** May throw BaselineRefusalError before any watcher is created (exit 3). */
export async function startWatch(opts) {
    const root = resolve(opts.workspaceRoot);
    const workspace = basename(root);
    const json = opts.json ?? false;
    const out = opts.stdout ?? process.stdout;
    const err = opts.stderr ?? process.stderr;
    const human = json ? err : out;
    const quietMs = opts.quietMs ?? DEBOUNCE_QUIET_MS;
    const ceilingMs = opts.ceilingMs ?? DEBOUNCE_CEILING_MS;
    const now = opts.now ?? (() => new Date());
    let seq = 0;
    let closed = false;
    let reviewing = false;
    let pending = false;
    let quietTimer;
    let ceilingTimer;
    // ---- Initial review + baseline (before watchers attach: our own
    // first-run/re-pin write must not self-trigger a re-review). ----
    let report = review(root);
    let extraction = extractPins(root);
    const loaded = loadBaseline(root); // throws BaselineRefusalError on containment violation
    const nowIso = now().toISOString();
    const startupFindings = [];
    let baselineEntities;
    let expectedHash;
    let createdAt;
    let lastPinnedAt;
    if (loaded.status === "ok") {
        baselineEntities = loaded.baseline.entities;
        expectedHash = loaded.fileHash;
        createdAt = loaded.baseline.createdAt;
        lastPinnedAt = loaded.baseline.lastPinnedAt;
        // Surface pre-existing drift vs the stored baseline immediately.
        startupFindings.push(...diffReports({ report, entities: baselineEntities }, { report, entities: extraction.entities }));
        if (opts.updateBaseline === true) {
            const repinned = buildBaseline(workspace, extraction, nowIso, loaded.baseline);
            expectedHash = writeBaseline(root, repinned).fileHash;
            baselineEntities = extraction.entities;
            createdAt = repinned.createdAt;
            lastPinnedAt = repinned.lastPinnedAt;
        }
    }
    else {
        const created = buildBaseline(workspace, extraction, nowIso);
        expectedHash = writeBaseline(root, created).fileHash;
        baselineEntities = extraction.entities;
        createdAt = created.createdAt;
        lastPinnedAt = created.lastPinnedAt;
        startupFindings.push(loaded.status === "absent"
            ? baselineCreatedFinding(extraction.entities.length)
            : baselineRegeneratedFinding(loaded.reason));
        // pin.conflict is a property of the current snapshot — surface it even
        // on a fresh pin (never a silent pick-one).
        startupFindings.push(...diffReports({ report, entities: baselineEntities }, { report, entities: extraction.entities }));
    }
    // ---- Identity registry (S2.1, ADR-005): observed at session start,
    // BEFORE watchers attach (our own registry write must not self-trigger).
    // Attribution continuity survives baseline resets (separate store). ----
    const identity = observeIdentities(root, report.reviewedSources, nowIso);
    startupFindings.push(...identity.findings);
    // ---- Policy store (ADR-009/S3.1) + authorization coverage (S3.3): loaded
    // BEFORE watchers attach. A containment violation throws PolicyRefusalError
    // (CLI exit 3). An invalid policy surfaces its policy.invalid finding
    // (advisory; ADR-009 N2) and governs nothing — every capability becomes an
    // authorization gap, mirroring the one-shot path. ----
    const policyLoad = loadPolicy(root);
    if (policyLoad.status === "invalid")
        startupFindings.push(...policyLoad.refusal.findings);
    async function emit(findings) {
        if (findings.length === 0)
            return;
        const occurredAt = now().toISOString();
        for (const f of findings) {
            seq += 1;
            if (json) {
                // principal: claimed agentId of the config surface the finding
                // originates from — derived fresh (ADR-005), never a store lookup.
                await writeLine(out, eventLine(buildEvent(f, { workspace, seq, occurredAt, principal: principalFor(f.source, workspace) })));
            }
            await writeLine(human, humanLine(f));
        }
    }
    // ---- Watchers (O(allowlist) parents, non-recursive) ----
    const watchers = new Map();
    function onFsEvent(relDir, filename) {
        if (closed)
            return;
        const name = typeof filename === "string" ? filename : filename ? filename.toString("utf8") : undefined;
        if (name !== undefined) {
            const rel = relDir === "" ? name : `${relDir}/${name}`;
            if (!isRelevantPath(rel))
                return;
        }
        // Unknown filename (platform quirk): fall through to a conservative
        // trigger — debounce + full re-review absorb the imprecision.
        schedule();
    }
    function attachWatchers() {
        if (closed)
            return;
        for (const relDir of WATCHED_PARENT_DIRS) {
            if (watchers.has(relDir))
                continue;
            const abs = relDir === "" ? root : join(root, relDir);
            if (!existsSync(abs))
                continue; // creation is caught by the root watch
            try {
                const w = fsWatch(abs, (_event, filename) => onFsEvent(relDir, filename));
                w.on("error", () => {
                    w.close();
                    watchers.delete(relDir);
                });
                watchers.set(relDir, w);
            }
            catch {
                /* directory vanished between existsSync and watch — root watch covers it */
            }
        }
    }
    // ---- Debounce + single-flight ----
    function schedule() {
        /* v8 ignore next -- reason: defensive; unreachable — both call sites (onFsEvent, runCycle's finally) re-check `closed` synchronously immediately before calling with no await in between, so schedule() can never observe closed===true on a single-threaded event loop. */
        if (closed)
            return;
        if (reviewing) {
            pending = true;
            return;
        }
        if (quietTimer !== undefined)
            clearTimeout(quietTimer);
        quietTimer = setTimeout(fire, quietMs);
        if (ceilingTimer === undefined) {
            // Ceiling measured from the first event after the previous run completed.
            ceilingTimer = setTimeout(fire, ceilingMs);
        }
    }
    function clearTimers() {
        if (quietTimer !== undefined) {
            clearTimeout(quietTimer);
            quietTimer = undefined;
        }
        if (ceilingTimer !== undefined) {
            clearTimeout(ceilingTimer);
            ceilingTimer = undefined;
        }
    }
    function fire() {
        clearTimers();
        void runCycle();
    }
    function tamperCheck() {
        let onDisk;
        try {
            onDisk = hashBaselineOnDisk(root);
            /* v8 ignore next 3 -- reason: defensive; unreachable today — hashBaselineOnDisk catches containment refusals internally and returns undefined by contract; this catch only guards against future contract drift in that callee. */
        }
        catch {
            onDisk = undefined; // containment refusal mid-session is suspicious too
        }
        return onDisk === expectedHash ? [] : [baselineTamperedFinding(expectedHash, onDisk)];
    }
    async function runCycle() {
        /* v8 ignore start -- reason: defensive re-entry guards; unreachable — runCycle is
           invoked only by fire(), which synchronously clears both timers before the call,
           and timers are never armed while `reviewing` or `closed` (schedule() coalesces to
           `pending` during a review; close() clears timers when setting `closed`), so
           double entry / post-close entry cannot occur on a single-threaded event loop.
           Kept as belt-and-braces against future refactors of the trigger wiring. */
        if (closed)
            return;
        if (reviewing) {
            pending = true;
            return;
        }
        /* v8 ignore stop */
        reviewing = true;
        try {
            const findings = [...tamperCheck()];
            const nextReport = review(root);
            const nextExtraction = extractPins(root);
            // prev = previous report (capability/gap delta) + SESSION BASELINE
            // entities (immutable → pin.drift is sticky until explicit re-pin).
            findings.push(...diffReports({ report, entities: baselineEntities }, { report: nextReport, entities: nextExtraction.entities }));
            report = nextReport;
            extraction = nextExtraction;
            await emit(findings);
            attachWatchers(); // pick up newly created allowlisted directories
        }
        finally {
            reviewing = false;
            if (pending && !closed) {
                pending = false;
                schedule();
            }
        }
    }
    // ---- Lifecycle ----
    const onSignal = () => {
        void close().then(() => process.exit(0));
    };
    function removeSignalHandlers() {
        process.removeListener("SIGINT", onSignal);
        process.removeListener("SIGTERM", onSignal);
    }
    async function close() {
        if (closed)
            return;
        closed = true;
        clearTimers();
        removeSignalHandlers();
        for (const w of watchers.values())
            w.close();
        watchers.clear();
        // Session-end tamper check (ADR-003 mitigation 3).
        const findings = tamperCheck();
        if (findings.length > 0) {
            const occurredAt = now().toISOString();
            for (const f of findings) {
                seq += 1;
                if (json) {
                    await writeLine(out, eventLine(buildEvent(f, { workspace, seq, occurredAt, principal: principalFor(f.source, workspace) })));
                }
                await writeLine(human, humanLine(f));
            }
        }
        await writeLine(human, "Watch session closed — all watchers released.");
    }
    async function whenIdle() {
        for (;;) {
            if (closed ||
                (!reviewing && !pending && quietTimer === undefined && ceilingTimer === undefined)) {
                return;
            }
            await delay(15);
        }
    }
    // ---- Session header (provenance disclosure, ADR-003 mitigation 1+2) ----
    await writeLine(human, "DeepSweep — Agent Environment Review (watch mode)");
    // createdAt/lastPinnedAt come from the agent-writable baseline file
    // (loadBaseline validates typeof only) — sanitize at the render boundary
    // like every other workspace-derived string, or a hostile baseline could
    // erase/forge the provenance-disclosure lines below (S1.4 security review P1).
    await writeLine(human, `Workspace: ${sanitizeField(workspace)} · baseline: ${countNoun(baselineEntities.length, "pinned entity", "pinned entities")} · created ${sanitizeField(createdAt)} · last pinned ${sanitizeField(lastPinnedAt)}`);
    await writeLine(human, `Baseline sha256 (read time): ${expectedHash}`);
    await writeLine(human, "The baseline is local and agent-writable — absence of drift findings is not positive assurance.");
    // Identity disclosure (S2.1, ADR-005): claimed-tier phrasing only, one
    // line per agent (registry fields are agent-writable — sanitize at the
    // render boundary like every other workspace-derived string).
    if (identity.records.length === 0) {
        await writeLine(human, "Agent identity: no agent config surfaces observed — nothing to attribute.");
    }
    else {
        for (const r of identity.records) {
            await writeLine(human, `Agent identity (claimed, not verified): ${sanitizeField(claimedIdentityClaim(r.agentType))} — ${sanitizeField(r.agentId)}`);
        }
    }
    // Trust score composites (S2.2, ADR-007): computed fresh at session start
    // from the startup findings — never persisted, never on the event surface
    // (ADR-004 events carry findings; the score is derived from them). Every
    // line renders the single-sourced qualified copy through the choke point.
    const trustScores = computeTrustScores({
        report,
        findings: startupFindings,
        identityRecords: identity.records,
    });
    for (const t of trustScores) {
        await writeLine(human, `Trust score (composite): ${sanitizeField(t.agentId)} — ${sanitizeField(qualifiedPostureLine(t.trustScore))}`);
        for (const f of t.trustScore.decomposition) {
            // Keep-ending sanitizer (S1.12): protection.anchored factor lines end
            // with the ADR-007 honest-limit disclosure — same treatment as the
            // one-shot renderTrustSection, through the same choke point.
            await writeLine(human, `  ${sanitizeFieldKeepEnding(factorLine(f))}`);
        }
    }
    if (trustScores.length > 0) {
        await writeLine(human, `${sanitizeField(POSTURE_ASSURANCE_NOTE)}`);
        await writeLine(human, `${sanitizeField(POSTURE_HONEST_LIMIT_NOTE)}`);
    }
    // Authorization coverage (S3.3, ADR-009 default-observe): a PROPORTIONATE
    // summary line — governed capabilities vs open authorization gaps — never one
    // screaming line per capability (the full per-gap list lives in the one-shot
    // report / --json). The composed line is sanitized whole through the choke
    // point (its only variable part is the static policy-file constant; counts
    // are numeric).
    const authView = buildAuthorizationGapView(report.capabilities, policyLoad);
    if (authView.totalCapabilities > 0) {
        const nCap = countNoun(authView.totalCapabilities, "capability", "capabilities");
        const authLine = authView.policyStatus === "absent"
            ? `Authorization: ${nCap} detected, 0 governed by policy — no ${authView.policyFile} yet; every capability is an open authorization gap.`
            : authView.policyStatus === "invalid"
                ? `Authorization: policy refused — no rule evaluated, so all ${nCap} are authorization gaps until policy.json is fixed.`
                : `Authorization: ${authView.governed} of ${nCap} governed by policy · ${countNoun(authView.gaps.length, "authorization gap", "authorization gaps")}.`;
        await writeLine(human, `${sanitizeField(authLine)}`);
    }
    // Policy decisions (S3.2, ADR-009 most-restrictive-wins): a PROPORTIONATE
    // one-line count of the advisory decisions over governed capabilities — the
    // full per-capability list lives in the one-shot report / --json. Posture is
    // a Condition INPUT (ADR-007), computed fresh per agent; driftOutstanding
    // reflects the startup findings. Advisory only — never enforced, never an
    // exit-code input; `observe` is record-only. The composed line is sanitized
    // whole through the choke point (its variable parts are numeric counts).
    const driftOutstanding = startupFindings.some((f) => f.kind === "pin.drift" || f.kind === "pin.conflict" || f.kind === "baseline.tampered");
    const postureByAgentType = new Map(trustScores.map((t) => [t.agentType, t.trustScore.postureScore]));
    const decisionView = buildDecisionView(report.capabilities, policyLoad, workspace, postureByAgentType, driftOutstanding);
    if (decisionView.policyStatus === "present" && decisionView.decisions.length > 0) {
        const tally = { deny: 0, "require-approval": 0, observe: 0, allow: 0 };
        for (const d of decisionView.decisions)
            tally[d.decision.outcome] += 1;
        const parts = ["deny", "require-approval", "observe", "allow"]
            .filter((o) => tally[o] > 0)
            .map((o) => `${tally[o]} ${OUTCOME_LABEL[o]}`)
            .join(" · ");
        const decisionLine = `Policy decisions (advisory, most-restrictive-wins): ${countNoun(decisionView.decisions.length, "governed capability", "governed capabilities")} — ${parts}.`;
        await writeLine(human, `${sanitizeField(decisionLine)}`);
    }
    // Transient claimed owner (ADR-005 F1): local human display ONLY — never
    // persisted, never emitted on the event surface.
    const claimedOwner = readClaimedOwner(root);
    if (claimedOwner !== undefined) {
        await writeLine(human, `Claimed owner (git user.email — shown for this session only, never stored): ${sanitizeField(claimedOwner)}`);
    }
    await emit(startupFindings);
    attachWatchers();
    await writeLine(human, `Watching ${countNoun(watchers.size, "location")} · debounce ${quietMs}ms quiet / ${ceilingMs}ms ceiling · Ctrl-C to stop`);
    if (opts.installSignalHandlers ?? true) {
        process.on("SIGINT", onSignal);
        process.on("SIGTERM", onSignal);
    }
    return { close, watcherCount: () => watchers.size, whenIdle };
}
