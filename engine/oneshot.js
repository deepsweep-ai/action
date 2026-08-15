/**
 * One-shot review composition (CLI shell layer, testable without the CLI).
 * Composes the pure review core (review, extractPins, diffReports) with
 * baseline persistence per ADR-003:
 *  - first run creates the baseline (info: baseline.created);
 *  - invalid/foreign/corrupt baselines are discarded and regenerated
 *    (warning: baseline.regenerated);
 *  - a drifted entity is NEVER re-pinned implicitly — pin.drift re-raises on
 *    every run until an explicit `--update-baseline`.
 */
import { basename, resolve } from "node:path";
import { review } from "./review/engine.js";
import { extractPins } from "./review/pins.js";
import { diffReports } from "./review/diff.js";
import { baselineCreatedFinding, baselineRegeneratedFinding, buildBaseline, loadBaseline, writeBaseline, } from "./review/baseline.js";
import { observeIdentities, readClaimedOwner } from "./review/identity.js";
import { reviewIdentityGaps } from "./identity/lifecycle.js";
import { deriveLifecycleRecords, identityGapFinding } from "./identity/wiring.js";
import { loadPolicy } from "./review/policy.js";
import { buildAuthorizationGapView } from "./review/authgap.js";
import { buildDecisionView } from "./review/evaluate.js";
import { computeTrustScores } from "./review/score.js";
import { appendLedgerEntry } from "./review/ledger.js";
/**
 * May throw BaselineRefusalError, IdentityRefusalError, or PolicyRefusalError
 * on `.deepsweep/` containment violations (all map to exit 3 in the CLI — the
 * same refusal class, ADR-003 invariants inherited by every contained store).
 */
export function runReviewOnce(workspaceRoot, opts = {}) {
    const root = resolve(workspaceRoot);
    const workspace = basename(root);
    const nowIso = (opts.now?.() ?? new Date()).toISOString();
    const report = review(root, opts.userConfigRoot !== undefined ? { userConfigRoot: opts.userConfigRoot } : {});
    const extraction = extractPins(root);
    const loaded = loadBaseline(root);
    const findings = [];
    let baselineEntities;
    let baselineDoc;
    let fileHash;
    let baselineDisposition;
    let repinned = false;
    if (loaded.status === "ok") {
        baselineEntities = loaded.baseline.entities;
        baselineDoc = loaded.baseline;
        fileHash = loaded.fileHash;
        baselineDisposition = { status: "existing" };
    }
    else {
        // First-run creation or regenerate-not-migrate (ADR-003).
        baselineDoc = buildBaseline(workspace, extraction, nowIso);
        fileHash = writeBaseline(root, baselineDoc).fileHash;
        baselineEntities = extraction.entities;
        if (loaded.status === "absent") {
            findings.push(baselineCreatedFinding(extraction.entities.length));
            baselineDisposition = { status: "created" };
        }
        else {
            findings.push(baselineRegeneratedFinding(loaded.reason));
            baselineDisposition = { status: "regenerated", reason: loaded.reason };
        }
    }
    // Identity registry (ADR-005): reconciled AFTER baseline handling so a
    // baseline reset demonstrably cannot touch it — attribution continuity
    // survives regeneration (its own store, its own lifecycle findings).
    const identity = observeIdentities(root, report.reviewedSources, nowIso);
    findings.push(...identity.findings);
    // Identity lifecycle gaps (ADR-011/ADR-019): derive transient JML records
    // from the registry (claimed owner participates as PRESENCE only — the
    // value never enters a record, finding, or event) and surface the gap
    // detectors as advisory findings. No ADR-006 exit-code mapping (the gate
    // filter below stays kind-keyed on the accepted kinds), no ADR-004 event
    // emission in v1; report/--json surface + ADR-011 posture deltas only.
    const lifecycleRecords = deriveLifecycleRecords(identity.records, readClaimedOwner(root) !== undefined);
    findings.push(...reviewIdentityGaps(lifecycleRecords, nowIso).map(identityGapFinding));
    // Policy store (ADR-009/S3.1): load + STRICTLY validate .deepsweep/policy.json
    // through the shared contained store. A containment violation throws
    // PolicyRefusalError (CLI exit 3). An invalid policy is a WHOLE-SET refusal —
    // its policy.invalid finding surfaces (advisory; ADR-009 N2 maps it to NO
    // exit code), and NO rule is evaluated. A valid or absent policy adds no
    // findings; evaluation against actions is S3.2/S3.3, not this stage.
    const policy = loadPolicy(root);
    if (policy.status === "invalid")
        findings.push(...policy.refusal.findings);
    // Authorization coverage (S3.3, ADR-009 default-observe): read the loaded
    // policy against the detected capabilities — governed vs open authorization
    // gaps. Absent OR invalid policy governs nothing (every capability is a gap);
    // this is a rendered VIEW, not a finding on the event/gating stream.
    const authorizationGaps = buildAuthorizationGapView(report.capabilities, policy);
    // Same report on both sides: capability/gap deltas are empty in one-shot
    // mode; only pin.drift / pin.conflict emerge (pins vs the stored baseline).
    findings.push(...diffReports({ report, entities: baselineEntities }, { report, entities: extraction.entities }));
    if (opts.updateBaseline === true && loaded.status === "ok") {
        const repinnedDoc = buildBaseline(workspace, extraction, nowIso, loaded.baseline);
        fileHash = writeBaseline(root, repinnedDoc).fileHash;
        baselineDoc = repinnedDoc;
        repinned = true;
    }
    const provenance = {
        createdAt: baselineDoc.createdAt,
        lastPinnedAt: baselineDoc.lastPinnedAt,
        entityCount: baselineDoc.entityCount,
        baselineSha256: fileHash,
    };
    // Advisory policy decisions (S3.2, ADR-009): evaluated AFTER drift so the
    // driftOutstanding Condition input reflects this run. Posture enters as a
    // Condition INPUT only (ADR-007) — computed fresh from this run's findings,
    // per agent. Pure and deterministic; produces decisions, enforces nothing.
    const driftOutstanding = findings.some((f) => f.kind === "pin.drift" || f.kind === "pin.conflict" || f.kind === "baseline.tampered");
    const trust = computeTrustScores({ report, findings, identityRecords: identity.records });
    const postureByAgentType = new Map(trust.map((t) => [t.agentType, t.trustScore.postureScore]));
    const policyDecisions = buildDecisionView(report.capabilities, policy, workspace, postureByAgentType, driftOutstanding);
    // Audit ledger (ADR-018): one metadata-only run record per one-shot
    // review — counts and hashes, never contents. A malformed ledger surfaces
    // loudly as ledger.corrupt (advisory; the corruption stays on disk for
    // anchor verification) and the review itself still completes.
    const appended = appendLedgerEntry(root, "review.run", {
        workspace,
        capabilities: report.totals.capabilities,
        boundaryGaps: report.totals.boundaryGaps,
        critical: report.totals.critical,
        high: report.totals.high,
        findingCount: findings.length,
        baselineSha256: fileHash,
    }, nowIso);
    if (appended === "corrupt") {
        findings.push({
            kind: "ledger.corrupt",
            severity: "high",
            resource: "ledger.jsonl",
            source: ".deepsweep/ledger.jsonl",
            entityHash: null,
            explanation: "Audit ledger is malformed — appends are refused so the corruption stays verifiable against any exported anchor. Verify against your latest anchor, then archive and re-initialize the ledger.",
        });
    }
    return {
        report,
        pinWarnings: extraction.warnings,
        provenance,
        findings,
        baselineDisposition,
        repinned,
        identityRecords: identity.records,
        authorizationGaps,
        policyDecisions,
    };
}
