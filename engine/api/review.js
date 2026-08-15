/**
 * Engine library — `review` capability (TEAM-ADR-027).
 *
 * Formerly reachable only through the `deepsweep review` command layer. The
 * composition (one-shot review + trust composites + ADR-006/ADR-012 exit-code
 * gating) now lives HERE so the Governance Studio (over Tauri IPC), the
 * headless sidecar, and the legacy CLI shim all call the SAME function with
 * identical semantics.
 *
 * Determinism (repo invariant): `nowIso` is REQUIRED and injected by the
 * caller — this module never reads an ambient clock.
 */
import { basename, resolve } from "node:path";
import { runReviewOnce } from "../oneshot.js";
import { resolveExitCode } from "../gating.js";
import { computeTrustScores } from "../review/score.js";
import { buildEvent } from "../review/events.js";
import { principalFor } from "../review/identity.js";
/**
 * Run one review and resolve its gated outcome. Pure with respect to time:
 * two calls with the same `nowIso` over the same workspace state produce the
 * same result.
 *
 * May throw the contained-store refusal classes (BaselineRefusalError,
 * IdentityRefusalError, PolicyRefusalError, LedgerRefusalError) — callers map
 * them to the ADR-003 refusal outcome (exit 3).
 */
export function reviewWorkspace(params) {
    const root = resolve(params.workspaceRoot);
    const nowIso = params.nowIso;
    const result = runReviewOnce(root, {
        ...(params.updateBaseline === true ? { updateBaseline: true } : {}),
        ...(params.userConfigRoot !== undefined ? { userConfigRoot: params.userConfigRoot } : {}),
        now: () => new Date(nowIso),
    });
    const report = {
        ...result.report,
        warnings: [...result.report.warnings, ...result.pinWarnings],
    };
    const trust = computeTrustScores({
        report,
        findings: result.findings,
        identityRecords: result.identityRecords,
    });
    const workspace = basename(root);
    const events = result.findings.map((f, i) => buildEvent(f, {
        workspace,
        seq: i + 1,
        occurredAt: nowIso,
        principal: principalFor(f.source, workspace),
    }));
    const exitCode = resolveExitCode({
        findings: result.findings,
        baselineDisposition: result.baselineDisposition,
        criticalGaps: report.totals.critical,
        highGaps: report.totals.high,
    }, {
        failOn: params.failOn ?? "critical",
        failOnDrift: params.failOnDrift === true,
        requireBaseline: params.requireBaseline === true,
    });
    return {
        report,
        provenance: result.provenance,
        findings: result.findings,
        baselineDisposition: result.baselineDisposition,
        repinned: result.repinned,
        identity: result.identityRecords,
        trust,
        authorization: result.authorizationGaps,
        decisions: result.policyDecisions,
        events,
        exitCode,
    };
}
