import type { BaselineDisposition } from "../oneshot.js";
import type { FailOnThreshold, GatedExitCode } from "../gating.js";
import type { AgentTrustScore } from "../review/score.js";
import type { DriftEvent } from "../review/events.js";
import type { AgentIdentityRecord } from "../review/identity.js";
import type { BaselineProvenance } from "../review/baseline.js";
import type { DriftFinding } from "../review/diff.js";
import type { AuthorizationGapView } from "../review/authgap.js";
import type { DecisionView } from "../review/evaluate.js";
import type { ReviewReport } from "../review/types.js";
export interface ReviewParams {
    /** Workspace to review. Resolved; never globbed. */
    readonly workspaceRoot: string;
    /** ADR-003 moment 2 — explicit re-pin. Never implied. */
    readonly updateBaseline?: boolean;
    /**
     * ADR-014 user-scope config root. Injected by the composition root; the
     * engine never locates the profile itself.
     */
    readonly userConfigRoot?: string;
    /** ADR-012 severity threshold for exit 2. Default `critical`. */
    readonly failOn?: FailOnThreshold;
    /** ADR-006 opt-in drift / trust-anchor gating. */
    readonly failOnDrift?: boolean;
    /** ADR-006 companion assertion that a persistent baseline already exists. */
    readonly requireBaseline?: boolean;
    /** Injected clock (determinism invariant). */
    readonly nowIso: string;
}
export interface ReviewResult {
    /** Report with pin-time warnings merged in (the rendered shape). */
    readonly report: ReviewReport;
    readonly provenance: BaselineProvenance;
    readonly findings: readonly DriftFinding[];
    readonly baselineDisposition: BaselineDisposition;
    readonly repinned: boolean;
    readonly identity: readonly AgentIdentityRecord[];
    readonly trust: readonly AgentTrustScore[];
    readonly authorization: AuthorizationGapView;
    readonly decisions: DecisionView;
    /** ADR-004 drift events for this run (machine surface). */
    readonly events: readonly DriftEvent[];
    /** ADR-006/ADR-012 gated exit code under the supplied flags. 0 is the only pass. */
    readonly exitCode: GatedExitCode;
}
/**
 * Run one review and resolve its gated outcome. Pure with respect to time:
 * two calls with the same `nowIso` over the same workspace state produce the
 * same result.
 *
 * May throw the contained-store refusal classes (BaselineRefusalError,
 * IdentityRefusalError, PolicyRefusalError, LedgerRefusalError) — callers map
 * them to the ADR-003 refusal outcome (exit 3).
 */
export declare function reviewWorkspace(params: ReviewParams): ReviewResult;
