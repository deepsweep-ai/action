import type { ReviewReport, ReviewWarning } from "./review/types.js";
import type { DriftFinding } from "./review/diff.js";
import type { BaselineInvalidReason, BaselineProvenance } from "./review/baseline.js";
import type { AgentIdentityRecord } from "./review/identity.js";
import type { AuthorizationGapView } from "./review/authgap.js";
import type { DecisionView } from "./review/evaluate.js";
/**
 * How this run obtained its baseline — the ADR-006 gating input. Carries the
 * regeneration reason so exit-code gating keys on KIND + reason, never on the
 * warning severity of the rendered finding.
 */
export type BaselineDisposition = {
    status: "existing";
} | {
    status: "created";
} | {
    status: "regenerated";
    reason: BaselineInvalidReason;
};
export interface OneShotOptions {
    /** Explicit re-pin (ADR-003 moment 2). Never implied. */
    updateBaseline?: boolean;
    /** Injectable clock for deterministic tests. */
    now?: () => Date;
    /** ADR-014: injectable user-scope config root (defaults to the home dir). */
    userConfigRoot?: string;
}
export interface OneShotResult {
    report: ReviewReport;
    /** Pin-time warnings (endpoint-shaped keys, secret-shaped args, dup keys). */
    pinWarnings: ReviewWarning[];
    provenance: BaselineProvenance;
    /** Sorted drift + lifecycle findings for this run. */
    findings: DriftFinding[];
    /** ADR-006 gating input: existing | created (first run) | regenerated. */
    baselineDisposition: BaselineDisposition;
    repinned: boolean;
    /**
     * Claimed agent identity registry after this run (S2.1, ADR-005):
     * attribution-for-explainability only, never authority. The transient
     * claimed owner is deliberately NOT part of this result (ADR-005 F1) —
     * display surfaces read it separately and never persist it.
     */
    identityRecords: AgentIdentityRecord[];
    /**
     * Authorization coverage view (S3.3, ADR-009 default-observe): which detected
     * capabilities are governed by `.deepsweep/policy.json` vs open authorization
     * gaps. An advisory read of policy against findings — never a decision, never
     * an exit-code input.
     */
    authorizationGaps: AuthorizationGapView;
    /**
     * Advisory policy decisions (S3.2, ADR-009): the per-capability
     * allow/deny/require-approval/observe decision for each GOVERNED capability,
     * with the deciding rule + version-pinned policyRef. Order-independent
     * most-restrictive-wins; `observe` is record-only. NEVER enforced, NEVER an
     * exit-code input — a rendered view only.
     */
    policyDecisions: DecisionView;
}
/**
 * May throw BaselineRefusalError, IdentityRefusalError, or PolicyRefusalError
 * on `.deepsweep/` containment violations (all map to exit 3 in the CLI — the
 * same refusal class, ADR-003 invariants inherited by every contained store).
 */
export declare function runReviewOnce(workspaceRoot: string, opts?: OneShotOptions): OneShotResult;
