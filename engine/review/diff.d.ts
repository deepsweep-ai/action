/**
 * Pure drift diff for watch mode and one-shot baseline comparison (ADR-004).
 * `diffReports(prev, next)` is a pure, deterministic function of two typed
 * snapshots; output ordering is fully sorted (by kind, then source, then
 * resource) so the stream is snapshot-testable — no wall-clock dependence.
 *
 * Snapshot semantics (ADR-003 re-pin policy): in the watch loop, `prev`
 * carries the PREVIOUS report (capability/gap delta) but the SESSION BASELINE
 * entities (held immutable in memory), so `pin.drift` re-raises on every
 * re-review until an explicit re-pin — silent re-trust cannot recur here.
 */
import type { ReviewReport, Severity } from "./types.js";
import type { PinnedEntity } from "./pins.js";
export type DriftKind = "capability.added" | "capability.removed" | "gap.opened" | "gap.resolved" | "pin.drift" | "pin.conflict" | "baseline.created" | "baseline.regenerated" | "baseline.tampered" | "identity.regenerated" | "policy.invalid" | "ledger.corrupt" | "identity.missingOwner" | "identity.staleIdentity" | "identity.indefiniteLifetime" | "identity.lifetimeExpired" | "identity.zombieActivity";
export interface DriftFinding {
    kind: DriftKind;
    severity: Severity;
    /** The affected resource (capability resource, entityType:logicalName, …). */
    resource: string;
    /** Workspace-relative source path (or "review" for cross-source gaps). */
    source: string;
    /** Canonical entity hash where applicable (pin.* kinds), else null. */
    entityHash: string | null;
    explanation: string;
}
export interface ReviewSnapshot {
    report: ReviewReport;
    entities: PinnedEntity[];
}
export declare function diffReports(prev: ReviewSnapshot, next: ReviewSnapshot): DriftFinding[];
