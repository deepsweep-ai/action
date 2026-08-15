/**
 * Agent Identity Lifecycle (JML for AI agents) + Agent Access Review.
 * ADR-019 — evidence: CSA RIG (Jul 27 2026), enterprise IAM-for-AI-systems
 * hiring signals, PP-5 (agent-first identity crisis) + PP-2 (governance).
 *
 * Invariants:
 *  - Deterministic, zero runtime deps, no network, no execution.
 *  - Every decision is explainable: who / what / why / policy / outcome.
 *  - Quarantine exit requires explicit approval (safe default).
 *  - Terminology: review / boundary gap / authorize — never "scan".
 */
export type LifecycleState = "registered" | "active" | "quarantined" | "decommissioned";
export interface AgentLifecycleRecord {
    agentId: string;
    /** Human accountable for this agent. CSA: 51% of orgs report no owner. */
    owner?: string;
    state: LifecycleState;
    registeredAt: string;
    lastSeenAt: string;
    /** Expected lifetime in days; absence means indefinite (flagged). */
    expectedLifetimeDays?: number;
}
export interface TransitionDecision {
    allowed: boolean;
    from: LifecycleState;
    to: LifecycleState;
    agentId: string;
    policy: string;
    reason: string;
    record?: AgentLifecycleRecord;
}
export declare function transition(rec: AgentLifecycleRecord, to: LifecycleState, opts?: {
    approved?: boolean;
    actor?: string;
}): TransitionDecision;
export type IdentityGapKind = "missingOwner" | "staleIdentity" | "lifetimeExpired" | "indefiniteLifetime" | "zombieActivity";
export interface IdentityGap {
    kind: IdentityGapKind;
    severity: "critical" | "high" | "medium";
    agentId: string;
    summary: string;
    recommendation: string;
}
export declare const STALE_AFTER_DAYS = 30;
/**
 * Review a fleet of agent identities for lifecycle boundary gaps.
 * `nowIso` is injected for determinism (never reads the clock).
 */
export declare function reviewIdentityGaps(records: AgentLifecycleRecord[], nowIso: string): IdentityGap[];
export interface AccessReview {
    agentId: string;
    /** Granted but never observed in the audit ledger → tighten (least privilege). */
    unusedCapabilities: string[];
    /** Observed but never granted → critical drift (ungoverned access path). */
    ungovernedActions: string[];
    /** Granted and observed — aligned. */
    aligned: string[];
    verdict: "aligned" | "tighten" | "drift";
}
/**
 * Compute an Agent Access Review from granted capabilities vs observed
 * actions (e.g. distinct action strings from the audit ledger). Pure.
 */
export declare function computeAccessReview(agentId: string, granted: string[], observed: string[]): AccessReview;
/** Plain-text rendering for CLI/IDE surfaces (60-second AHA rule). */
export declare function renderAccessReview(r: AccessReview): string;
