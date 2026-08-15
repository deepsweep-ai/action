/**
 * ADR-011 — identity lifecycle wiring: registry → JML records → review
 * findings. Pure derivation; no I/O, no clock (nowIso is the caller's).
 *
 * v0 derivation semantics (deliberately narrow, documented in ADR-011):
 *  - Every registry record derives as state "active" — no persisted state
 *    machine exists yet, so quarantine/decommission states (and therefore
 *    the zombieActivity detector) cannot fire from this path. transition()
 *    remains the programmatic JML surface for E2 consumers.
 *  - lastSeenAt falls back to firstObservedAt on pre-ADR-011 stores.
 *  - The claimed owner (git user.email) participates as PRESENCE ONLY: a
 *    sentinel string stands in for it so the value itself can never leak
 *    through a lifecycle record, gap summary, finding, or event (ADR-005
 *    transient-owner rule). Gap text carries agentIds (inert derived hex)
 *    and static template copy — metadata-only by construction.
 */
import { IDENTITY_REL_PATH } from "../review/identity.js";
/** Presence stand-in for the transient claimed owner — never the value. */
export const OWNER_PRESENT = "(claimed-owner-present)";
/** Derive transient JML records from the persisted identity registry. */
export function deriveLifecycleRecords(records, ownerPresent) {
    return records.map((r) => ({
        agentId: r.agentId,
        state: "active",
        registeredAt: r.firstObservedAt,
        lastSeenAt: r.lastObservedAt ?? r.firstObservedAt,
        ...(ownerPresent ? { owner: OWNER_PRESENT } : {}),
    }));
}
/** Total, type-guarded gap-kind → finding-kind map (ADR-011 additive kinds). */
const GAP_FINDING_KIND = {
    missingOwner: "identity.missingOwner",
    staleIdentity: "identity.staleIdentity",
    indefiniteLifetime: "identity.indefiniteLifetime",
    lifetimeExpired: "identity.lifetimeExpired",
    zombieActivity: "identity.zombieActivity",
};
/**
 * Render an IdentityGap as a review finding. Advisory: these kinds have no
 * ADR-006 exit-code mapping and are not on the ADR-004 event stream in v1;
 * they surface in the report / --json and deduct posture via ADR-011's
 * FINDING_DELTAS entries (workspace-shared scope — the registry is a
 * workspace store; per-agent scoping is an ADR-011 noted follow-up).
 */
export function identityGapFinding(gap) {
    return {
        kind: GAP_FINDING_KIND[gap.kind],
        severity: gap.severity,
        resource: gap.agentId,
        source: IDENTITY_REL_PATH,
        entityHash: null,
        explanation: `${gap.summary} Recommendation: ${gap.recommendation}`,
    };
}
