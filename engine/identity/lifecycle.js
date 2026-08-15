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
/** Valid state transitions. Anything absent is denied (deny-wins). */
const VALID = {
    registered: ["active", "decommissioned"],
    active: ["quarantined", "decommissioned"],
    quarantined: ["active", "decommissioned"],
    decommissioned: [],
};
export function transition(rec, to, opts = {}) {
    const base = { from: rec.state, to, agentId: rec.agentId };
    // Totality guard: a forged/unknown state (records are structural — a
    // tampered store or an any-cast reaches here at runtime) must DENY, never
    // throw and never fall through to a permissive branch. Bounded slice so a
    // hostile state string cannot bloat the reason surface.
    const permitted = VALID[rec.state];
    if (permitted === undefined) {
        return {
            ...base,
            allowed: false,
            policy: "lifecycle.unknown-state",
            reason: `Unknown lifecycle state ${JSON.stringify(String(rec.state).slice(0, 32))} — denied (fail-closed).`,
        };
    }
    if (!permitted.includes(to)) {
        return {
            ...base,
            allowed: false,
            policy: "lifecycle.valid-transitions",
            reason: `Transition ${rec.state} → ${to} is not permitted (deny-wins).`,
        };
    }
    if (rec.state === "quarantined" && to === "active" && opts.approved !== true) {
        return {
            ...base,
            allowed: false,
            policy: "lifecycle.quarantine-exit-requires-approval",
            reason: "Re-activation from quarantine requires explicit human approval.",
        };
    }
    return {
        ...base,
        allowed: true,
        policy: "lifecycle.valid-transitions",
        reason: `Transition ${rec.state} → ${to} authorized${opts.actor ? ` by ${opts.actor}` : ""}.`,
        record: { ...rec, state: to },
    };
}
export const STALE_AFTER_DAYS = 30;
const DAY_MS = 86_400_000;
function daysBetween(aIso, bIso) {
    return (Date.parse(bIso) - Date.parse(aIso)) / DAY_MS;
}
/**
 * Review a fleet of agent identities for lifecycle boundary gaps.
 * `nowIso` is injected for determinism (never reads the clock).
 */
export function reviewIdentityGaps(records, nowIso) {
    const gaps = [];
    for (const r of records) {
        if (r.state === "decommissioned") {
            if (daysBetween(r.lastSeenAt, nowIso) < 1) {
                gaps.push({
                    kind: "zombieActivity",
                    severity: "critical",
                    agentId: r.agentId,
                    summary: `Decommissioned agent ${r.agentId} showed activity within the last day.`,
                    recommendation: "Revoke remaining credentials and review the audit ledger for this agent.",
                });
            }
            continue;
        }
        if (!r.owner) {
            gaps.push({
                kind: "missingOwner",
                severity: "high",
                agentId: r.agentId,
                summary: `Agent ${r.agentId} has no accountable human owner.`,
                recommendation: "Assign an owning team/individual before granting further authorization.",
            });
        }
        if (daysBetween(r.lastSeenAt, nowIso) > STALE_AFTER_DAYS) {
            gaps.push({
                kind: "staleIdentity",
                severity: "high",
                agentId: r.agentId,
                summary: `Agent ${r.agentId} has been inactive for over ${STALE_AFTER_DAYS} days.`,
                recommendation: "Decommission the identity or recertify it via an access review.",
            });
        }
        if (r.expectedLifetimeDays === undefined) {
            gaps.push({
                kind: "indefiniteLifetime",
                severity: "medium",
                agentId: r.agentId,
                summary: `Agent ${r.agentId} has no expected lifetime.`,
                recommendation: "Set expectedLifetimeDays so leaver-stage offboarding can trigger.",
            });
        }
        else if (daysBetween(r.registeredAt, nowIso) > r.expectedLifetimeDays) {
            gaps.push({
                kind: "lifetimeExpired",
                severity: "critical",
                agentId: r.agentId,
                summary: `Agent ${r.agentId} exceeded its expected lifetime of ${r.expectedLifetimeDays} days.`,
                recommendation: "Decommission now (leaver stage) or explicitly recertify with a new lifetime.",
            });
        }
    }
    return gaps;
}
/**
 * Compute an Agent Access Review from granted capabilities vs observed
 * actions (e.g. distinct action strings from the audit ledger). Pure.
 */
export function computeAccessReview(agentId, granted, observed) {
    const g = new Set(granted);
    const o = new Set(observed);
    const unusedCapabilities = [...g].filter((x) => !o.has(x)).sort();
    const ungovernedActions = [...o].filter((x) => !g.has(x)).sort();
    const aligned = [...g].filter((x) => o.has(x)).sort();
    const verdict = ungovernedActions.length > 0 ? "drift" : unusedCapabilities.length > 0 ? "tighten" : "aligned";
    return { agentId, unusedCapabilities, ungovernedActions, aligned, verdict };
}
/** Plain-text rendering for CLI/IDE surfaces (60-second AHA rule). */
export function renderAccessReview(r) {
    const lines = [
        `Agent Access Review — ${r.agentId}`,
        `Verdict: ${r.verdict.toUpperCase()}`,
    ];
    if (r.ungovernedActions.length)
        lines.push(`  ⚠ Ungoverned actions (used, never authorized): ${r.ungovernedActions.join(", ")}`);
    if (r.unusedCapabilities.length)
        lines.push(`  ↓ Unused capabilities (tighten to least privilege): ${r.unusedCapabilities.join(", ")}`);
    if (r.aligned.length)
        lines.push(`  ✓ Aligned: ${r.aligned.join(", ")}`);
    if (r.verdict === "aligned" && !r.aligned.length)
        lines.push("  (no capabilities granted, none observed)");
    return lines.join("\n");
}
