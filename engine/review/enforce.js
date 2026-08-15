/**
 * Enforcement posture mapping (ADR-010) — the ACTED-ON contract.
 *
 * ADR-009's advisory READ path defaults an unmatched action to `observe`:
 * non-permissive, record-only, grants nothing. That is the correct advisory
 * posture. But the moment a decision is ACTED ON (S4.1+, the Protect stage),
 * the governing invariant is stricter: deny-wins, the DEFAULT EFFECT is
 * require-approval, and no parse/verification failure may ever fail open.
 *
 * This module is that invariant as executable contract, written BEFORE the
 * first enforcement consumer exists so no acting code path can be wired to a
 * softer default. It is pure, total, and deliberately paranoid:
 *
 *  - `deny` and `require-approval` pass through unchanged (deny-wins ladder).
 *  - `observe` — including the ADR-009 default for an unmatched action —
 *    maps to `require-approval` when acted on. Record-only is not a grant.
 *  - `allow` survives ONLY when the policy load is `ok`. An `allow` outcome
 *    paired with an `invalid`/`absent` policy is a contradiction (invalid and
 *    absent policies contribute zero rules, so no legitimate evaluation can
 *    produce it): treated as evidence of tampering or a torn read, it lands
 *    in `deny` — the verification-error posture, not merely the default.
 *  - Any outcome value outside the typed vocabulary (forged via JSON or an
 *    any-cast) lands in `deny`. Unknown input is never a permission.
 *
 * Explainability (Principle 5): the mapping is exposed both as the bare
 * effect and as an ExplainedEnforcement carrying the human "why".
 */
const OUTCOMES = new Set(["deny", "require-approval", "observe", "allow"]);
const OK_STATUSES = new Set(["ok", "invalid", "absent"]);
/**
 * Map an advisory PolicyDecision outcome to the effect an enforcement point
 * must apply. Total over arbitrary runtime input: forged/unknown values land
 * in `deny` (fail-closed), never in a permissive posture.
 */
export function enforcementEffectFor(outcome, policyStatus) {
    return explainEnforcement(outcome, policyStatus).effect;
}
/** Same mapping, with the explanation attached (Principle 5). */
export function explainEnforcement(outcome, policyStatus) {
    if (!OUTCOMES.has(outcome) || !OK_STATUSES.has(policyStatus)) {
        return {
            effect: "deny",
            why: "unrecognized decision or policy-load shape — treated as a verification failure, denied (never fail open)",
        };
    }
    switch (outcome) {
        case "deny":
            return { effect: "deny", why: "policy denies this action (deny-wins)" };
        case "require-approval":
            return { effect: "require-approval", why: "policy requires human approval for this action" };
        case "observe":
            return {
                effect: "require-approval",
                why: "no policy rule grants this action — the default acted-on posture is require-approval (record-only is not a grant)",
            };
        case "allow":
            if (policyStatus === "ok") {
                return { effect: "allow", why: "an explicit allow rule from a valid policy grants this action" };
            }
            return {
                effect: "deny",
                why: "allow outcome without a valid policy is contradictory — treated as tampering/torn state, denied",
            };
    }
}
/**
 * The ONE mapping that runs ABOVE the ADR-021 layered-policy merge.
 *
 * The self-protection rule (agent-attributed mutation of `.deepsweep/**` or
 * `~/.deepsweep/**`) is evaluated FIRST and, when it fires, the policy outcome
 * is never consulted. That ordering is the whole point: an org bundle, a
 * workspace policy, a user policy and a `defaultEffect` are all *policy*, and
 * policy cannot be allowed to grant an agent write access to the evidence that
 * makes the agent accountable.
 *
 * Total over arbitrary runtime input: a forged self-protection object (an
 * any-cast, a tampered IPC frame) whose `protected` field is not a boolean is
 * an unknown shape, and unknown shapes land in `deny` — never fail open.
 */
export function explainEnforcementAboveLayeredPolicy(selfProtection, outcome, policyStatus) {
    const sp = selfProtection;
    if (typeof sp !== "object" || sp === null || typeof sp.protected !== "boolean") {
        return {
            effect: "deny",
            why: "unrecognized self-protection verdict shape — treated as a verification failure, denied (never fail open)",
        };
    }
    if (sp.protected) {
        return {
            effect: "deny",
            why: `${sp.why} [${sp.policy}: non-overridable, evaluated above the layered-policy merge]`,
        };
    }
    return explainEnforcement(outcome, policyStatus);
}
