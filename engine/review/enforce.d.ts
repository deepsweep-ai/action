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
import type { PolicyOutcome } from "./evaluate.js";
/** What an enforcement point may actually do. There is no "observe" here —
 * acting code has exactly three postures, and the safe ones sort first. */
export type EnforcementEffect = "deny" | "require-approval" | "allow";
/** Policy-load provenance, as the discriminant of policy.ts's PolicyLoad. */
export type PolicyLoadStatus = "ok" | "invalid" | "absent";
export interface ExplainedEnforcement {
    readonly effect: EnforcementEffect;
    /** The human "why" for this mapping — carried into approval prompts and audit. */
    readonly why: string;
}
/**
 * Map an advisory PolicyDecision outcome to the effect an enforcement point
 * must apply. Total over arbitrary runtime input: forged/unknown values land
 * in `deny` (fail-closed), never in a permissive posture.
 */
export declare function enforcementEffectFor(outcome: PolicyOutcome, policyStatus: PolicyLoadStatus): EnforcementEffect;
/** Same mapping, with the explanation attached (Principle 5). */
export declare function explainEnforcement(outcome: PolicyOutcome, policyStatus: PolicyLoadStatus): ExplainedEnforcement;
/**
 * The minimal shape this module needs from the self-protection rule
 * (TEAM-ADR-028). Deliberately STRUCTURAL: enforce.ts imports nothing from
 * self-protect.ts, so the dependency runs one way (self-protect -> enforce)
 * and no module cycle can form.
 */
export interface SelfProtectionInput {
    readonly protected: boolean;
    readonly why: string;
    readonly policy: string;
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
export declare function explainEnforcementAboveLayeredPolicy(selfProtection: SelfProtectionInput, outcome: PolicyOutcome, policyStatus: PolicyLoadStatus): ExplainedEnforcement;
