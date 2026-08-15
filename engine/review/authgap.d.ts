/**
 * S3.3 — Authorization-gap report (ADR-009 default-observe, the READ path).
 *
 * The joint 60-second payoff for S3.1: with the policy schema in place, this
 * module makes the gap between what agents CAN do (detected capabilities) and
 * what a policy actually GOVERNS visible at a glance. It READS policies against
 * findings — it is NOT the decision engine (S3.2/E4). No allow/deny outcome is
 * computed here, no enforcement happens, and nothing on this path touches exit
 * codes: authorization gaps are a rendered VIEW, never DriftFindings on the
 * event/gating/score stream.
 *
 * The "covered" definition (precise, and deliberately narrower than a decision
 * — documented because S3.2 must not contradict it): a capability is COVERED
 * when SOME policy rule's (action, resource) matchers NAME it — regardless of
 * the rule's `effect`, and regardless of `principal`/`condition`. The question
 * this stage answers is GOVERNED-vs-ungoverned ("does any rule speak to this
 * capability at all?"), not allowed-vs-denied. Principal and condition refine
 * the DECISION for a governed capability (S3.2's job); they never change
 * whether the capability is governed, so they are intentionally ignored here.
 * A capability governed only by a `deny` rule is still governed — the gap is
 * silence, not permissiveness.
 *
 * Default-observe (ADR-009): a capability NAMED BY NO rule is an authorization
 * gap — "this agent CAN do X, and no policy says whether it's allowed." Two
 * whole-set states govern NOTHING and so make every capability a gap: an ABSENT
 * policy file (the honest "nothing is governed yet" state) and an INVALID one
 * (ADR-009 whole-set refusal — no rule is evaluated). Only an `ok` policy
 * contributes rules. Unmatched is never silent.
 *
 * Pure, deterministic, zero runtime dependencies. The action/resource matching
 * reuses the ONE grammar semantics from policy.ts (`matchesAction` /
 * `matchesResource`) — never a second matcher the S3.2 evaluator would then
 * contradict — and the ONE capability→action table (`CAPABILITY_ACTION`).
 */
import type { Capability, CapabilityKind } from "./types.js";
import type { PolicyAction, PolicyLoad, PolicyRule } from "./policy.js";
/**
 * One authorization gap: a detected capability that no policy rule names. The
 * fields carry exactly what a render surface needs to explain the gap (who/
 * what/where) — `summary`, `resource`, and `source` are workspace-derived and
 * MUST be sanitized at every render boundary (norm 9); `action` and `kind` are
 * closed-vocabulary constants.
 */
export interface AuthorizationGap {
    /** Index into the report's `capabilities[]` (stable, deterministic order). */
    readonly capabilityIndex: number;
    readonly kind: CapabilityKind;
    /** The governing action word this capability maps to (CAPABILITY_ACTION). */
    readonly action: PolicyAction;
    /** The capability's emitted logical resource identifier. */
    readonly resource: string;
    /** Workspace-relative config file that grants the capability. */
    readonly source: string;
    /** Human-readable statement of the power (the capability's own summary). */
    readonly summary: string;
}
/** Whether — and how — a policy governs this workspace. */
export type PolicyPosture = "absent" | "invalid" | "present";
/**
 * The rendered authorization-coverage view (report / --json / artifact /
 * watch). Additive JSON-serializable shape; consumers tolerate unknown fields
 * (ADR-003 evolution rule).
 */
export interface AuthorizationGapView {
    readonly policyStatus: PolicyPosture;
    /** The policy document this coverage was read against (for the copy). */
    readonly policyFile: string;
    readonly totalCapabilities: number;
    /** Capabilities named by at least one rule (totalCapabilities − gaps). */
    readonly governed: number;
    readonly gaps: readonly AuthorizationGap[];
}
/**
 * The pure core: given detected capabilities and the effective ruleset, return
 * every capability NO rule names, in capability order. `rules` is the evaluated
 * ruleset — `[]` for an absent or refused policy (both govern nothing). See the
 * module doc for the exact "covered" semantics.
 */
export declare function findAuthorizationGaps(capabilities: readonly Capability[], rules: readonly PolicyRule[]): AuthorizationGap[];
/**
 * Build the render-facing view from the loaded policy. The whole-set semantics
 * live HERE (ADR-009): only `ok` contributes rules; `absent` and `invalid`
 * both govern nothing, so every capability is a gap — the difference is
 * presentation (absent = "nothing governed yet"; invalid = "policy refused,
 * fix it"), which `policyStatus` carries. Pure — same inputs, same view.
 */
export declare function buildAuthorizationGapView(capabilities: readonly Capability[], policy: PolicyLoad): AuthorizationGapView;
