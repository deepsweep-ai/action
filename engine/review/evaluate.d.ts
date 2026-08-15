/**
 * S3.2 — Policy evaluation core (ADR-009, the BINDING contract).
 *
 * The deterministic, fully-explained, **ADVISORY** decision engine: given a
 * validated PolicySet and an evaluation context, it renders one PolicyDecision
 * per (principal, action, resource). It PRODUCES decisions — it does NOT
 * enforce, block, gate, or touch exit codes. Pre-E4 every decision is advisory
 * reporting (ADR-009 named hard gate on S4.1); this module deliberately trips
 * none of that gate.
 *
 * PURITY (ADR-009): evaluate is a pure function of (policy set, context). No
 * wall-clock, no fs read, no randomness inside evaluation — time and drift and
 * posture enter ONLY as explicit context inputs (the ADR excludes time-window
 * atoms from v1 precisely to keep this true). Same inputs → byte-identical
 * decision, so the permutation test (shuffled rule order) yields identical
 * output by construction.
 *
 * ORDER-INDEPENDENT, MOST-RESTRICTIVE-WINS (ADR-009): the decision for a tuple
 * is the combination of ALL effective rules by severity
 * `deny > require-approval > observe > allow`. Rule order in policy.json is
 * semantically meaningless — a git merge that reorders a file is a no-op by
 * contract. The explanation lists EVERY matched rule (not only the winner), and
 * every list this module emits is sorted deterministically, so permuting the
 * input rules cannot change a single output byte.
 *
 * OBSERVE IS RECORD-ONLY (ADR-009 decision 8 / round-2 N4 — forward-note a):
 * `observe` is a distinct, NON-PERMISSIVE outcome. `allow` is the ONLY
 * broadening outcome in v1 (`isBroadeningOutcome`); observe/deny/
 * require-approval grant nothing. S4.1 (the first consumer that ACTS on a
 * decision) inherits this by construction: an enforcement point may treat ONLY
 * `allow` as permission — an unmatched action defaults to `observe` and MUST
 * NOT fall through to permitted. A contract test pins that no code path here
 * equates observe with allow.
 *
 * DEFAULT-OBSERVE, NEVER SILENT (ADR-009): a tuple that no rule makes effective
 * evaluates to outcome `observe` with `policyRef: null`. Whether that tuple is
 * ALSO an authorization gap ("no rule NAMES this capability at all") is the
 * separate coverage question answered by authgap.ts (the shared "covered" read)
 * — reused here, never forked: `buildDecisionView` emits decisions only for
 * COVERED capabilities and leaves gaps to S3.3's view, so the two never
 * duplicate or contradict.
 *
 * FRESH-DERIVED PRINCIPAL (ADR-005): selectors resolve against a fresh-derived
 * identity (`principalFor` / `agentTypeForSource`), NEVER against the
 * agent-writable identity store. A tampered or absent identity.json cannot
 * change which rule matches — the store is explainability-only.
 *
 * Zero runtime dependencies. Reuses the ONE grammar matchers (`matchesAction`,
 * `matchesResource`), the ONE canonical rule hash (`policyRuleHash` over
 * canonical.ts), and the ONE capability→action table (`CAPABILITY_ACTION`) —
 * never a second semantics S3.3 or a validator would then contradict.
 */
import type { Capability, CapabilityKind } from "./types.js";
import type { ConditionAtom, ConditionAttestationTier, PolicyAction, PolicyLoad, PolicySet } from "./policy.js";
import type { AgentType } from "./identity.js";
import type { PolicyPosture } from "./authgap.js";
/**
 * A decision outcome (ADR-009 forward map). Identical vocabulary to a rule's
 * `effect`: the outcome a tuple resolves to. `allow` is the ONLY broadening
 * outcome; the other three are narrowing / record-only.
 */
export type PolicyOutcome = "deny" | "require-approval" | "observe" | "allow";
/**
 * The forward-note-a invariant, as a pure predicate S4.1 (E4) inherits:
 * `allow` is the ONLY broadening outcome. `observe` — the default outcome for
 * an unmatched action — is NON-PERMISSIVE (record-only), exactly like `deny`
 * and `require-approval`. An enforcement point may key permission on this
 * predicate and on nothing else; a contract test asserts observe is never
 * treated as a grant.
 */
export declare function isBroadeningOutcome(outcome: PolicyOutcome): boolean;
/**
 * A versioned citation for one rule (ADR-009 explainability): the rule's unique
 * `name` plus the SHA-256 of its canonicalized content (the ADR-003
 * canonicalizer, via `policyRuleHash`) — pinning WHICH VERSION of the rule
 * spoke, for the AuditEvent forward map.
 */
export interface PolicyRef {
    readonly name: string;
    readonly sha256: string;
}
/** One rule that was effective for a tuple (cited in the explanation). */
export interface MatchedRule {
    readonly name: string;
    /** The rule's effect === the outcome it contributed. */
    readonly effect: PolicyOutcome;
    /** The human "why" (ADR-009 required `rationale`). */
    readonly rationale: string;
    readonly policyRef: PolicyRef;
}
/**
 * The evaluation context (ADR-009 pure-function input). All identity fields are
 * FRESH-DERIVED by the caller (`principalFor` / `agentTypeForSource`), never
 * store-resolved. Posture is a Condition INPUT only (integer, ADR-007); drift
 * and attestation enter as explicit inputs — never read from a clock or fs
 * inside evaluation.
 */
export interface EvaluationContext {
    /** WHO — fresh-derived agentId, or null for an unattributed source. */
    readonly principal: string | null;
    /** The derivation input for the `{agentType}` selector (fresh-derived). */
    readonly agentType: AgentType | null;
    readonly action: PolicyAction;
    readonly resource: string;
    /** Integer posture score (0–100) for `postureBelow` atoms (ADR-007). */
    readonly postureScore: number;
    /** Attestation tier for `attestationAtMost` atoms (ADR-005; `claimed` in v0). */
    readonly attestation: ConditionAttestationTier;
    /** True when the run has unresolved pin.drift / pin.conflict / baseline.tampered. */
    readonly driftOutstanding: boolean;
}
/**
 * A fully-explained decision (ADR-009 forward map): every field a
 * who/what/why/policy/outcome explanation needs, plus the additive
 * `matchedRules` (every effective rule, not only the winner). A decision that
 * cannot explain itself is non-conforming (Principle 5).
 */
export interface PolicyDecision {
    /** WHO. */
    readonly principal: string | null;
    /** WHAT. */
    readonly action: PolicyAction;
    readonly resource: string;
    /** The deciding rule's condition atoms, if any (else null). */
    readonly condition: readonly ConditionAtom[] | null;
    /** The combined most-restrictive outcome. */
    readonly outcome: PolicyOutcome;
    /** POLICY (every matched rule) — deterministically sorted, order-independent. */
    readonly matchedRules: readonly MatchedRule[];
    /** POLICY (the winner) — the deciding rule's ref, or null (default-observe). */
    readonly policyRef: PolicyRef | null;
    /** WHY — single-sourced human sentence over the fields above. */
    readonly explanation: string;
}
/**
 * The pure core (ADR-009): a deterministic PolicyDecision for one tuple.
 * Combines ALL effective rules by most-restrictive-wins; cites every matched
 * rule; defaults to a non-permissive `observe` with `policyRef: null` when no
 * rule is effective. No wall-clock, no fs read — order-independent by
 * construction (every emitted list is sorted).
 */
export declare function evaluate(policySet: PolicySet, ctx: EvaluationContext): PolicyDecision;
/** A per-capability decision for the render surfaces (workspace-derived). */
export interface CapabilityDecision {
    readonly capabilityIndex: number;
    readonly kind: CapabilityKind;
    /** The capability's human summary (sanitized at every render boundary). */
    readonly summary: string;
    readonly decision: PolicyDecision;
}
/** The rendered advisory decision view (report / --json / artifact / watch). */
export interface DecisionView {
    readonly policyStatus: PolicyPosture;
    /** Decisions for COVERED capabilities only; gaps are S3.3's view. */
    readonly decisions: readonly CapabilityDecision[];
}
/**
 * Build the advisory decision view from the loaded policy. Whole-set semantics
 * (ADR-009): only an `ok` policy contributes rules — an absent or invalid
 * (whole-set-refused) policy governs nothing, so there are NO decisions (every
 * capability is an authorization gap in S3.3's view). Emits a decision only for
 * COVERED capabilities (reusing the shared matchers for the same coverage read
 * S3.3 uses), so decisions and gaps never duplicate. Pure and deterministic.
 *
 * @param postureByAgentType per-agent posture (ADR-007 composite) for
 *   `postureBelow` atoms; an unattributed capability has no measured agent
 *   posture, so it evaluates at BASE_POSTURE — posture conditions do not fire
 *   for it in v0 (an honest advisory limit, not a security decision).
 */
export declare function buildDecisionView(capabilities: readonly Capability[], policy: PolicyLoad, workspace: string, postureByAgentType: ReadonlyMap<string, number>, driftOutstanding: boolean): DecisionView;
/** Short version-pin for a policyRef in human renders (name + sha8). */
export declare function policyRefLabel(ref: PolicyRef): string;
/** Static tag for a decision outcome (shared by the render surfaces). */
export declare const OUTCOME_LABEL: Record<PolicyOutcome, string>;
