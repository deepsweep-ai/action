import { CAPABILITY_ACTION, matchesAction, matchesResource, policyRuleHash, } from "./policy.js";
import { agentTypeForSource, principalFor } from "./identity.js";
import { BASE_POSTURE } from "./score.js";
/**
 * Most-restrictive-wins severity (ADR-009): `deny > require-approval > observe
 * > allow`. Order-independence lives here — combination is a max over this
 * total order, never a first-match scan.
 */
const OUTCOME_RANK = {
    deny: 3,
    "require-approval": 2,
    observe: 1,
    allow: 0,
};
/**
 * The forward-note-a invariant, as a pure predicate S4.1 (E4) inherits:
 * `allow` is the ONLY broadening outcome. `observe` — the default outcome for
 * an unmatched action — is NON-PERMISSIVE (record-only), exactly like `deny`
 * and `require-approval`. An enforcement point may key permission on this
 * predicate and on nothing else; a contract test asserts observe is never
 * treated as a grant.
 */
export function isBroadeningOutcome(outcome) {
    return outcome === "allow";
}
const ATTESTATION_ORDER = {
    claimed: 0,
    "session-observed": 1,
};
/** A rule's optional condition (allow has no condition field — ADR-009 crux). */
function conditionOf(rule) {
    return "condition" in rule ? rule.condition : undefined;
}
/**
 * Principal-selector match against the FRESH-DERIVED context (ADR-005). `"*"`
 * matches any principal including a null (unattributed) one; `{agentId}` the
 * exact derived ID; `{agentType}` the derivation input. Dispatch is on the
 * selector's shape, never an authority branch on an identity value.
 */
function principalMatches(selector, ctx) {
    if (selector === "*")
        return true;
    if ("agentId" in selector) {
        // A narrowing-only selector match (ADR-009: narrowing variants may key on
        // any principal; grants nothing). Expressed as SET MEMBERSHIP — the same
        // sanctioned shape as identity.ts's `known.has(agentId)` — never a
        // `===`/switch authority branch on an identity value (ADR-005 containment
        // guard, tests/identity.test.ts AC5). The fresh-derived principal must be
        // present AND in the singleton set of the selector's accepted id.
        if (ctx.principal === null)
            return false;
        return new Set([selector.agentId]).has(ctx.principal);
    }
    return ctx.agentType !== null && selector.agentType === ctx.agentType;
}
/** One typed condition atom against the context (ADR-009 atoms, ANDed). */
function atomHolds(atom, ctx) {
    if ("postureBelow" in atom)
        return ctx.postureScore < atom.postureBelow; // integer compare (ADR-007)
    if ("attestationAtMost" in atom) {
        return ATTESTATION_ORDER[ctx.attestation] <= ATTESTATION_ORDER[atom.attestationAtMost];
    }
    return ctx.driftOutstanding === true;
}
/**
 * A rule is EFFECTIVE for a tuple when action + resource NAME it, the principal
 * selector matches the fresh-derived identity, and every condition atom holds
 * (absent condition = vacuously true). Reuses the ONE grammar matchers — the
 * decision engine and S3.3's coverage read never disagree on what a matcher
 * names.
 */
function ruleEffective(rule, ctx) {
    if (!matchesAction(rule.action, ctx.action))
        return false;
    if (!matchesResource(rule.resource, ctx.resource))
        return false;
    if (!principalMatches(rule.principal, ctx))
        return false;
    const condition = conditionOf(rule);
    if (condition !== undefined && !condition.every((atom) => atomHolds(atom, ctx)))
        return false;
    return true;
}
function refOf(rule) {
    return { name: rule.name, sha256: policyRuleHash(rule) };
}
/** Deterministic order for matched rules: most-restrictive first, then name. */
function compareMatched(a, b) {
    const byRank = OUTCOME_RANK[b.effect] - OUTCOME_RANK[a.effect];
    if (byRank !== 0)
        return byRank;
    // The trailing 0 (equal names) is unreachable for any VALIDATED PolicySet
    // (duplicate names are a whole-set refusal, ADR-009) — but PolicySet is
    // structural and evaluate() is exported, so a forged set reaches it at
    // runtime; the comparator stays total and the tie benign (pinned by test).
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}
/** Single-sourced human WHY over the decision fields (Principle 5). */
function buildExplanation(outcome, ctx, matched, decidingName) {
    const who = ctx.principal ?? "an unattributed source";
    const what = `${ctx.action} on ${ctx.resource}`;
    if (matched.length === 0) {
        if (outcome === "observe") {
            return `observe (default): no policy rule applies to ${what} for ${who} — recorded for review, grants nothing`;
        }
        // ADR-021: an operator-narrowed default (never allow — validation
        // forbids it). Same explainability contract, honest about the source.
        return `${outcome} (policy defaultEffect): no policy rule applies to ${what} for ${who} — the policy narrows its unmatched-action outcome`;
    }
    const why = matched.map((m) => `${m.name} (${m.effect}): ${m.rationale}`).join("; ");
    return `${outcome} for ${what} by ${who} — decided by rule "${decidingName}" (most-restrictive of ${matched.length} matched); ${why}`;
}
/**
 * The pure core (ADR-009): a deterministic PolicyDecision for one tuple.
 * Combines ALL effective rules by most-restrictive-wins; cites every matched
 * rule; defaults to a non-permissive `observe` with `policyRef: null` when no
 * rule is effective. No wall-clock, no fs read — order-independent by
 * construction (every emitted list is sorted).
 */
export function evaluate(policySet, ctx) {
    const effective = policySet.rules.filter((rule) => ruleEffective(rule, ctx));
    const matchedRules = effective
        .map((rule) => ({
        name: rule.name,
        effect: rule.effect,
        rationale: rule.rationale,
        policyRef: refOf(rule),
    }))
        .sort(compareMatched);
    if (matchedRules.length === 0) {
        // ADR-021: the unmatched outcome is the policy's defaultEffect when the
        // operator narrowed it (validation guarantees it is never "allow");
        // absent, the ADR-009 default-observe stands byte-identically — the
        // golden vectors pin that.
        const unmatched = policySet.defaultEffect ?? "observe";
        return {
            principal: ctx.principal,
            action: ctx.action,
            resource: ctx.resource,
            condition: null,
            outcome: unmatched,
            matchedRules: [],
            policyRef: null,
            explanation: buildExplanation(unmatched, ctx, [], null),
        };
    }
    // Winner: the highest-severity effect; ties broken by the deterministic sort
    // above, so the deciding rule is order-independent (first in matchedRules).
    const winner = matchedRules[0];
    const outcome = winner.effect;
    const decidingRule = effective.find((rule) => rule.name === winner.name);
    return {
        principal: ctx.principal,
        action: ctx.action,
        resource: ctx.resource,
        condition: conditionOf(decidingRule) ?? null,
        outcome,
        matchedRules,
        policyRef: winner.policyRef,
        explanation: buildExplanation(outcome, ctx, matchedRules, winner.name),
    };
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
export function buildDecisionView(capabilities, policy, workspace, postureByAgentType, driftOutstanding) {
    const policyStatus = policy.status === "ok" ? "present" : policy.status === "invalid" ? "invalid" : "absent";
    if (policy.status !== "ok")
        return { policyStatus, decisions: [] };
    const rules = policy.policy.rules;
    const decisions = [];
    capabilities.forEach((cap, capabilityIndex) => {
        const action = CAPABILITY_ACTION[cap.kind];
        const covered = rules.some((rule) => matchesAction(rule.action, action) && matchesResource(rule.resource, cap.resource));
        if (!covered)
            return; // an authorization gap — S3.3 renders it, not this view
        const agentType = agentTypeForSource(cap.source);
        const posture = agentType !== undefined && postureByAgentType.has(agentType)
            ? postureByAgentType.get(agentType)
            : BASE_POSTURE;
        const ctx = {
            principal: principalFor(cap.source, workspace) ?? null,
            agentType: agentType ?? null,
            action,
            resource: cap.resource,
            postureScore: posture,
            attestation: "claimed",
            driftOutstanding,
        };
        decisions.push({
            capabilityIndex,
            kind: cap.kind,
            summary: cap.summary,
            decision: evaluate(policy.policy, ctx),
        });
    });
    return { policyStatus, decisions };
}
/** Short version-pin for a policyRef in human renders (name + sha8). */
export function policyRefLabel(ref) {
    return `${ref.name}@${ref.sha256.slice(0, 8)}`;
}
/** Static tag for a decision outcome (shared by the render surfaces). */
export const OUTCOME_LABEL = {
    deny: "DENY",
    "require-approval": "REQUIRE-APPROVAL",
    observe: "OBSERVE",
    allow: "ALLOW",
};
