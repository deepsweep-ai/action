import { CAPABILITY_ACTION, matchesAction, matchesResource, POLICY_REL_PATH } from "./policy.js";
/**
 * The pure core: given detected capabilities and the effective ruleset, return
 * every capability NO rule names, in capability order. `rules` is the evaluated
 * ruleset — `[]` for an absent or refused policy (both govern nothing). See the
 * module doc for the exact "covered" semantics.
 */
export function findAuthorizationGaps(capabilities, rules) {
    const gaps = [];
    capabilities.forEach((cap, capabilityIndex) => {
        const action = CAPABILITY_ACTION[cap.kind];
        const covered = rules.some((rule) => matchesAction(rule.action, action) && matchesResource(rule.resource, cap.resource));
        if (!covered) {
            gaps.push({
                capabilityIndex,
                kind: cap.kind,
                action,
                resource: cap.resource,
                source: cap.source,
                summary: cap.summary,
            });
        }
    });
    return gaps;
}
/**
 * Build the render-facing view from the loaded policy. The whole-set semantics
 * live HERE (ADR-009): only `ok` contributes rules; `absent` and `invalid`
 * both govern nothing, so every capability is a gap — the difference is
 * presentation (absent = "nothing governed yet"; invalid = "policy refused,
 * fix it"), which `policyStatus` carries. Pure — same inputs, same view.
 */
export function buildAuthorizationGapView(capabilities, policy) {
    const rules = policy.status === "ok" ? policy.policy.rules : [];
    const gaps = findAuthorizationGaps(capabilities, rules);
    const policyStatus = policy.status === "ok" ? "present" : policy.status === "invalid" ? "invalid" : "absent";
    return {
        policyStatus,
        policyFile: POLICY_REL_PATH,
        totalCapabilities: capabilities.length,
        governed: capabilities.length - gaps.length,
        gaps,
    };
}
