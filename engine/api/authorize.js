/**
 * Engine library — `authorize` capability (TEAM-ADR-027).
 *
 * MOVED here from the `deepsweep authorize` command layer, where the layered
 * policy load, the evaluation, the ADR-010 enforcement mapping and the
 * ADR-018 ledger append used to live inline. The Studio (over Tauri IPC), the
 * headless sidecar and the legacy CLI shim now share this one implementation,
 * so an explained decision cannot drift between surfaces.
 *
 * Identity discipline (ADR-005): `principal` is a neutral identifier carried
 * through to the evaluator. It is never compared to a magic value here — the
 * CLI's "none" sentinel is parsed at its composition root and arrives as null.
 */
import { resolve } from "node:path";
import { loadLayeredPolicy } from "../review/policy.js";
import { evaluate } from "../review/evaluate.js";
import { enforcementEffectFor } from "../review/enforce.js";
import { appendLedgerEntry } from "../review/ledger.js";
import { sha256Hex } from "../review/canonical.js";
/** Marker used when no rule matched and the policy's defaultEffect decided. */
export const DEFAULT_EFFECT_RULE_LABEL = "(none — defaultEffect)";
/**
 * Evaluate ONE policy decision and record it. Deterministic: posture,
 * attestation and drift enter at their bases so the answer is a pure function
 * of the policy layers and the query — never of transient workspace state.
 *
 * May throw PolicyRefusalError / LedgerRefusalError on `.deepsweep/`
 * containment violations (ADR-003 refusal class → exit 3 at the edges).
 */
export function authorizeAction(params) {
    const root = resolve(params.workspaceRoot);
    const layered = loadLayeredPolicy(root, params.userConfigRoot !== undefined ? { userConfigRoot: params.userConfigRoot } : {});
    const refusals = layered.refusals.map((r) => ({
        layer: r.layer,
        source: r.source,
        reason: r.reasons[0] ?? "nonconforming",
    }));
    const decision = evaluate(layered.policy, {
        principal: params.principal,
        agentType: null,
        action: params.action,
        resource: params.resource,
        // A pure policy query: posture/attestation/drift enter at their bases.
        postureScore: 100,
        attestation: "claimed",
        driftOutstanding: false,
    });
    // A refused PRIMARY layer (org/workspace) poisons the whole evaluation:
    // ADR-010 maps it to the safe default, never to allow.
    const primaryRefused = layered.refusals.some((r) => r.layer !== "user");
    const acted = enforcementEffectFor(decision.outcome, primaryRefused ? "invalid" : "ok");
    const ruleLabel = decision.policyRef === null ? DEFAULT_EFFECT_RULE_LABEL : decision.policyRef.name;
    // ADR-018/ADR-021: HASHES + outcome only — a cloud-bound record never
    // carries principal/action/resource VALUES (metadata-first invariant).
    const appended = appendLedgerEntry(root, "policy.decision", {
        principalHash: sha256Hex(decision.principal ?? ""),
        actionHash: sha256Hex(decision.action),
        resourceHash: sha256Hex(decision.resource),
        outcome: decision.outcome,
        rule: ruleLabel,
        mode: layered.mode,
    }, params.nowIso);
    const enforcing = layered.mode === "enforce";
    return {
        principal: decision.principal,
        action: decision.action,
        resource: decision.resource,
        explanation: decision.explanation,
        layersLoaded: layered.layersLoaded,
        mode: layered.mode,
        ruleLabel,
        outcome: decision.outcome,
        actedOn: enforcing ? acted : null,
        refusals,
        ledgerAppended: appended !== "corrupt",
        exitCode: enforcing ? (acted === "allow" ? 0 : acted === "require-approval" ? 3 : 4) : 0,
    };
}
