import type { PolicyAction, PolicyMode } from "../review/policy.js";
import type { PolicyOutcome } from "../review/evaluate.js";
import type { EnforcementEffect } from "../review/enforce.js";
export interface AuthorizeParams {
    readonly workspaceRoot: string;
    /** Neutral identifier; null = unattributed (ADR-021 "none"). */
    readonly principal: string | null;
    readonly action: PolicyAction;
    readonly resource: string;
    /** ADR-014 user-scope config root, injected by the composition root. */
    readonly userConfigRoot?: string;
    /** Injected clock (determinism invariant). */
    readonly nowIso: string;
}
/** One refused policy layer — the layer contributed ZERO rules (fail-closed). */
export interface AuthorizeLayerRefusal {
    readonly layer: string;
    readonly source: string;
    readonly reason: string;
}
export interface AuthorizeResult {
    readonly principal: string | null;
    readonly action: PolicyAction;
    readonly resource: string;
    readonly explanation: string;
    readonly layersLoaded: readonly string[];
    readonly mode: PolicyMode;
    /** Deciding rule name, or the defaultEffect marker when no rule matched. */
    readonly ruleLabel: string;
    readonly outcome: PolicyOutcome;
    /** ADR-010 acted-on effect; null in observe mode (computed, never blocking). */
    readonly actedOn: EnforcementEffect | null;
    readonly refusals: readonly AuthorizeLayerRefusal[];
    /** Whether the metadata-only decision record was appended to the ledger. */
    readonly ledgerAppended: boolean;
    /**
     * ADR-021 exit vocabulary: 0 allow (or observe mode) · 3 require-approval
     * (incl. the ADR-010 safe default over a refused primary layer) · 4 deny.
     */
    readonly exitCode: 0 | 3 | 4;
}
/** Marker used when no rule matched and the policy's defaultEffect decided. */
export declare const DEFAULT_EFFECT_RULE_LABEL = "(none \u2014 defaultEffect)";
/**
 * Evaluate ONE policy decision and record it. Deterministic: posture,
 * attestation and drift enter at their bases so the answer is a pure function
 * of the policy layers and the query — never of transient workspace state.
 *
 * May throw PolicyRefusalError / LedgerRefusalError on `.deepsweep/`
 * containment violations (ADR-003 refusal class → exit 3 at the edges).
 */
export declare function authorizeAction(params: AuthorizeParams): AuthorizeResult;
