/**
 * 60-second AHA rendering of a ReviewReport (kb/team-norms.md rule 5).
 * Plain text, no color deps; IDE surfaces restyle later.
 *
 * Render-boundary hardening (S1.9): every interpolated field that can carry
 * attacker-influenced content (server names, commands, hook events, mount
 * paths, permission patterns…) routes through the single sanitization choke
 * point in sanitize.ts — no local strip/cap logic lives here. JSON output
 * stays raw-but-structured: JSON.stringify escapes control characters itself.
 */
import type { ReviewReport, Severity } from "./types.js";
import type { DriftFinding } from "./diff.js";
import type { BaselineProvenance } from "./baseline.js";
import type { DriftEvent } from "./events.js";
import type { AgentIdentityRecord } from "./identity.js";
import type { AgentTrustScore } from "./score.js";
import type { AuthorizationGapView } from "./authgap.js";
import type { DecisionView } from "./evaluate.js";
/** Static severity labels — shared with the artifact renderer (S1.6). */
export declare const SEV_LABEL: Record<Severity, string>;
/**
 * Error surface (CLI stderr). Error messages can echo workspace-derived text
 * (paths, labels) — they are a rendered surface like any other and pass
 * through the same choke point (S1.9).
 */
export declare function renderErrorLine(message: string): string;
/**
 * Machine-surface JSON renderer (ADR-DS-005): deep-sanitizing walk then
 * pretty JSON — the sanctioned way to print a structured value. Evidence
 * bundles are hashes/counts/enums by construction, but they still route
 * through the choke point so no future field can bypass it.
 */
export declare function renderJsonValue(value: unknown): string;
/**
 * Canonical machine surface (TEAM-ADR-027): the same deep-sanitizing walk as
 * renderJsonValue, then RFC 8785-style canonicalization — keys sorted, no
 * insignificant whitespace, byte-stable across runs and platforms.
 *
 * This is the ONLY sanctioned producer for the headless engine host's stdout:
 * the sidecar's consumers (the Governance Studio over IPC, and the CI runner)
 * hash and diff that stream, so key order is a contract, not a detail.
 * Added to the sanctioned render set deliberately — see the write-site guard
 * in tests/sanitize.test.ts.
 */
export declare function renderCanonicalJson(value: unknown): string;
/** Success/notice sibling of renderErrorLine — same choke point (ADR-022). */
export declare function renderNoticeLine(message: string): string;
/**
 * The `--json` one-shot surface (QA defect D3): the report + provenance are
 * deep-sanitized through the choke point's machine-surface walk
 * (sanitizeJsonValue, 512 cap); the drift array is appended OUTSIDE the walk
 * so ADR-004 event bytes are untouched by construction (they were sanitized
 * at buildEvent — eventIds are content-derived and byte-frozen).
 * This is the ONLY sanctioned producer for the JSON dump: the CLI must emit
 * it verbatim (per-write-site guard in tests/sanitize.test.ts).
 * Additive fields under schemaVersion 1 (ADR-003 evolution rule): consumers
 * must tolerate unknown fields.
 */
export declare function renderJsonReport(report: ReviewReport, baseline: BaselineProvenance, drift: DriftEvent[], identity?: readonly AgentIdentityRecord[], trust?: readonly AgentTrustScore[], authorization?: AuthorizationGapView, decisions?: DecisionView): string;
export declare function renderReport(r: ReviewReport): string;
/**
 * Agent identity section (S2.1, ADR-005): the attributed identity lines of
 * the one-shot text report. Every line uses the claimed-tier phrasing
 * ("agent claiming to be X") and disclosed attestation — claimed identity is
 * never presented as authenticated. All interpolated fields (agentType and
 * timestamps can arrive from the agent-writable identity store; workspace
 * basename is attacker-influenced) route through the S1.9 choke point.
 * `claimedOwner` is the TRANSIENT owner claim (ADR-005 F1): display here
 * only — callers must never pass it to persisted/emitted surfaces.
 */
export declare function renderIdentitySection(records: readonly AgentIdentityRecord[], claimedOwner?: string): string;
/**
 * Trust score section (S2.2, ADR-007): one composite line per attributed
 * identity, rendered ONLY through the single-sourced qualified copy (the
 * posture number never appears without its attestation qualifier), plus the
 * full decomposition inline — surfaces may summarize, but the full
 * decomposition is available in this same run's output. Ends with the
 * no-positive-assurance and honest-limit notes on every render. All
 * workspace-derived fields (agentType and factor explanations can carry
 * gap summaries / protection rules / store fields) route through the S1.9
 * choke point.
 */
export declare function renderTrustSection(scores: readonly AgentTrustScore[]): string;
/**
 * Authorization coverage section (S3.3, ADR-009 default-observe): the
 * 60-second read of which detected capabilities are GOVERNED by policy vs
 * which are open authorization gaps. NOT a decision (no allow/deny), NOT an
 * exit-code input — an advisory read of `.deepsweep/policy.json` against this
 * run's findings. Rendered PROPORTIONATELY: a policy-less workspace shows one
 * honest summary line ("N capabilities, 0 governed"), never one screaming line
 * per capability; a partial policy lists the specific gaps, which are the
 * actionable holes. Every workspace-derived field (capability summary,
 * resource, source) routes through the S1.9 choke point (norm 9).
 */
export declare function renderAuthorizationSection(view: AuthorizationGapView): string;
/**
 * Policy decisions section (S3.2, ADR-009 order-independent
 * most-restrictive-wins): the advisory per-capability decision — allow / deny /
 * require-approval / observe — for each capability a committed policy GOVERNS,
 * with the deciding rule + version-pinned policyRef and every matched rule.
 * ADVISORY only: this is a rendered VIEW, never enforced, never an exit-code
 * input; `observe` is record-only (never a grant). Gaps (capabilities no rule
 * names) are shown by the authorization-coverage section, not here — the two
 * never duplicate. Every workspace-derived field (capability summary, resource,
 * rationale) routes through the S1.9 choke point (norm 9).
 */
export declare function renderDecisionSection(view: DecisionView): string;
/**
 * Baseline provenance + drift section (ADR-003 threat-note mitigations 1+2):
 * every report discloses createdAt / lastPinnedAt / entity count / the
 * baseline file's read-time SHA-256, and the absence of drift findings is
 * NEVER phrased as positive assurance — the baseline is agent-writable.
 */
export declare function renderBaselineSection(provenance: BaselineProvenance, findings: DriftFinding[], repinned: boolean): string;
/**
 * ADR-021 — the `deepsweep authorize` decision block (sanctioned render
 * surface: ALL argument-derived fields pass the S1.9 choke point here, so
 * the CLI writes exactly one render call). Deterministic: same inputs,
 * byte-identical output.
 */
export declare function renderAuthorizeDecision(input: {
    who: string | null;
    action: string;
    resource: string;
    explanation: string;
    layers: readonly string[];
    mode: string;
    ruleLabel: string;
    outcome: string;
    actedOn: string | null;
}): string;
