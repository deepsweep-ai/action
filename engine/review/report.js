import { BASELINE_REL_PATH } from "./baseline.js";
import { claimedIdentityClaim } from "./identity.js";
import { BASE_POSTURE, factorLine, POSTURE_ASSURANCE_NOTE, POSTURE_HONEST_LIMIT_NOTE, qualifiedPostureLine, } from "./score.js";
import { OUTCOME_LABEL, policyRefLabel } from "./evaluate.js";
import { sanitizeField, sanitizeFieldKeepEnding, sanitizeJsonValue } from "./sanitize.js";
import { canonicalize } from "./canonical.js";
import { countNoun } from "./text.js";
/** Static severity labels — shared with the artifact renderer (S1.6). */
export const SEV_LABEL = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    warning: "WARNING",
    info: "INFO",
};
/**
 * Error surface (CLI stderr). Error messages can echo workspace-derived text
 * (paths, labels) — they are a rendered surface like any other and pass
 * through the same choke point (S1.9).
 */
export function renderErrorLine(message) {
    return `deepsweep: ${sanitizeField(message)}`;
}
/**
 * Machine-surface JSON renderer (ADR-DS-005): deep-sanitizing walk then
 * pretty JSON — the sanctioned way to print a structured value. Evidence
 * bundles are hashes/counts/enums by construction, but they still route
 * through the choke point so no future field can bypass it.
 */
export function renderJsonValue(value) {
    return JSON.stringify(sanitizeJsonValue(value), null, 2);
}
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
export function renderCanonicalJson(value) {
    return canonicalize(sanitizeJsonValue(value));
}
/** Success/notice sibling of renderErrorLine — same choke point (ADR-022). */
export function renderNoticeLine(message) {
    return `deepsweep: ${sanitizeField(message)}`;
}
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
export function renderJsonReport(report, baseline, drift, identity, trust, authorization, decisions) {
    // Identity rides INSIDE the sanitizing walk (records come from the
    // agent-writable identity store — ADR-005 threat note) as an additive
    // field under schemaVersion 1. Attestation + the "agent claiming to be X"
    // phrasing are disclosed per record (ADR-005: no surface presents claimed
    // identity as authenticated). The transient claimed owner (ADR-005 F1)
    // never enters this function.
    //
    // Trust score (S2.2, ADR-007 N5): serialized ONLY as the composite object
    // nested per identity record — never a top-level or bare numeric field —
    // accompanied by the pre-rendered qualified string (single-sourced copy),
    // the no-positive-assurance note, and the honest-limit note. CI consumers
    // diffing scores across runs MUST assert equal scoreVersion first.
    const trustFor = new Map((trust ?? []).map((t) => [t.agentId, t.trustScore]));
    const composite = (ts) => ts === undefined
        ? {}
        : {
            trustScore: {
                ...ts,
                qualified: qualifiedPostureLine(ts),
                assurance: POSTURE_ASSURANCE_NOTE,
                honestLimit: POSTURE_HONEST_LIMIT_NOTE,
            },
        };
    const identitySection = identity === undefined
        ? {}
        : {
            identity: {
                attestation: "claimed",
                agents: identity.map((r) => ({
                    ...r,
                    claim: claimedIdentityClaim(r.agentType),
                    ...composite(trustFor.get(r.agentId)),
                })),
            },
        };
    // Authorization coverage (S3.3, ADR-009 default-observe): the governed-vs-gap
    // view rides INSIDE the sanitizing walk (summaries/resources/sources are
    // workspace-derived) as an additive field under schemaVersion 1. NOT a
    // decision and NOT an exit-code input — an advisory read of policy against
    // findings.
    const authorizationSection = authorization === undefined ? {} : { authorization };
    // Policy decisions (S3.2, ADR-009): the advisory per-capability decision view
    // rides INSIDE the sanitizing walk (summaries/resources/rationales are
    // workspace-derived) as an additive field under schemaVersion 1. ADVISORY —
    // never a decision that is ACTED on, never an exit-code input; `observe` is
    // record-only (never `allow`).
    const decisionsSection = decisions === undefined ? {} : { policyDecisions: decisions };
    return JSON.stringify({
        ...sanitizeJsonValue({
            ...report,
            baseline,
            ...identitySection,
            ...authorizationSection,
            ...decisionsSection,
        }),
        drift,
    }, null, 2);
}
export function renderReport(r) {
    const s = sanitizeField;
    const lines = [];
    lines.push("DeepSweep — Agent Environment Review");
    lines.push("=".repeat(52));
    if (r.capabilities.length === 0) {
        lines.push("No agent capabilities detected in this workspace.");
        lines.push(`Sources reviewed: ${r.reviewedSources.length ? r.reviewedSources.map(s).join(", ") : "none found"}`);
        pushWarnings(lines, r);
        return lines.join("\n");
    }
    lines.push("");
    lines.push("Your AI agents currently have:");
    for (const c of r.capabilities) {
        lines.push(`  • ${s(c.summary)}   [${s(c.source)}]`);
    }
    lines.push("");
    lines.push(`Boundary gaps found: ${r.totals.boundaryGaps} (${r.totals.critical} critical, ${r.totals.high} high)`);
    for (const g of r.boundaryGaps) {
        lines.push(`  [${SEV_LABEL[g.severity]}] ${s(g.summary)}`);
        lines.push(`     → Recommended protection: ${s(g.recommendation)}`);
    }
    pushWarnings(lines, r);
    lines.push("");
    lines.push("Which AI agent is doing what — and should it be allowed to?");
    // External-audience copy only (user-facing-content-integrity): user-visible
    // benefit + next action — no internal repo paths or roadmap pointers.
    lines.push("Next: open the Governance Studio to watch this environment for drift as it happens and turn these gaps into policy.");
    return lines.join("\n");
}
function pushWarnings(lines, r) {
    if (r.warnings.length === 0)
        return;
    lines.push("");
    lines.push("Review warnings:");
    for (const w of r.warnings) {
        // Keep-ending sanitizer (S1.12): pin warnings end with their remediation
        // ("Review the value directly when re-pinning", "prefer env…", "move
        // secrets to env/headers…") and realistic server/key names push the
        // endpoint-shaped-key copy past the 200-char human cap — middle-truncate
        // so the actionable ending survives.
        lines.push(`  ! ${sanitizeFieldKeepEnding(w.summary)}`);
    }
}
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
export function renderIdentitySection(records, claimedOwner) {
    const s = sanitizeField;
    const lines = [];
    lines.push("Agent identity (claimed from workspace config — not verified):");
    if (records.length === 0) {
        lines.push("  No agent config surfaces observed — nothing to attribute in this workspace.");
    }
    else {
        for (const r of records) {
            lines.push(`  • ${s(r.agentId)} — ${s(claimedIdentityClaim(r.agentType))} · first observed ${s(r.firstObservedAt)} · attestation: ${s(r.attestation)}`);
        }
    }
    if (claimedOwner !== undefined) {
        lines.push(`  Claimed owner (git user.email — shown for this run only, never stored): ${s(claimedOwner)}`);
    }
    return lines.join("\n");
}
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
export function renderTrustSection(scores) {
    const s = sanitizeField;
    const lines = [];
    lines.push(`Trust score (composite, per claimed identity — scoreVersion ${scores[0]?.trustScore.scoreVersion ?? 1}):`);
    if (scores.length === 0) {
        lines.push("  No attributed agent identities to score in this workspace.");
    }
    else {
        for (const a of scores) {
            lines.push(`  • ${s(a.agentId)} — ${s(claimedIdentityClaim(a.agentType))}`);
            lines.push(`    ${s(qualifiedPostureLine(a.trustScore))}`);
            lines.push(`    Decomposition (base ${BASE_POSTURE}; integer deltas sum exactly to the score):`);
            if (a.trustScore.decomposition.length === 0) {
                lines.push("      (no factors — base posture unchanged)");
            }
            for (const f of a.trustScore.decomposition) {
                // Keep-ending sanitizer (S1.12): protection.anchored factor lines
                // carry two workspace-derived summaries and END with the ADR-007
                // honest-limit disclosure ("structural presence only, runtime
                // efficacy not verified") — realistic summaries push the line past
                // the 200-char cap, and tail truncation cut that disclosure.
                lines.push(`      ${sanitizeFieldKeepEnding(factorLine(f))}`);
            }
        }
    }
    lines.push(`  ${s(POSTURE_ASSURANCE_NOTE)}`);
    lines.push(`  ${s(POSTURE_HONEST_LIMIT_NOTE)}`);
    return lines.join("\n");
}
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
export function renderAuthorizationSection(view) {
    const s = sanitizeField;
    const caps = (n) => countNoun(n, "capability", "capabilities");
    const lines = [];
    lines.push(`Authorization coverage (policy: ${s(view.policyFile)}):`);
    if (view.totalCapabilities === 0) {
        lines.push("  No agent capabilities detected — nothing to govern yet.");
        return lines.join("\n");
    }
    if (view.policyStatus === "absent") {
        // Proportionate honest state: the summary, not N findings.
        lines.push(`  ${caps(view.totalCapabilities)} detected, 0 governed by policy — no ${s(view.policyFile)} yet.`);
        lines.push("  DeepSweep sees what your agents CAN do; no policy yet says whether it is allowed. Author a policy to govern them.");
        return lines.join("\n");
    }
    if (view.policyStatus === "invalid") {
        lines.push(`  Policy was refused (see the policy.invalid finding) — no rule is evaluated, so all ${caps(view.totalCapabilities)} are authorization gaps until it is fixed.`);
        return lines.join("\n");
    }
    // present
    lines.push(`  ${view.governed} of ${caps(view.totalCapabilities)} governed by policy · ${countNoun(view.gaps.length, "authorization gap", "authorization gaps")}.`);
    if (view.gaps.length === 0) {
        lines.push("  Every detected capability is named by a policy rule.");
    }
    else {
        for (const g of view.gaps) {
            lines.push(`  [GAP] ${s(g.summary)} — action ${s(g.action)}, resource ${s(g.resource)} [${s(g.source)}]: no policy rule names this capability.`);
        }
    }
    return lines.join("\n");
}
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
export function renderDecisionSection(view) {
    const s = sanitizeField;
    const lines = [];
    lines.push(`Policy decisions (advisory — ${POLICY_DECISION_NOTE}):`);
    if (view.policyStatus !== "present") {
        lines.push("  No committed policy governs any capability yet — see authorization coverage above.");
        return lines.join("\n");
    }
    if (view.decisions.length === 0) {
        lines.push("  No governed capabilities to decide on (every capability is an authorization gap).");
        return lines.join("\n");
    }
    for (const d of view.decisions) {
        const dec = d.decision;
        if (dec.matchedRules.length === 0) {
            // Covered by a rule that does not APPLY to this principal/posture →
            // default observe (record-only). Distinct from an authorization gap.
            lines.push(`  [${OUTCOME_LABEL[dec.outcome]}] ${s(d.summary)} — action ${s(dec.action)}, resource ${s(dec.resource)}: governed, but no rule applies to this principal/condition — defaults to observe (record-only, grants nothing).`);
            continue;
        }
        const matched = dec.matchedRules.map((m) => s(policyRefLabel(m.policyRef))).join(", ");
        lines.push(`  [${OUTCOME_LABEL[dec.outcome]}] ${s(d.summary)} — action ${s(dec.action)}, resource ${s(dec.resource)}: decided by ${s(policyRefLabel(dec.policyRef))}; matched ${matched}.`);
        // The single-sourced WHY (rationales of every matched rule) on its own line.
        lines.push(`     why: ${sanitizeFieldKeepEnding(dec.explanation)}`);
    }
    return lines.join("\n");
}
/** Single-sourced external copy for the decision section's advisory framing. */
const POLICY_DECISION_NOTE = ".deepsweep/policy.json, most-restrictive-wins; never enforced, never a grant";
/**
 * Baseline provenance + drift section (ADR-003 threat-note mitigations 1+2):
 * every report discloses createdAt / lastPinnedAt / entity count / the
 * baseline file's read-time SHA-256, and the absence of drift findings is
 * NEVER phrased as positive assurance — the baseline is agent-writable.
 */
export function renderBaselineSection(provenance, findings, repinned) {
    const s = sanitizeField;
    const lines = [];
    lines.push(`Baseline (${BASELINE_REL_PATH} — local, agent-writable):`);
    lines.push(`  Pinned entities: ${provenance.entityCount} · created ${s(provenance.createdAt)} · last pinned ${s(provenance.lastPinnedAt)}`);
    lines.push(`  File sha256 (computed at read time): ${s(provenance.baselineSha256)}`);
    if (repinned) {
        lines.push("  Baseline explicitly re-pinned this run (--update-baseline).");
    }
    const drift = findings.filter((f) => f.kind === "pin.drift" || f.kind === "pin.conflict");
    const lifecycle = findings.filter((f) => f.kind !== "pin.drift" && f.kind !== "pin.conflict");
    for (const f of lifecycle) {
        // Keep-ending sanitizer (S1.12, the S2.1 QA P4 defect): the
        // identity.regenerated explanation is 254–267 chars and its remediation
        // ("re-review before continuing to trust attribution…") is the ENDING —
        // tail truncation at the 200-char human cap cut it mid-sentence.
        lines.push(`  [${SEV_LABEL[f.severity]}] ${f.kind}: ${sanitizeFieldKeepEnding(f.explanation)}`);
    }
    if (drift.length === 0) {
        lines.push("  No drift detected against the local baseline. The baseline is agent-writable — this is not positive assurance; verify the provenance above.");
    }
    else {
        for (const f of drift) {
            // Keep-ending sanitizer (QA defect D2): pin.drift explanations end with
            // the remediation ("re-pin via --update-baseline") — middle-truncate so
            // the actionable ending survives the human-render cap.
            lines.push(`  [${SEV_LABEL[f.severity]}] ${f.kind} ${s(f.resource)} — ${sanitizeFieldKeepEnding(f.explanation)}`);
        }
    }
    return lines.join("\n");
}
/**
 * ADR-021 — the `deepsweep authorize` decision block (sanctioned render
 * surface: ALL argument-derived fields pass the S1.9 choke point here, so
 * the CLI writes exactly one render call). Deterministic: same inputs,
 * byte-identical output.
 */
export function renderAuthorizeDecision(input) {
    const s = sanitizeField;
    const outcomeLine = input.actedOn === null
        ? `outcome:  ${s(input.outcome)} (observe mode: recorded, not acted on)`
        : `outcome:  ${s(input.outcome)} → acted-on ${s(input.actedOn)}`;
    return [
        `who:      ${s(input.who ?? "unattributed")}`,
        `what:     ${s(input.action)} on ${s(input.resource)}`,
        `why:      ${s(input.explanation)}`,
        `policy:   layers ${s(input.layers.join("+") || "(none)")} · mode ${s(input.mode)} · matched rule ${s(input.ruleLabel)}`,
        outcomeLine,
    ].join("\n");
}
