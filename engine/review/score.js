import { agentTypeForSource } from "./identity.js";
/** Formula version (ADR-007). Bumps on ANY output-altering change. */
export const SCORE_VERSION = 1;
/** The version's defined base every decomposition sums from. */
export const BASE_POSTURE = 100;
// ------------------------------------------------------------------ copy
/**
 * The ONE place the qualified posture copy is defined (ADR-007 normative
 * rule: the posture number is NEVER rendered without its attestation
 * qualifier — the claimedIdentityClaim pattern). Every surface renders this
 * copy through its S1.9 sanitizer.
 */
export function qualifiedPostureLine(score) {
    const band = postureBand(score.postureScore, score.attestation);
    return `posture ${score.postureScore}/100 (${band} posture) — identity ${score.attestation}, not verified`;
}
/**
 * No-positive-assurance phrasing (ADR-007 presentation rules), single-sourced
 * for every surface: a high posture score is never a safety certification.
 */
export const POSTURE_ASSURANCE_NOTE = "Posture reflects protections observed in the local, agent-writable environment at review time — never a safety certification, never identity verification.";
/**
 * The honest-limit note (ADR-007 carry-forward 3): v0 credits the STRUCTURAL
 * PRESENCE of capability-anchored protections, not verified runtime efficacy
 * (verification of enforcement is E4+ scope).
 */
export const POSTURE_HONEST_LIMIT_NOTE = "Protection credits reflect the structural presence of capability-anchored protections, not verified runtime efficacy.";
/**
 * Single-sourced human render of one decomposition entry (report text, watch
 * header, artifact all use it — through their own S1.9 sanitizers).
 */
export function factorLine(f) {
    const refs = [f.findingRef, f.protectionRef, f.anchorRef]
        .filter((r) => r !== undefined)
        .join(" → ");
    const sign = f.delta < 0 ? "" : "+";
    return `${sign}${f.delta} ${f.factor} [${f.scope}]${refs === "" ? "" : ` ${refs}`} — ${f.explanation}`;
}
/**
 * Presentation band with the ADR-007 tier ceiling: the top band is
 * STRUCTURALLY unreachable for any identity below `verified-signed` — a
 * claimed identity with perfect posture reads at best "good". (Only
 * `claimed` exists in v0; the ceiling is written against the tier name so
 * the construction survives the additive attestation enum.)
 */
const TOP_BAND_MINIMUM_ATTESTATION = "verified-signed";
export function postureBand(postureScore, attestation) {
    const uncapped = postureScore >= 90 ? "strong" : postureScore >= 70 ? "good" : postureScore >= 40 ? "fair" : "weak";
    if (uncapped === "strong" && attestation !== TOP_BAND_MINIMUM_ATTESTATION)
        return "good";
    return uncapped;
}
// --------------------------------------------------------------- weights
const GAP_DELTAS = {
    critical: -25,
    high: -15,
    medium: -8,
    warning: -4,
    info: -2,
};
const PROTECTION_CREDIT = 5;
const FINDING_DELTAS = {
    "pin.drift": -10,
    "pin.conflict": -10,
    "baseline.regenerated": -10,
    "baseline.tampered": -20,
    "identity.regenerated": -5,
    // ADR-018: a corrupt audit ledger is a tamper-evidence signal (same tier
    // as baseline.regenerated). Conservative extension: the kind could not
    // occur pre-ADR-018, so scoreVersion stays 1 (ADR-011 precedent).
    "ledger.corrupt": -10,
    // Identity lifecycle gaps (ADR-011): deltas mirror GAP_DELTAS for the
    // detector's own severity tier, so lifecycle posture costs stay consistent
    // with boundary-gap costs. Sourced from .deepsweep/identity.json, so scope
    // resolves workspace-shared (the registry is a workspace store).
    "identity.missingOwner": -15,
    "identity.staleIdentity": -15,
    "identity.indefiniteLifetime": -8,
    "identity.lifetimeExpired": -25,
    "identity.zombieActivity": -25,
    // baseline.created / capability.* / gap.* carry no posture delta: the
    // report's gaps already carry the posture, and creation is not drift.
};
/** ADR-007 F2 runtime guard: a non-integer on the score path fail-stops. */
function assertInt(value, label) {
    if (!Number.isInteger(value)) {
        throw new Error(`posture arithmetic must be integer-only (ADR-007 F2): ${label} = ${value}`);
    }
    return value;
}
// ----------------------------------------------------------- attribution
/**
 * The agent type that OWNS a boundary gap: defined only when every related
 * capability comes from that one agent's config surfaces (via
 * agentTypeForSource); otherwise the gap is workspace-shared.
 */
function gapOwner(gap, report) {
    const owners = new Set();
    for (const i of gap.relatedCapabilities) {
        owners.add(agentTypeForSource(report.capabilities[i]?.source ?? ""));
    }
    if (owners.size !== 1)
        return undefined;
    const [only] = owners;
    return only;
}
// -------------------------------------------------------------- compute
/**
 * Compute the Trust score composite for every attributed identity record.
 * Deterministic and pure: output ordering is fully sorted (records by
 * agentId; decomposition by factor/scope/refs, clamp entry last), with no
 * wall-clock inputs. Cross-version rule (ADR-007): consumers MUST assert
 * equal `scoreVersion` before comparing two composites; an unknown version
 * is unknown, not comparable.
 */
export function computeTrustScores(input) {
    const { report, findings, identityRecords } = input;
    const shared = [];
    const owned = new Map();
    const add = (owner, entry) => {
        assertInt(entry.delta, entry.factor);
        if (owner === undefined) {
            shared.push(entry);
        }
        else {
            const list = owned.get(owner) ?? [];
            list.push(entry);
            owned.set(owner, list);
        }
    };
    // Boundary gaps: severity-weighted deductions, each citing its report index.
    report.boundaryGaps.forEach((gap, i) => {
        const owner = gapOwner(gap, report);
        add(owner, {
            factor: `gap.${gap.severity}`,
            scope: owner === undefined ? "workspace-shared" : "agent-owned",
            delta: GAP_DELTAS[gap.severity],
            findingRef: `boundaryGaps[${i}]`,
            explanation: `Boundary gap (${gap.severity}): ${gap.summary}`,
        });
    });
    // Capability-anchored protection credits (ADR-007 F1): credit ONLY when an
    // independently-detected capability of the constrained kind exists in this
    // run; inert protections earn zero and are omitted. At most one credit per
    // (owner, constrained kind) — redundant stacking earns nothing.
    const credited = new Set();
    (report.protections ?? []).forEach((p, i) => {
        const owner = agentTypeForSource(p.source);
        // Anchor selection (deterministic): the first capability of the
        // constrained kind owned by the protection's own agent, else the first
        // of that kind in the run — same-run anchoring is what F1 requires;
        // same-agent is preferred purely for explainability.
        // ADR-014 self-anchor exclusion: hook-command capabilities never anchor
        // credit — a hook constraining tool calls must not be credited against
        // the shellExecution capability that IS its own command (and hook
        // commands are not tool calls, so no protection governs them).
        const candidates = report.capabilities
            .map((c, j) => ({ c, j }))
            .filter(({ c }) => c.kind === p.constrains && c.detail?.["hook"] === undefined);
        if (candidates.length === 0)
            return; // nothing to constrain — zero credit
        const anchorIndex = (candidates.find(({ c }) => agentTypeForSource(c.source) === owner) ?? candidates[0]).j;
        const key = `${owner ?? ""}\u0000${p.constrains}`;
        if (credited.has(key))
            return; // redundant protection — zero credit
        credited.add(key);
        const anchor = report.capabilities[anchorIndex];
        add(owner, {
            factor: "protection.anchored",
            scope: owner === undefined ? "workspace-shared" : "agent-owned",
            delta: PROTECTION_CREDIT,
            protectionRef: `protections[${i}]`,
            anchorRef: `capabilities[${anchorIndex}]`,
            explanation: `Protection constrains a detected ${p.constrains} capability: ${p.summary} (anchored to: ${anchor?.summary ?? p.constrains}) — structural presence only, runtime efficacy not verified`,
        });
    });
    // Outstanding lifecycle/drift findings (sticky findings stay sticky here).
    for (const f of findings) {
        const delta = FINDING_DELTAS[f.kind];
        if (delta === undefined)
            continue;
        const owner = agentTypeForSource(f.source);
        add(owner, {
            factor: `finding.${f.kind}`,
            scope: owner === undefined ? "workspace-shared" : "agent-owned",
            delta,
            findingRef: `finding:${f.kind}:${f.resource}`,
            explanation: `Outstanding ${f.kind} finding on ${f.resource}`,
        });
    }
    // Assemble one composite per identity record: workspace-shared factors
    // apply to all agents; agent-owned factors apply to their agent only.
    return [...identityRecords]
        .sort((a, b) => (a.agentId < b.agentId ? -1 : a.agentId > b.agentId ? 1 : 0))
        .map((record) => {
        const decomposition = [...shared, ...(owned.get(record.agentType) ?? [])].sort(compareFactors);
        let raw = BASE_POSTURE;
        for (const f of decomposition)
            raw += assertInt(f.delta, f.factor);
        assertInt(raw, "raw posture");
        const postureScore = raw < 0 ? 0 : raw > 100 ? 100 : raw;
        if (postureScore !== raw) {
            // Reconciliation entry: keeps deltas-sum-exactly true BY ARITHMETIC
            // when the bounded score departs from the raw sum. Always last.
            decomposition.push({
                factor: "range.clamp",
                scope: "workspace-shared",
                delta: assertInt(postureScore - raw, "range.clamp"),
                explanation: `Posture score is bounded to 0-100; this entry reconciles the decomposition sum (raw ${raw}) to the bounded score (${postureScore}).`,
            });
        }
        return {
            agentId: record.agentId,
            agentType: record.agentType,
            trustScore: {
                attestation: record.attestation,
                postureScore: assertInt(postureScore, "postureScore"),
                scoreVersion: SCORE_VERSION,
                decomposition,
            },
        };
    });
}
/** Full deterministic ordering for decomposition entries. */
function compareFactors(a, b) {
    const key = (f) => [f.factor, f.scope, f.findingRef ?? "", f.protectionRef ?? "", f.anchorRef ?? "", f.explanation].join("\u0000");
    const ka = key(a);
    const kb = key(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
}
