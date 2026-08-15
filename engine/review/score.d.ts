/**
 * S2.2 — Trust score v0 (ADR-007, the BINDING contract for this module).
 *
 * The Trust score is the COMPOSITE `{ attestation, postureScore,
 * scoreVersion, decomposition }` — no scalar trust score exists in any API,
 * artifact, or surface, and no code path may collapse the composite into a
 * bare number (the no-laundering rule). The numeric component is the
 * POSTURE SCORE (0–100 integer): it measures exactly one thing — the
 * reviewed environment's protection posture — and identity confidence is
 * carried ONLY by the `attestation` tier riding alongside it.
 *
 * Pure function, in core: no I/O, no wall clock, no randomness. Same
 * environment → byte-identical composite including decomposition ordering.
 *
 * Inputs (v0, ADR-007): DeepSweep's OWN findings from the current run —
 * boundary gaps (severity-weighted), capability-anchored protection credits,
 * and outstanding baseline/identity lifecycle findings. Excluded,
 * normatively: behavioral history (S2.3), cloud data (ADR-001), workspace
 * self-assertions, and the transient owner claim (ADR-005 F1).
 *
 * Capability-anchored crediting (ADR-007 F1, binding): a protection earns
 * posture credit ONLY when an independently-detected capability of its
 * `constrains` kind exists in the same run. A protection with nothing to
 * constrain earns ZERO (and is omitted from the decomposition — inert
 * configs cannot inflate posture). Anchors are independent by construction:
 * detectors never derive capabilities from protection entries. Credit is
 * granted at most ONCE per (owner, constrained kind) — stacking redundant
 * protections against the same capability kind earns nothing beyond the
 * first (broadening-by-inflation closed).
 *
 * Integer-only arithmetic (ADR-007 F2, binding): every value on the score
 * path is an integer point value; floating-point arithmetic is forbidden in
 * this module (a static guard test scans this file, and assertInt fail-stops
 * at runtime). scoreVersion 1 uses whole-integer weights throughout, so no
 * fractional weights exist and no largest-remainder apportionment is needed;
 * introducing fractional weights (integer numerators over a fixed
 * denominator, largest-remainder reconciled) bumps `scoreVersion`.
 *
 * scoreVersion-1 weight table (implementation detail under the versioning
 * rule — ANY change to these values, the factors, the band boundaries, or
 * the base bumps `scoreVersion`; scores with different versions are never
 * compared, and consumers must treat an unknown version as unknown):
 *
 *   base posture                    100
 *   gap.critical                    -25   per critical boundary gap
 *   gap.high                        -15   per high boundary gap
 *   gap.medium                       -8   per medium boundary gap
 *   gap.warning                      -4   per warning boundary gap
 *   gap.info                         -2   per info boundary gap
 *   protection.anchored              +5   once per (owner, constrained kind)
 *   finding.pin.drift               -10   per outstanding pin.drift (sticky)
 *   finding.pin.conflict            -10   per pin.conflict
 *   finding.baseline.regenerated    -10
 *   finding.baseline.tampered       -20
 *   finding.identity.regenerated     -5
 *   finding.identity.missingOwner   -15   ADR-011 lifecycle gaps: severity-
 *   finding.identity.staleIdentity  -15   consistent with the gap.* tiers
 *   finding.identity.indefiniteLifetime -8
 *   finding.identity.lifetimeExpired    -25
 *   finding.identity.zombieActivity     -25
 *   (scoreVersion stays 1: these kinds could not occur in any pre-ADR-011
 *   run, so the extension is conservative — identical inputs still yield
 *   identical outputs; the new deltas fire only for newly-possible inputs.
 *   The INPUT pipeline grew, exactly like adding a detector; the formula
 *   for every previously-possible input is unchanged.)
 *   range.clamp             reconciling   bounds the score to 0–100; the
 *                                         entry's delta keeps deltas-sum-
 *                                         exactly true by arithmetic
 *
 * Bands are PRESENTATION over the composite, tier-capped (ADR-007): weak
 * (<40), fair (<70), good (<90), strong (90+ — structurally unreachable for
 * any identity below `verified-signed`; every v0 identity is `claimed`).
 *
 * Never persisted: composites are computed fresh each run and never written
 * to identity.json, the baseline, or any store. Output artifacts embedding
 * the composite are point-in-time snapshots, never re-read as inputs.
 * No exit-code mapping (ADR-006 untouched), no score on ADR-004 events.
 * Forward map (E3/E4): Condition input only, narrow-only at every tier.
 */
import type { ReviewReport } from "./types.js";
import type { DriftFinding } from "./diff.js";
import type { AgentIdentityRecord, AttestationLevel } from "./identity.js";
/** Formula version (ADR-007). Bumps on ANY output-altering change. */
export declare const SCORE_VERSION = 1;
/** The version's defined base every decomposition sums from. */
export declare const BASE_POSTURE = 100;
/** Presentation bands (tier-capped — see postureBand). */
export type PostureBand = "weak" | "fair" | "good" | "strong";
/** Factor scope per ADR-007: agent-owned config surface vs workspace-shared. */
export type FactorScope = "agent-owned" | "workspace-shared";
/**
 * One decomposition entry: every point of the posture score is traceable to
 * a cited finding, or to a protection together with the capability it
 * anchors to (ADR-007 F1), in the explainability tradition of
 * PolicyDecision. A score with no decomposition is non-conforming.
 */
export interface ScoreFactor {
    /** Stable factor kind (see the weight table above). */
    factor: string;
    scope: FactorScope;
    /** Integer point delta from the base. */
    delta: number;
    /** Citation for gap/lifecycle deductions (report index or finding key). */
    findingRef?: string;
    /** Citation for protection credits (report index)… */
    protectionRef?: string;
    /** …together with the independently-detected capability it anchors to. */
    anchorRef?: string;
    explanation: string;
}
/**
 * The Trust score composite (ADR-007). There is NO scalar form: the posture
 * number never leaves this shape, and no surface renders it without the
 * attestation qualifier (qualifiedPostureLine is the single-sourced copy).
 * Schema evolves additively under the ADR-003 rule.
 */
export interface TrustScore {
    attestation: AttestationLevel;
    /** 0–100 integer; BASE_POSTURE + Σ decomposition deltas, exactly. */
    postureScore: number;
    scoreVersion: typeof SCORE_VERSION;
    /** Fully sorted; the range.clamp reconciliation entry, if any, is last. */
    decomposition: ScoreFactor[];
}
/** A composite attributed to one claimed agent identity. */
export interface AgentTrustScore {
    agentId: string;
    agentType: string;
    trustScore: TrustScore;
}
export interface ScoreInput {
    report: ReviewReport;
    /** Sorted drift + lifecycle findings of the same run. */
    findings: readonly DriftFinding[];
    /** Claimed identity registry after this run (scored per record). */
    identityRecords: readonly AgentIdentityRecord[];
}
/**
 * The ONE place the qualified posture copy is defined (ADR-007 normative
 * rule: the posture number is NEVER rendered without its attestation
 * qualifier — the claimedIdentityClaim pattern). Every surface renders this
 * copy through its S1.9 sanitizer.
 */
export declare function qualifiedPostureLine(score: TrustScore): string;
/**
 * No-positive-assurance phrasing (ADR-007 presentation rules), single-sourced
 * for every surface: a high posture score is never a safety certification.
 */
export declare const POSTURE_ASSURANCE_NOTE = "Posture reflects protections observed in the local, agent-writable environment at review time \u2014 never a safety certification, never identity verification.";
/**
 * The honest-limit note (ADR-007 carry-forward 3): v0 credits the STRUCTURAL
 * PRESENCE of capability-anchored protections, not verified runtime efficacy
 * (verification of enforcement is E4+ scope).
 */
export declare const POSTURE_HONEST_LIMIT_NOTE = "Protection credits reflect the structural presence of capability-anchored protections, not verified runtime efficacy.";
/**
 * Single-sourced human render of one decomposition entry (report text, watch
 * header, artifact all use it — through their own S1.9 sanitizers).
 */
export declare function factorLine(f: ScoreFactor): string;
export declare function postureBand(postureScore: number, attestation: string): PostureBand;
/**
 * Compute the Trust score composite for every attributed identity record.
 * Deterministic and pure: output ordering is fully sorted (records by
 * agentId; decomposition by factor/scope/refs, clamp entry last), with no
 * wall-clock inputs. Cross-version rule (ADR-007): consumers MUST assert
 * equal `scoreVersion` before comparing two composites; an unknown version
 * is unknown, not comparable.
 */
export declare function computeTrustScores(input: ScoreInput): AgentTrustScore[];
