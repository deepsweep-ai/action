/**
 * ADR-006 + ADR-012 — CLI exit-code gating for one-shot runs.
 *
 * Pure, deterministic resolution of the finding-based exit codes: given the
 * run's drift findings, the baseline disposition, and the active flags,
 * return the single exit code the process must use. Error-path codes
 * (1 usage, 3 baseline containment refusal) preempt before this function is
 * ever reached and are NOT in its domain.
 *
 * Contract highlights (ADR-006, Accepted 2026-07-23):
 *  - Gating keys on finding KIND plus the baseline regeneration reason —
 *    NEVER on a finding's severity.
 *  - `pin.drift` / `pin.conflict` under `--fail-on-drift` → 4.
 *  - Regeneration from ANY invalid baseline (corrupt / unknownSchemaVersion /
 *    foreignWorkspace) under `--fail-on-drift` → 5 (trust-anchor divergence;
 *    fail-closed — "corrupt the baseline" must not suppress drift).
 *  - `baseline.tampered` → 5 (reserved mapping; watch-emitted kind, kept live
 *    here so a future session-outcome gate cannot fail open).
 *  - Absent baseline under `--require-baseline` → 5; without it, true
 *    first-run creation → 0.
 *  - Exit 2 is severity-threshold gating (ADR-012): `--fail-on` with default
 *    `critical`, orthogonal to output format. The pre-ADR-012 rule (exit 2
 *    iff `--json` AND criticals) was a fail-open CI path for text-mode runs;
 *    `--fail-on=none` restores the old text-mode behavior explicitly, and
 *    the output format no longer participates in gating at all. `--json`
 *    runs behave exactly as before under the default threshold.
 *  - Precedence: 5 > 4 > 2; exit 0 is the ONLY pass.
 */
import type { DriftFinding } from "./review/diff.js";
import type { BaselineDisposition } from "./oneshot.js";
/** Finding-based exit codes (ADR-006 table). 0 is the only pass. */
export type GatedExitCode = 0 | 2 | 4 | 5;
/** `--fail-on` severity threshold (ADR-012). */
export type FailOnThreshold = "critical" | "high" | "none";
export interface GateFlags {
    /**
     * `--fail-on` (ADR-012) — boundary-gap severity threshold for exit 2,
     * independent of output format. Default `critical`; `high` also gates on
     * high-severity gaps; `none` disables gap gating (the pre-ADR-012
     * text-mode behavior, now an explicit choice instead of a silent default).
     */
    failOn: FailOnThreshold;
    /** `--fail-on-drift` — opt-in drift / trust-anchor gating (one-shot only). */
    failOnDrift: boolean;
    /**
     * `--require-baseline` — companion assertion that a persistent baseline
     * already exists; only meaningful alongside `failOnDrift` (the CLI rejects
     * it standalone as a usage error before this function runs).
     */
    requireBaseline: boolean;
}
export interface GateInput {
    /** Sorted drift + lifecycle findings of the run (oneshot composition). */
    findings: readonly DriftFinding[];
    /** How this run obtained its baseline (carries the regeneration reason). */
    baselineDisposition: BaselineDisposition;
    /** Merged report totals: count of critical boundary gaps. */
    criticalGaps: number;
    /** Merged report totals: count of high-severity boundary gaps (ADR-012). */
    highGaps: number;
}
/**
 * Resolve the process exit code for a one-shot run under the active flags.
 * Deterministic. Under the default threshold a `--json` run reproduces the
 * pre-ADR-012 behavior exactly; a text-mode run now gates criticals too —
 * that asymmetry was a fail-open CI path, not a contract worth preserving.
 */
export declare function resolveExitCode(input: GateInput, flags: GateFlags): GatedExitCode;
