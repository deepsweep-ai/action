/**
 * Compile-time detector contract for the review engine.
 * Detectors are fixed modules composed in registry.ts — NOT a plugin
 * framework: no dynamic loading, no configuration, no runtime dependencies
 * (ADR-002; reaffirmed by the Sprint 02 ADR-gate ruling, 2026-07-23).
 * Every detector shares the Capability / BoundaryGap contract in ../types.ts;
 * boundary-gap derivation stays centralized in the engine so gaps can relate
 * capabilities across detector families.
 */
import type { Capability, Protection, ReviewWarning } from "../types.js";
export interface DetectorResult {
    /** Sources this detector found and reviewed (workspace-relative). */
    reviewedSources: string[];
    capabilities: Capability[];
    /**
     * Detected protections (S2.2, ADR-007): structurally-present controls
     * that can constrain a capability. Detectors never derive capabilities
     * FROM protection entries — the capability-anchored crediting rule
     * (ADR-007 F1) depends on anchors being independent by construction.
     */
    protections: Protection[];
    /** Malformed/unrecognized sources, degraded to warnings (never a crash). */
    warnings: ReviewWarning[];
}
/**
 * Per-run detection context (ADR-014). `userConfigRoot` anchors USER-SCOPE
 * config reads (global assistant configs living under the user profile).
 * It is injected by the composition layer — the CLI's single sanctioned
 * profile-directory call site in production, a temp dir in tests. ABSENT
 * means user-scope sources are skipped: the engine cannot locate the user
 * profile itself (ADR-005 static guard).
 */
export interface DetectorContext {
    readonly userConfigRoot?: string;
}
export interface Detector {
    /** Stable identifier for the detector family (e.g. "cursor"). */
    readonly id: string;
    /** Pure, deterministic, read-only, offline detection pass. */
    readonly detect: (workspaceRoot: string, ctx: DetectorContext) => DetectorResult;
}
export declare function emptyResult(): DetectorResult;
