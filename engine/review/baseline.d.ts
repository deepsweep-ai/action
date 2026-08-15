import type { PinExtraction, PinnedEntity } from "./pins.js";
import type { DriftFinding } from "./diff.js";
export declare const BASELINE_DIR = ".deepsweep";
export declare const BASELINE_FILE = "baseline.json";
export declare const BASELINE_REL_PATH = ".deepsweep/baseline.json";
export interface BaselineFile {
    schemaVersion: 1;
    /** Workspace root BASENAME only — never absolute paths (ADR-003). */
    workspace: string;
    createdAt: string;
    lastPinnedAt: string;
    entityCount: number;
    /** Workspace-relative MCP config sources pinned. */
    reviewedSources: string[];
    /** Raw-bytes SHA-256 per source file (cheap change detection). */
    rawFileHashes: Record<string, string>;
    entities: PinnedEntity[];
}
/** Provenance disclosed on every report and watch session header (ADR-003). */
export interface BaselineProvenance {
    createdAt: string;
    lastPinnedAt: string;
    entityCount: number;
    /** SHA-256 of the baseline file bytes, computed at read time, never stored. */
    baselineSha256: string;
}
export type BaselineInvalidReason = "corrupt" | "unknownSchemaVersion" | "foreignWorkspace";
export type BaselineLoad = {
    status: "absent";
} | {
    status: "invalid";
    reason: BaselineInvalidReason;
} | {
    status: "ok";
    baseline: BaselineFile;
    fileHash: string;
};
/** Raised when containment invariants forbid touching the baseline at all. */
export declare class BaselineRefusalError extends Error {
    constructor(reason: string);
}
/**
 * Load the baseline with full containment checks.
 * Throws BaselineRefusalError only for containment violations; every other
 * failure degrades to a regenerable status (regenerate-not-migrate).
 */
export declare function loadBaseline(workspaceRoot: string): BaselineLoad;
/** Pure construction; preserves createdAt across explicit re-pins. */
export declare function buildBaseline(workspaceBasename: string, extraction: PinExtraction, nowIso: string, previous?: BaselineFile): BaselineFile;
/**
 * Atomic, contained baseline write (ADR-003 moments only: first-run creation
 * or explicit re-pin). Returns the SHA-256 of the written bytes so the watch
 * session can track its in-memory tamper-check hash.
 */
export declare function writeBaseline(workspaceRoot: string, baseline: BaselineFile): {
    fileHash: string;
};
/**
 * Hash the on-disk baseline for the in-session tamper check (ADR-003
 * mitigation 3). Returns undefined when absent/unreadable — the caller
 * treats any divergence from the in-memory hash as baseline.tampered
 * (fail-suspicious by design).
 */
export declare function hashBaselineOnDisk(workspaceRoot: string): string | undefined;
export declare function baselineCreatedFinding(entityCount: number): DriftFinding;
export declare function baselineRegeneratedFinding(reason: BaselineInvalidReason): DriftFinding;
export declare function baselineTamperedFinding(expectedHash: string, foundHash: string | undefined): DriftFinding;
