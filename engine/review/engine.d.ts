/**
 * Agent Environment Review engine (DeepSweep Review wedge).
 * Deterministic, offline, zero runtime dependencies. See ADR-002.
 * Detection is composed from the compile-time fixed registry in
 * detectors/registry.ts; boundary-gap derivation stays centralized here so
 * gaps can relate capabilities across detector families.
 */
import type { ReviewReport } from "./types.js";
export interface ReviewOptions {
    /**
     * Root for USER-SCOPE config reads (ADR-014). NO ambient default: the
     * engine is structurally incapable of locating the user profile itself
     * (the ADR-005 static guard allows exactly one sanctioned call site, in
     * the CLI composition root). Absent → user-scope sources are skipped.
     */
    userConfigRoot?: string;
}
export declare function review(workspaceRoot: string, opts?: ReviewOptions): ReviewReport;
