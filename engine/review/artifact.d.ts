import type { ReviewReport } from "./types.js";
import type { DriftFinding } from "./diff.js";
import type { BaselineProvenance } from "./baseline.js";
import type { AgentIdentityRecord } from "./identity.js";
import type { AgentTrustScore } from "./score.js";
import type { AuthorizationGapView } from "./authgap.js";
import type { DecisionView } from "./evaluate.js";
export type ArtifactFormat = "md" | "html";
/** Everything a one-shot run must hand the artifact renderer. */
export interface ArtifactInput {
    report: ReviewReport;
    provenance: BaselineProvenance;
    /** Sorted drift + lifecycle findings of the run. */
    findings: DriftFinding[];
    repinned: boolean;
    /** ISO timestamp of the review run (injectable for deterministic tests). */
    generatedAt: string;
    /** Tool version (toolVersion() at the CLI; injectable in tests). */
    toolVersion: string;
    /**
     * Claimed agent identity records (S2.1, ADR-005). Optional additively;
     * the CLI always supplies it. The transient claimed owner (ADR-005 F1)
     * must NEVER be part of this input — artifacts are shareable.
     */
    identity?: readonly AgentIdentityRecord[];
    /**
     * Trust score composites (S2.2, ADR-007). Optional additively; the CLI
     * always supplies it. Artifacts embedding the composite are point-in-time
     * SNAPSHOTS (never re-read by the runtime) and always carry the full
     * qualified composite plus the review timestamp — never a bare number.
     */
    trust?: readonly AgentTrustScore[];
    /**
     * Authorization coverage (S3.3, ADR-009 default-observe). Optional
     * additively; the CLI always supplies it. Advisory read of policy against
     * findings — governed capabilities vs open authorization gaps.
     */
    authorization?: AuthorizationGapView;
    /**
     * Policy decisions (S3.2, ADR-009). Optional additively; the CLI always
     * supplies it. Advisory per-capability allow/deny/require-approval/observe
     * with the deciding rule + version-pinned policyRef — never enforced, never
     * a grant (`observe` is record-only).
     */
    decisions?: DecisionView;
}
/**
 * Tool version, read from this package's own package.json at runtime (the
 * boring way: no build-step stamping, no extra dependency). The path is the
 * same relative hop from src/review/ (dev, tsx) and dist/review/ (built):
 * two levels up is the package root. Never throws — an unreadable manifest
 * degrades to "unknown".
 */
export declare function toolVersion(): string;
/** Dispatcher the CLI writes through (per-write-site guard recognizes it). */
export declare function renderArtifact(input: ArtifactInput, format: ArtifactFormat): string;
export declare function renderMarkdownArtifact(input: ArtifactInput): string;
export declare function renderHtmlArtifact(input: ArtifactInput): string;
