/**
 * Typed contracts for the Agent Environment Review engine.
 * Terminology per kb/glossary.md — "review", "capability", "boundary gap".
 */
/**
 * CapabilityKind evolves ADDITIVELY under schemaVersion 1: new kinds may be
 * appended as detector coverage grows; existing kinds are never renamed,
 * removed, or re-meaning'd without a schemaVersion bump. (This additive
 * schema-evolution rule will be codified by ADR-003, currently in draft.)
 */
export type CapabilityKind = "shellExecution" | "repositoryWrite" | "mcpToolAccess" | "secretsExposure" | "autoApproval" | "agentInstructions" | "containerMount" | "externalDirectoryAccess" | "portExposure" | "privilegedContainer";
/**
 * "warning" was added (additively, per the ADR-003 evolution rule) for
 * baseline lifecycle findings such as baseline.regenerated (ADR-003/004).
 */
export type Severity = "critical" | "high" | "medium" | "warning" | "info";
export interface Capability {
    /**
     * F6/ADR-020: stable content-hash id — "cap_" + sha256(canonicalize(
     * {kind, resource, source}))[0..16], with "#n" suffixes disambiguating
     * same-content duplicates in emission order. Stable across runs of the
     * same environment; additive under schemaVersion 1.
     */
    id?: string;
    kind: CapabilityKind;
    /** Human-readable statement of the power an agent holds. */
    summary: string;
    /** The resource the capability touches (server name, path, tool, branch…). */
    resource: string;
    /** Workspace-relative path of the config file that grants this capability. */
    source: string;
    /** Extra structured detail (never secret values — names/presence only). */
    detail?: Record<string, string | number | boolean>;
}
export interface BoundaryGap {
    severity: Severity;
    /** What protection is missing for a discovered capability. */
    summary: string;
    /** Recommended protection, phrased as an action. */
    recommendation: string;
    /**
     * DEPRECATED (ADR-020 deprecation window): indices into capabilities[].
     * Emitted alongside relatedCapabilityIds until consumers migrate; the
     * ids are the stable form (indices shift when detectors reorder).
     */
    relatedCapabilities: number[];
    /** F6/ADR-020: stable content-hash ids of the related capabilities. */
    relatedCapabilityIds?: string[];
}
/**
 * A protection: a configured control that CAN constrain a capability
 * (deny rule, pre-execution hook). Detected structurally — presence of the
 * config, never verified runtime efficacy (ADR-007 honest limit). A
 * protection earns posture credit ONLY when an independently-detected
 * capability of its `constrains` kind exists in the same run (ADR-007 F1,
 * capability-anchored crediting); protections themselves NEVER produce
 * capabilities, so self-anchoring is structurally impossible.
 * (Additive field under schemaVersion 1 — see CapabilityKind note above.)
 */
export interface Protection {
    /** The capability kind this protection constrains when anchored. */
    constrains: CapabilityKind;
    /** Human-readable statement of what the protection does. */
    summary: string;
    /** The rule/hook the protection is defined by (pattern, matcher…). */
    resource: string;
    /** Workspace-relative path of the config file that defines it. */
    source: string;
}
/**
 * A degraded finding: a reviewed source was present but malformed or
 * unrecognized, so capability extraction was skipped for it. The review
 * never crashes on bad input — it reports the gap in its own coverage.
 * (Additive field under schemaVersion 1 — see CapabilityKind note above.)
 */
export interface ReviewWarning {
    /** Workspace-relative path of the source that could not be understood. */
    source: string;
    summary: string;
}
export interface ReviewReport {
    schemaVersion: 1;
    workspaceRoot: string;
    /** Config files that were found and reviewed (workspace-relative). */
    reviewedSources: string[];
    capabilities: Capability[];
    boundaryGaps: BoundaryGap[];
    /**
     * Detected protections (S2.2, ADR-007). Optional ADDITIVELY under
     * schemaVersion 1 (older snapshots lack it); the engine always sets it.
     */
    protections?: Protection[];
    /** Malformed/unrecognized sources, degraded to warnings (never a crash). */
    warnings: ReviewWarning[];
    /** Deterministic summary counts for CI thresholds. */
    totals: {
        capabilities: number;
        boundaryGaps: number;
        critical: number;
        high: number;
    };
}
