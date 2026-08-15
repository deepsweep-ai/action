import type { DriftFinding } from "./diff.js";
export declare const IDENTITY_FILE = "identity.json";
export declare const IDENTITY_REL_PATH = ".deepsweep/identity.json";
/**
 * Agent types this build derives (ADR-005; evolves additively like
 * CapabilityKind — existing values are never renamed or re-meaning'd).
 */
export type AgentType = "cursor" | "claude-code" | "copilot" | "windsurf" | "devcontainer";
/**
 * Attestation levels (ADR-005 additive enum). Only `claimed` exists in v0;
 * `session-observed` (S2.3), `verified-signed` (E4), and `attested` (cloud)
 * arrive with their own ADRs. v0 readers treat any OTHER value in the store
 * as corrupt (regenerate-not-migrate): rendering an unknown level could
 * present a claimed identity as something stronger — the exact
 * no-positive-assurance failure ADR-005 forbids.
 */
export type AttestationLevel = "claimed";
export interface AgentIdentityRecord {
    /** "agt_" + first 16 hex of the ADR-005 derivation. Attribution only. */
    agentId: string;
    /** Derived AgentType for records this build writes (string for tolerance). */
    agentType: string;
    /** Workspace root BASENAME only — never absolute paths (ADR-003). */
    workspace: string;
    firstObservedAt: string;
    /**
     * Most recent run-day this agent surface was observed (ADR-011, additive
     * under schemaVersion 1). Updated at UTC-day granularity — one store write
     * per agent per day, bounded churn — because its only consumer is the
     * staleness detector, whose unit is days. Absent on pre-ADR-011 stores:
     * readers fall back to firstObservedAt.
     */
    lastObservedAt?: string;
    attestation: AttestationLevel;
}
export interface IdentityFile {
    schemaVersion: 1;
    /** Workspace root BASENAME only (ADR-003 rule, as in baseline.json). */
    workspace: string;
    agents: AgentIdentityRecord[];
}
export type IdentityInvalidReason = "corrupt" | "unknownSchemaVersion" | "foreignWorkspace";
export type IdentityLoad = {
    status: "absent";
} | {
    status: "invalid";
    reason: IdentityInvalidReason;
} | {
    status: "ok";
    identity: IdentityFile;
};
/** Raised when containment invariants forbid touching the identity store. */
export declare class IdentityRefusalError extends Error {
    constructor(reason: string);
}
/**
 * The stable Agent ID (ADR-005): deterministic, metadata-only, byte-stable
 * across runs and machines. Reuses the ONE canonicalizer + hash (ADR-003).
 * Deliberately excludes owner and session data so the ID cannot churn when
 * they change.
 */
export declare function deriveAgentId(agentType: string, workspace: string): string;
/**
 * Map an allowlisted reviewed-source path to the agent surface it belongs to.
 * Returns undefined for generic surfaces attributable to no specific agent
 * product (.env*, .git, AGENTS.md — an open convention, not one product —
 * and .deepsweep/*). `.mcp.json` is the Claude Code project-level MCP config;
 * `.vscode/mcp.json` is the VS Code (Copilot agent mode) MCP config.
 */
export declare function agentTypeForSource(source: string): AgentType | undefined;
/** Distinct agent types observed in a run's reviewed sources, sorted. */
export declare function observedAgentTypes(reviewedSources: readonly string[]): AgentType[];
/**
 * The `principal` fill for drift events (ADR-004 promise, ADR-005 semantics):
 * the agentId STRING claimed by the config surface a finding originates from,
 * derived FRESH from (agentType, workspace) — never resolved from the store
 * (containment of authority: the store is display/continuity only). Returns
 * undefined (→ `principal: null`) for sources owned by no specific agent.
 */
export declare function principalFor(source: string, workspace: string): string | undefined;
/**
 * The ONE place the claimed-identity phrasing is defined (ADR-005 normative
 * rule: never present claimed identity as authenticated). Every surface
 * renders this copy through its S1.9 sanitizer.
 */
export declare function claimedIdentityClaim(agentType: string): string;
/**
 * Load the identity registry with full containment checks. Throws
 * IdentityRefusalError only for containment violations; every other failure
 * degrades to a regenerable status (regenerate-not-migrate, ADR-003 rule
 * inherited by ADR-005).
 */
export declare function loadIdentity(workspaceRoot: string): IdentityLoad;
/** Atomic, contained identity-store write (shared store primitives). */
export declare function writeIdentity(workspaceRoot: string, identity: IdentityFile): void;
export interface IdentityObservation {
    /** The full registry after this run: previously observed + current agents. */
    records: AgentIdentityRecord[];
    /** identity.regenerated lifecycle findings (warning severity), if any. */
    findings: DriftFinding[];
}
/**
 * Observe the current run's agents and reconcile the registry: previously
 * observed records are KEPT (continuity survives baseline resets — that is
 * the store's entire reason to exist), newly observed agents are appended
 * with firstObservedAt = nowIso, and an invalid store is discarded and
 * regenerated (warning-severity identity.regenerated — losing the registry
 * resets attribution continuity and must be visible). The store is written
 * only when the registry changed. May throw IdentityRefusalError on
 * containment violations (CLI exit 3).
 */
export declare function observeIdentities(workspaceRoot: string, reviewedSources: readonly string[], nowIso: string): IdentityObservation;
/**
 * Claimed owner: git `user.email` from `.git/config`, read under ADR-002
 * containment (safeRead — symlink/realpath refusal, size cap). TRANSIENT
 * ONLY (ADR-005 F1): callers may show it on local human surfaces (text
 * report, watch header) and must never persist or emit it — a planted-owner
 * fixture in tests/identity.test.ts proves the composition. Returns
 * undefined when absent or unparseable. The OS username is never read.
 */
export declare function readClaimedOwner(workspaceRoot: string): string | undefined;
export declare function identityRegeneratedFinding(reason: IdentityInvalidReason): DriftFinding;
