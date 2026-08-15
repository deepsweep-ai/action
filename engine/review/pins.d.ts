/**
 * Pinned-entity extraction for MCP tool-description pinning (S1.4 AC3,
 * detection-only). ADR-003:
 *  - Pinned-entity key is the tuple (entityType, logicalName) — deliberately
 *    excluding `source`, so identity survives moves between allowlisted files.
 *  - `contentHash` is a canonical per-entity SHA-256 (RFC 8785-style) so
 *    formatting-only edits raise no false drift, while any code-point change
 *    in a description does.
 *  - Secret redaction BEFORE hashing: env.* / headers.* VALUES are replaced
 *    with "<redacted>"; key NAMES are preserved and remain part of the pinned
 *    identity. Consequence: rotating a secret does not raise drift.
 *  - args are NOT redacted (endpoint/command semantics are attack-relevant);
 *    a warning is raised when an arg matches secret-shaped heuristics.
 *  - Endpoint-shaped env/header key NAMES raise a pin-time warning: changes
 *    to their values will not raise drift. Key-name matching only.
 * Reads local files only via safeRead (ADR-002 containment); no execution,
 * no network.
 */
import type { ReviewWarning } from "./types.js";
/** Fixed allowlist of MCP config sources pinned into the baseline (ADR-002). */
export declare const PIN_SOURCES: readonly [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".windsurf/mcp_config.json"];
/** Fixed placeholder substituted for secret-bearing values before hashing. */
export declare const REDACTED_PLACEHOLDER = "<redacted>";
export type PinnedEntityType = "mcpServer" | "toolDescription";
export interface PinnedEntity {
    entityType: PinnedEntityType;
    /** e.g. "github" (mcpServer) or "github/create_pr" (toolDescription). */
    logicalName: string;
    /** Workspace-relative config path the entity was found in. */
    source: string;
    /** SHA-256 of the redacted, canonicalized entity definition. */
    contentHash: string;
}
export interface PinExtraction {
    /** Sorted by (entityType, logicalName, source) for determinism. */
    entities: PinnedEntity[];
    /** Pin-time warnings: endpoint-shaped keys, secret-shaped args, duplicate keys. */
    warnings: ReviewWarning[];
    /** MCP config sources found (workspace-relative). */
    sources: string[];
    /** Raw-bytes SHA-256 per source file (cheap change detection, ADR-003). */
    rawFileHashes: Record<string, string>;
}
/**
 * Replace env.* / headers.* VALUES with the fixed placeholder; key names are
 * preserved (presence-and-key-names-only invariant, ADR-002/ADR-003).
 */
export declare function redactServerDefinition(def: Record<string, unknown>): Record<string, unknown>;
/**
 * Extract pinned entities from the fixed MCP config allowlist.
 * Pure function of workspace file contents; deterministic ordering.
 */
export declare function extractPins(workspaceRoot: string): PinExtraction;
