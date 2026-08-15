import type { ArgCredentialHit } from "./credentials.js";
import type { UnreadableReason } from "../read.js";
import type { ReviewWarning } from "../types.js";
export declare function asRecord(v: unknown): Record<string, unknown> | undefined;
export declare function asString(v: unknown): string | undefined;
export declare function malformedWarning(source: string): ReviewWarning;
/**
 * S1.14 absent-evidence observability: an agent-config file that is present
 * but UNREADABLE must never degrade to silence — its capabilities are simply
 * missing from the review, with nothing telling the operator so. This
 * warning carries METADATA ONLY: the allowlisted path plus a reason class.
 * Never file content, and never a guess at what the capabilities might be.
 */
export declare function unreadableWarning(source: string, reason: UnreadableReason): ReviewWarning;
/**
 * Directory listing that cannot silently lose evidence.
 *
 * Extends the S1.14 warning contract from files to directories: an
 * ENUMERABLE directory yields its names, an ABSENT one yields none, and a
 * PRESENT-BUT-UNREADABLE one yields none *plus a warning*. Collapsing the
 * last two — which `listDirNames` alone does — is what let `chmod 000` on a
 * rules directory delete a capability from the review and raise the score.
 *
 * Warnings are deduplicated by source so a nested walk cannot emit the same
 * path twice.
 */
export declare function dirNamesOrWarn(workspaceRoot: string, relPath: string, warnings: ReviewWarning[]): string[];
export interface McpServerEntry {
    /** Number of launch args (shape only — arg contents never leave util). */
    argCount?: number;
    /** ADR-013 credential-shape hits over the args (pattern + index only). */
    credentialHits?: ArgCredentialHit[];
    /** Cleartext non-loopback http transport, and where it was declared. */
    cleartextHttp?: "url" | "args";
    name: string;
    command?: string;
    url?: string;
}
/**
 * Redact a server URL before it can reach any report surface (text, --json,
 * future cloud payloads): keep scheme + host + path ONLY. Userinfo
 * credentials, query strings (tokens), and fragments are dropped.
 */
export declare function redactUrl(raw: string): string;
/**
 * Extract MCP server entries from the common `mcpServers`/`servers` map shape
 * shared by Cursor, VS Code, Claude Code, and Windsurf MCP configs.
 * Env blocks are never surfaced. Args are reviewed IN-MODULE for credential
 * SHAPE and transport (ADR-013) — pattern kinds, indexes, and counts leave;
 * arg contents never do. URLs are redacted (scheme + host + path) before
 * leaving this module.
 */
export declare function mcpServersFrom(json: unknown): McpServerEntry[];
/** Cap + join a list of names for a detail field (first `max`, sorted input). */
export declare function nameList(names: string[], max?: number): string;
/** Visible (non-dot) entry names — used for rule/instruction directories. */
export declare function visibleNames(names: string[]): string[];
