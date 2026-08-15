/** Max bytes we will read from any single config file (defensive bound). */
export declare const MAX_FILE_BYTES = 1000000;
/**
 * Pure containment comparison (exported for explicit path.win32 tests).
 * Case-insensitive when the platform's filesystems are (win32): folding is
 * only applied where the filesystem itself folds, because folding on a
 * case-SENSITIVE filesystem would loosen containment (fail-open) instead of
 * fixing missed detection (fail-closed). macOS needs no folding here: both
 * sides of every comparison are realpath-canonicalized to on-disk casing.
 */
export declare function isPathContained(root: string, target: string, opts?: {
    caseInsensitive?: boolean;
    separator?: string;
}): boolean;
/**
 * Why an allowlisted path could not be read (S1.14 absent-evidence
 * observability). Reason CLASSES only — metadata, never content:
 *  - "oversized"         file exceeds MAX_FILE_BYTES
 *  - "not-a-file"        the inode is not a regular file (e.g. a directory)
 *  - "escaping-symlink"  containment refusal: the path resolves (lexically
 *                        or via a symlink) outside the reviewed root
 *  - "io-error"          open/stat/read failed (permissions, torn read, race)
 */
export type UnreadableReason = "oversized" | "not-a-file" | "escaping-symlink" | "io-error";
/**
 * Three-way probe outcome (S1.14): ABSENT is structurally distinct from
 * UNREADABLE, because for a review surface "no evidence found" and
 * "evidence present but not reviewable" must never be conflated — silence
 * about the latter understates what an agent may do.
 */
export type ProbeResult = {
    status: "ok";
    text: string;
} | {
    status: "absent";
} | {
    status: "unreadable";
    reason: UnreadableReason;
};
/**
 * S1.14 — probing read with absent-vs-unreadable classification. Same
 * containment core, same fd discipline as the original safeRead; the ONLY
 * addition is that refusals carry a metadata reason class (path is the
 * caller's; content NEVER rides on a refusal — an unreadable result carries
 * no bytes by construction).
 */
export declare function probeRead(workspaceRoot: string, relPath: string): ProbeResult;
/** Undefined-collapsing read (pre-S1.14 contract, kept for presence-style callers). */
export declare function safeRead(workspaceRoot: string, relPath: string): string | undefined;
/**
 * Inode-type-aware presence probe. A directory can never satisfy a "file"
 * probe (a directory named AGENTS.md is not agent instructions), and a file
 * can never satisfy a "directory" probe (a file named .git is not a
 * repository) — presence capabilities cannot be forged by inode type.
 */
export declare function exists(workspaceRoot: string, relPath: string, expect?: "file" | "directory"): boolean;
/**
 * ADR-014 — user-scope config reads (e.g. ~/.codeium/windsurf/mcp_config.json).
 * Identical invariants to the workspace readers, anchored at an EXPLICIT
 * user-config root instead of the workspace: allowlisted relative paths
 * only, symlinks resolving outside the root refused, size-capped, no
 * execution, no network. The root is injected by the composition layer
 * (the CLI's sanctioned profile-directory lookup in production; a temp dir
 * in tests) — the engine never locates the user profile itself (ADR-005).
 */
export declare function safeReadUser(userConfigRoot: string, relPath: string): string | undefined;
/** User-scope sibling of probeRead (ADR-014 invariants; S1.14 classification). */
export declare function probeReadUser(userConfigRoot: string, relPath: string): ProbeResult;
/** Max directory entries surfaced by listDirNames (bounds attacker fan-out). */
export declare const MAX_DIR_ENTRIES = 200;
/**
 * Classified directory listing — the S1.14 contract, extended from files to
 * DIRECTORIES.
 *
 * `probeRead` has always distinguished "absent" from "present but unreadable";
 * `listDirNames` did not, and collapsed both to `[]`. That made a live
 * capability vanish silently: `chmod 000 .cursor/rules` dropped the directory
 * out of `reviewedSources`, removed its capabilities, left `warnings` empty —
 * and *improved* the posture score. Any agent holding `chmod` could buy itself
 * a cleaner review.
 *
 * Absence and refusal are different facts and are now reported as such.
 */
export type DirProbeResult = {
    status: "ok";
    names: string[];
} | {
    status: "absent";
} | {
    status: "unreadable";
    reason: UnreadableReason;
};
/**
 * List entry NAMES of an allowlisted, workspace-relative directory.
 * Metadata only — entry contents are never read here; no recursion; symlinked
 * directories resolving outside the workspace root are refused. Sorted for
 * determinism and capped at MAX_DIR_ENTRIES (sorted-first) to bound
 * attacker-created fan-out.
 */
export declare function probeDirNames(workspaceRoot: string, relPath: string): DirProbeResult;
/**
 * Undefined-collapsing listing (pre-S1.14 contract, kept for presence-style
 * callers that genuinely do not care why the list is empty).
 *
 * Prefer `probeDirNames` in any detector: collapsing here is exactly what let
 * an unreadable rules directory read as an empty one.
 */
export declare function listDirNames(workspaceRoot: string, relPath: string): string[];
/**
 * Tolerant JSON parse for config files that may contain JSONC-style
 * line/block comments and trailing commas (e.g. .vscode/settings.json).
 * Deterministic; returns undefined on unrecoverable input.
 */
export declare function parseTolerantJson(text: string): unknown;
/** Parse .env-style content returning KEY NAMES ONLY (values are discarded). */
export declare function envKeyNames(text: string): string[];
