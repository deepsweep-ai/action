/**
 * Shared, dependency-free helpers for detector modules.
 * Metadata-first invariant: helpers here surface structure and NAMES only —
 * never secret values (ADR-002).
 */
import { firstUrlArgIndex, isCleartextHttpUrl, reviewArgsForCredentials } from "./credentials.js";
import { probeDirNames } from "../read.js";
export function asRecord(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v)
        ? v
        : undefined;
}
export function asString(v) {
    return typeof v === "string" ? v : undefined;
}
/**
 * An EMPTY config document is "nothing configured", NOT "malformed".
 *
 * FOUND 2026-08-15 on a real Antigravity install: it ships
 * `~/.gemini/config/mcp_config.json` as a ZERO-BYTE file on first run. Every
 * detector here fed that straight into `parseTolerantJson`, got `undefined`,
 * and raised "Configuration is malformed" — so every Antigravity user's very
 * first review would have opened with a false alarm about a file they had
 * never touched.
 *
 * NONE of the seven detector families guarded this, so the defect was latent
 * across the whole engine and Antigravity merely made it reachable: it is the
 * only assistant we cover that creates the file eagerly rather than on first
 * use.
 *
 * This matters more than one spurious line. A warning channel that cries wolf
 * on a clean machine is a warning channel operators learn to skip, and the
 * S1.14 absent-evidence guarantee depends on those warnings being believed.
 * Fix the false alarms first — a muted guard is worse than no guard.
 *
 * A blank document is reported as REVIEWED with no capabilities, which is the
 * truth: we read it, and it grants nothing.
 */
export function isBlankDocument(text) {
    return text.trim().length === 0;
}
export function malformedWarning(source) {
    return {
        source,
        summary: `Configuration in ${source} is malformed or unrecognized — reviewed for presence only. Fix the file and re-run the review for full capability coverage.`,
    };
}
/** Human phrasing per unreadable reason class (S1.14) — static copy only. */
const UNREADABLE_REASON_LABEL = {
    oversized: "it exceeds the review size cap",
    "not-a-file": "it is not a regular file",
    "escaping-symlink": "it resolves outside the reviewed root via a symlink",
    "io-error": "read access was refused or failed",
};
/**
 * S1.14 absent-evidence observability: an agent-config file that is present
 * but UNREADABLE must never degrade to silence — its capabilities are simply
 * missing from the review, with nothing telling the operator so. This
 * warning carries METADATA ONLY: the allowlisted path plus a reason class.
 * Never file content, and never a guess at what the capabilities might be.
 */
export function unreadableWarning(source, reason) {
    return {
        source,
        summary: `Configuration at ${source} exists but could not be read (${UNREADABLE_REASON_LABEL[reason]}) — its capabilities are missing from this review. Restore read access and re-run the review; missing evidence is not missing capability.`,
    };
}
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
export function dirNamesOrWarn(workspaceRoot, relPath, warnings) {
    const probe = probeDirNames(workspaceRoot, relPath);
    if (probe.status === "unreadable") {
        if (!warnings.some((w) => w.source === relPath)) {
            warnings.push(unreadableWarning(relPath, probe.reason));
        }
        return [];
    }
    return probe.status === "ok" ? probe.names : [];
}
/**
 * The ADR-013 credential/transport fragment for one MCP server, flattened into
 * the primitive record a `Capability.detail` must be.
 *
 * THIS EXISTS BECAUSE FOUR OF SIX READERS FORGOT IT. `mcpServersFrom` computed
 * `credentialHits` for every family, and only `mcp.ts` and the windsurf
 * USER-scope loop ever read them back — so a plaintext database URL in an MCP
 * server's args was reported in `.mcp.json`, `.cursor/mcp.json` and
 * `.vscode/mcp.json`, and silently dropped in `.trae/mcp.json`,
 * `.agents/mcp_config.json` and `.windsurf/mcp_config.json` (measured
 * 2026-08-16, TEAM-ADR-035). Those last three are the editors most of our
 * users actually run.
 *
 * One owner, so a family added tomorrow cannot quietly omit it: spread this
 * into `detail` instead of hand-assembling the fields.
 *
 * Emits pattern NAMES, indexes and counts only — never an argument's content.
 */
export function mcpCredentialDetail(server) {
    const hits = server.credentialHits ?? [];
    const first = hits[0];
    return {
        ...(server.argCount !== undefined ? { argCount: server.argCount } : {}),
        ...(first !== undefined
            ? {
                credentialPattern: first.credentialPattern,
                argIndex: first.argIndex,
                credentialPatternCount: hits.length,
            }
            : {}),
        ...(hits.length > 1
            ? {
                credentialPatterns: hits
                    .map((h) => `${h.credentialPattern}@${h.argIndex}`)
                    .join(","),
            }
            : {}),
        ...(server.cleartextHttp !== undefined
            ? { cleartextHttp: true, cleartextDeclaredIn: server.cleartextHttp }
            : {}),
    };
}
/**
 * Redact a server URL before it can reach any report surface (text, --json,
 * future cloud payloads): keep scheme + host + path ONLY. Userinfo
 * credentials, query strings (tokens), and fragments are dropped.
 */
export function redactUrl(raw) {
    try {
        const u = new URL(raw);
        let pathname = u.pathname;
        // S1.7 close-out: exotic non-special-scheme parses keep the whole
        // authority in the PATHNAME with an empty host — e.g.
        // "mcp.example.com:pass@evil/path" parses with scheme "mcp.example.com:"
        // and pathname "pass@evil/path" — so credential-shaped "userinfo@" text
        // would survive the host-based redaction. When the parse produced no
        // host, strip any leading userinfo-shaped run from the pathname
        // (over-redaction of "@"-text is acceptable; leaking credentials is not).
        if (u.host === "")
            pathname = pathname.replace(/^[^/@]*@/, "");
        return `${u.protocol}//${u.host}${pathname}`;
    }
    catch {
        // Not URL-parseable: still drop query/fragment and userinfo-shaped prefixes.
        /* v8 ignore next -- reason: split(/[?#]/, 1)[0] is defined for every string (the regex cannot match empty input, so the result array is never empty); the nullish fallback only satisfies noUncheckedIndexedAccess and is provably unreachable. */
        const noQuery = raw.split(/[?#]/, 1)[0] ?? "";
        return noQuery.replace(/\/\/[^/@]*@/, "//");
    }
}
/**
 * Extract MCP server entries from the common `mcpServers`/`servers` map shape
 * shared by Cursor, VS Code, Claude Code, and Windsurf MCP configs.
 * Env blocks are never surfaced. Args are reviewed IN-MODULE for credential
 * SHAPE and transport (ADR-013) — pattern kinds, indexes, and counts leave;
 * arg contents never do. URLs are redacted (scheme + host + path) before
 * leaving this module.
 */
export function mcpServersFrom(json) {
    const root = asRecord(json);
    if (!root)
        return [];
    const servers = asRecord(root["mcpServers"]) ?? asRecord(root["servers"]);
    if (!servers)
        return [];
    const out = [];
    for (const name of Object.keys(servers).sort()) {
        const entry = asRecord(servers[name]) ?? {};
        const command = asString(entry["command"]);
        // Windsurf declares remote servers with `serverUrl`; other editors use
        // `url`. Both route through redactUrl so credentials/query never surface
        // (QA defect D1 regression: serverUrl-only servers were mislabeled
        // "(local)" and their URL omitted).
        const url = asString(entry["url"]) ?? asString(entry["serverUrl"]);
        const e = { name };
        if (command !== undefined)
            e.command = command;
        if (url !== undefined)
            e.url = redactUrl(url);
        // ADR-013: review args for credential shape + transport, IN-MODULE —
        // only patterns/indexes/counts escape; hostile non-string entries are
        // ignored (shape tolerance, same posture as the rest of this reader).
        const rawArgs = Array.isArray(entry["args"])
            ? entry["args"].filter((a) => typeof a === "string")
            : undefined;
        if (rawArgs !== undefined) {
            e.argCount = rawArgs.length;
            const hits = reviewArgsForCredentials(rawArgs);
            if (hits.length > 0)
                e.credentialHits = hits;
        }
        if (url !== undefined && isCleartextHttpUrl(url)) {
            e.cleartextHttp = "url";
        }
        else if (rawArgs !== undefined) {
            const ui = firstUrlArgIndex(rawArgs);
            if (ui !== undefined && isCleartextHttpUrl(rawArgs[ui]))
                e.cleartextHttp = "args";
        }
        out.push(e);
    }
    return out;
}
/** Cap + join a list of names for a detail field (first `max`, sorted input). */
export function nameList(names, max = 10) {
    return names.slice(0, max).join(", ");
}
/** Visible (non-dot) entry names — used for rule/instruction directories. */
export function visibleNames(names) {
    return names.filter((n) => !n.startsWith("."));
}
