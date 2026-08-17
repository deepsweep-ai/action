/**
 * Antigravity detector (Google).
 * Covers well-known workspace locations:
 *  - .agents/mcp_config.json              (workspace MCP config)
 *  - GEMINI.md                            (project agent context)
 *  - ~/.gemini/config/mcp_config.json     (USER-SCOPE MCP, ADR-014 — shared by
 *                                          the Antigravity IDE *and* its CLI)
 *  - ~/.gemini/antigravity/               (OAuth token store — PRESENCE ONLY)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 *
 * WHY THIS DETECTOR EXISTS. Measured over 90 days, Antigravity users complete
 * 38 reviews across 10 people — 3.8 each, against 1.1 for Cursor and 0.9 for
 * VS Code. They are our most engaged human cohort and the engine could not see
 * their agent configuration at all.
 *
 * `.agents` IS PLURAL. Secondary write-ups say `.agent`; Google's own MCP
 * documentation says `.agents` consistently. Getting this wrong produces a
 * detector that never fires and reports "no agent configuration" for a
 * workspace that has one — silent, and indistinguishable from a clean result.
 *
 * `AGENTS.md` is deliberately NOT claimed here: the copilot detector already
 * reviews it, and two detectors emitting the same source would double-count it
 * in every total. `GEMINI.md` is Antigravity-specific and unclaimed.
 *
 * NOT YET SHIPPED: `.agent/rules/*.md` appears in secondary sources only and is
 * unconfirmed by Google's documentation. It stays out until a running install
 * confirms it — see
 * `deepsweep-knowledge/research/antigravity-trae-detector-surfaces.md`.
 */
import { exists, parseTolerantJson, probeDirNames, probeRead, probeReadUser } from "../read.js";
import { emptyResult } from "./detector.js";
import { isBlankDocument, malformedWarning, mcpCredentialDetail, mcpServersFrom, unreadableWarning, } from "./util.js";
const MCP_CONFIG = ".agents/mcp_config.json";
const CONTEXT_FILE = "GEMINI.md";
/** USER-SCOPE paths, relative to the injected user root (ADR-014). */
const USER_MCP_REL = ".gemini/config/mcp_config.json";
const USER_MCP_LABEL = "~/.gemini/config/mcp_config.json";
const OAUTH_DIR_REL = ".gemini/antigravity";
const OAUTH_TOKEN_NAME = "mcp_oauth_tokens.json";
const OAUTH_TOKEN_LABEL = "~/.gemini/antigravity/mcp_oauth_tokens.json";
/** Shared by the workspace and user-scope passes so the two cannot drift. */
function emitMcpCapabilities(json, source, out, scope) {
    for (const server of mcpServersFrom(json)) {
        const transport = server.url ? "remote" : "local";
        const where = scope === "user" ? `${transport}, user-scope config` : transport;
        const reach = scope === "user" ? " in EVERY workspace, and to the Antigravity CLI" : "";
        out.capabilities.push({
            kind: "mcpToolAccess",
            summary: `MCP server "${server.name}" (${where}) is available to Antigravity agents${reach}`,
            resource: server.name,
            source,
            detail: {
                transport,
                ...(scope === "user" ? { scope: "user" } : {}),
                ...(server.command ? { command: server.command } : {}),
                ...(server.url ? { url: server.url } : {}),
                ...mcpCredentialDetail(server),
            },
        });
        if (server.command) {
            out.capabilities.push({
                kind: "shellExecution",
                summary: `MCP server "${server.name}" launches a local process ("${server.command}")`,
                resource: server.command,
                source,
            });
        }
    }
}
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    // --- project context -----------------------------------------------------
    if (exists(workspaceRoot, CONTEXT_FILE)) {
        out.reviewedSources.push(CONTEXT_FILE);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "GEMINI.md instructions auto-load into Antigravity agent context",
            resource: CONTEXT_FILE,
            source: CONTEXT_FILE,
        });
    }
    // --- workspace MCP -------------------------------------------------------
    const mcpProbe = probeRead(workspaceRoot, MCP_CONFIG);
    if (mcpProbe.status === "unreadable") {
        out.warnings.push(unreadableWarning(MCP_CONFIG, mcpProbe.reason));
    }
    else if (mcpProbe.status === "ok") {
        out.reviewedSources.push(MCP_CONFIG);
        const json = parseTolerantJson(mcpProbe.text);
        if (json === undefined) {
            // An empty file is nothing configured, not malformed — the guard
            // nests here so the else-branch keeps its type narrowing.
            if (!isBlankDocument(mcpProbe.text))
                out.warnings.push(malformedWarning(MCP_CONFIG));
        }
        else {
            emitMcpCapabilities(json, MCP_CONFIG, out, "workspace");
        }
    }
    // --- user-scope MCP (ADR-014) -------------------------------------------
    const userMcp = ctx.userConfigRoot !== undefined
        ? probeReadUser(ctx.userConfigRoot, USER_MCP_REL)
        : { status: "absent" };
    if (userMcp.status === "unreadable") {
        out.warnings.push(unreadableWarning(USER_MCP_LABEL, userMcp.reason));
    }
    else if (userMcp.status === "ok") {
        out.reviewedSources.push(USER_MCP_LABEL);
        const json = parseTolerantJson(userMcp.text);
        if (json === undefined) {
            // An empty file is nothing configured, not malformed — the guard
            // nests here so the else-branch keeps its type narrowing.
            if (!isBlankDocument(userMcp.text))
                out.warnings.push(malformedWarning(USER_MCP_LABEL));
        }
        else {
            emitMcpCapabilities(json, USER_MCP_LABEL, out, "user");
        }
    }
    // --- OAuth token store: PRESENCE ONLY ------------------------------------
    // Antigravity persists MCP OAuth ACCESS TOKENS to disk in the same profile
    // tree an agent can reach. That is a standing credential exposure and it is
    // exactly the finding this product exists to surface.
    //
    // Detected by LISTING THE DIRECTORY, never by opening the file. A token file
    // is the one thing a reviewer must not read: reading it would pull live
    // credentials through the engine for no gain, since presence is the whole
    // finding. Only the name is ever observed.
    if (ctx.userConfigRoot !== undefined) {
        const probe = probeDirNames(ctx.userConfigRoot, OAUTH_DIR_REL);
        if (probe.status === "ok" && probe.names.includes(OAUTH_TOKEN_NAME)) {
            out.reviewedSources.push(OAUTH_TOKEN_LABEL);
            out.capabilities.push({
                kind: "secretsExposure",
                summary: "Antigravity stores MCP OAuth access tokens on disk in the user profile, readable by any agent with user-scope file access",
                resource: OAUTH_TOKEN_LABEL,
                source: OAUTH_TOKEN_LABEL,
                detail: { scope: "user", contentsRead: false },
            });
        }
        // An unreadable profile directory is NOT reported: absence of permission
        // to list it is not evidence of a token store, and a warning here would
        // fire on every machine that has never run Antigravity.
    }
    return out;
}
export const antigravityDetector = { id: "antigravity", detect };
