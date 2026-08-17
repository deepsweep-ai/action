/**
 * Trae detector (ByteDance).
 * Covers well-known workspace locations:
 *  - .trae/rules/            (project rule files — NAMES only)
 *  - .trae/mcp.json          (workspace MCP config, standard mcpServers map)
 *  - ~/.trae/mcp.json        (USER-SCOPE MCP config, ADR-014)
 *  - ~/.trae/user_rules/     (USER-SCOPE rule files — NAMES only)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 *
 * WHY THIS DETECTOR EXISTS. Measured over 90 days, Trae users complete 28
 * reviews across 9 people — 3.1 each, against 1.1 for Cursor and 0.9 for VS
 * Code. They are among our most engaged cohorts and the engine could not see
 * their agent configuration at all, so every review of a Trae workspace
 * silently reported on generic surfaces only.
 *
 * Paths are transcribed from Trae's published documentation (rules live in
 * `.trae/rules`; workspace MCP in `.trae/mcp.json` under the project root;
 * user scope under `~/.trae`). They are NOT yet confirmed against a running
 * install — see `deepsweep-knowledge/research/antigravity-trae-detector-surfaces.md`.
 * A detector aimed at a path that does not exist fails SILENTLY, reporting
 * "no agent configuration" for a workspace that has one.
 */
import { parseTolerantJson, probeDirNames, probeRead, probeReadUser } from "../read.js";
import { emptyResult } from "./detector.js";
import { dirNamesOrWarn, isBlankDocument, malformedWarning, mcpCredentialDetail, mcpServersFrom, nameList, unreadableWarning, visibleNames, } from "./util.js";
import { countNoun } from "../text.js";
const RULES_DIR = ".trae/rules";
const MCP_CONFIG = ".trae/mcp.json";
/** USER-SCOPE paths, relative to the injected user root (ADR-014). */
const USER_MCP_REL = ".trae/mcp.json";
const USER_MCP_LABEL = "~/.trae/mcp.json";
const USER_RULES_REL = ".trae/user_rules";
const USER_RULES_LABEL = "~/.trae/user_rules";
/**
 * Emit the capabilities implied by one MCP config document. Shared by the
 * workspace and user-scope passes so the two can never drift into reviewing
 * the same document to different standards — `scopeNote` is the ONLY
 * difference, because a user-scope server is available in EVERY workspace.
 */
function emitMcpCapabilities(json, source, out, scope) {
    for (const server of mcpServersFrom(json)) {
        const transport = server.url ? "remote" : "local";
        const where = scope === "user"
            ? `${transport}, user-scope config`
            : transport;
        const reach = scope === "user" ? " in EVERY workspace" : "";
        out.capabilities.push({
            kind: "mcpToolAccess",
            summary: `MCP server "${server.name}" (${where}) is available to Trae agents${reach}`,
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
    // --- workspace rules -----------------------------------------------------
    const ruleFiles = visibleNames(dirNamesOrWarn(workspaceRoot, RULES_DIR, out.warnings));
    if (ruleFiles.length > 0) {
        out.reviewedSources.push(RULES_DIR);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: `${countNoun(ruleFiles.length, "Trae rule file auto-applies", "Trae rule files auto-apply")} workspace instructions to agent sessions`,
            resource: RULES_DIR,
            source: RULES_DIR,
            detail: { fileCount: ruleFiles.length, fileNames: nameList(ruleFiles) },
        });
    }
    // --- workspace MCP -------------------------------------------------------
    // S1.14: absent evidence must be visible — a present-but-unreadable config
    // degrades to a metadata-only warning, never to silence.
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
    // The injected user root itself never reaches any surface; only the "~/"
    // label does.
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
    // --- user-scope rules ----------------------------------------------------
    if (ctx.userConfigRoot !== undefined) {
        const probe = probeDirNames(ctx.userConfigRoot, USER_RULES_REL);
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(USER_RULES_LABEL, probe.reason));
        }
        else if (probe.status === "ok") {
            const names = visibleNames(probe.names);
            if (names.length > 0) {
                out.reviewedSources.push(USER_RULES_LABEL);
                out.capabilities.push({
                    kind: "agentInstructions",
                    summary: `${countNoun(names.length, "Trae user rule file applies", "Trae user rule files apply")} instructions to agent sessions in EVERY workspace`,
                    resource: USER_RULES_LABEL,
                    source: USER_RULES_LABEL,
                    detail: { scope: "user", fileCount: names.length, fileNames: nameList(names) },
                });
            }
        }
    }
    return out;
}
export const traeDetector = { id: "trae", detect };
