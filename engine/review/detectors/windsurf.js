/**
 * Windsurf detector.
 * Covers well-known workspace locations:
 *  - .windsurfrules            (legacy root rules file, auto-loaded)
 *  - .windsurf/rules/          (rule files — NAMES only)
 *  - .windsurf/workflows/      (agent-invocable workflows — NAMES only)
 *  - .windsurf/mcp_config.json (workspace MCP config, standard mcpServers map)
 *  - ~/.codeium/windsurf/mcp_config.json (USER-SCOPE global config, ADR-014:
 *    read through the same contained reader anchored at the injected user
 *    root — symlink/size invariants identical; labeled scope "user" and
 *    "~/"-prefixed in every surface so operators can tell it apart from
 *    workspace posture at a glance)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 */
import { exists, parseTolerantJson, probeRead, probeReadUser } from "../read.js";
import { emptyResult } from "./detector.js";
import { dirNamesOrWarn, malformedWarning, mcpServersFrom, nameList, unreadableWarning, visibleNames, } from "./util.js";
import { countNoun } from "../text.js";
const RULES_FILE = ".windsurfrules";
const RULES_DIR = ".windsurf/rules";
const WORKFLOWS_DIR = ".windsurf/workflows";
const MCP_CONFIG = ".windsurf/mcp_config.json";
/** USER-SCOPE global config, relative to the injected user root (ADR-014). */
const GLOBAL_MCP_CONFIG_REL = ".codeium/windsurf/mcp_config.json";
const GLOBAL_MCP_CONFIG_LABEL = "~/.codeium/windsurf/mcp_config.json";
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    if (exists(workspaceRoot, RULES_FILE)) {
        out.reviewedSources.push(RULES_FILE);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "Windsurf rules file auto-loads workspace instructions into agent sessions",
            resource: RULES_FILE,
            source: RULES_FILE,
        });
    }
    const ruleFiles = visibleNames(dirNamesOrWarn(workspaceRoot, RULES_DIR, out.warnings));
    if (ruleFiles.length > 0) {
        out.reviewedSources.push(RULES_DIR);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: `${countNoun(ruleFiles.length, "Windsurf rule file auto-applies", "Windsurf rule files auto-apply")} workspace instructions to agent sessions`,
            resource: RULES_DIR,
            source: RULES_DIR,
            detail: { fileCount: ruleFiles.length, fileNames: nameList(ruleFiles) },
        });
    }
    const workflows = visibleNames(dirNamesOrWarn(workspaceRoot, WORKFLOWS_DIR, out.warnings));
    if (workflows.length > 0) {
        out.reviewedSources.push(WORKFLOWS_DIR);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: countNoun(workflows.length, "Windsurf workflow is an agent-invocable multi-step instruction set", "Windsurf workflows are agent-invocable multi-step instruction sets"),
            resource: WORKFLOWS_DIR,
            source: WORKFLOWS_DIR,
            detail: { fileCount: workflows.length, fileNames: nameList(workflows) },
        });
    }
    // S1.14: absent evidence must be visible — a present-but-unreadable MCP
    // config degrades to a metadata-only warning, never to silence.
    const mcpProbe = probeRead(workspaceRoot, MCP_CONFIG);
    if (mcpProbe.status === "unreadable") {
        out.warnings.push(unreadableWarning(MCP_CONFIG, mcpProbe.reason));
    }
    else if (mcpProbe.status === "ok") {
        out.reviewedSources.push(MCP_CONFIG);
        const json = parseTolerantJson(mcpProbe.text);
        if (json === undefined) {
            out.warnings.push(malformedWarning(MCP_CONFIG));
        }
        else {
            for (const server of mcpServersFrom(json)) {
                const transport = server.url ? "remote" : "local";
                out.capabilities.push({
                    kind: "mcpToolAccess",
                    summary: `MCP server "${server.name}" (${transport}) is available to agents`,
                    resource: server.name,
                    source: MCP_CONFIG,
                    detail: {
                        transport,
                        ...(server.command ? { command: server.command } : {}),
                        ...(server.url ? { url: server.url } : {}),
                    },
                });
                if (server.command) {
                    out.capabilities.push({
                        kind: "shellExecution",
                        summary: `MCP server "${server.name}" launches a local process ("${server.command}")`,
                        resource: server.command,
                        source: MCP_CONFIG,
                    });
                }
            }
        }
    }
    // USER-SCOPE global MCP config (ADR-014): same reader invariants, same
    // credential/transport review (mcpServersFrom), distinct labeling.
    // S1.14: unreadable degrades to a metadata-only warning under the "~/"
    // label — the injected user root itself never reaches any surface.
    const globalProbe = ctx.userConfigRoot !== undefined
        ? probeReadUser(ctx.userConfigRoot, GLOBAL_MCP_CONFIG_REL)
        : { status: "absent" };
    if (globalProbe.status === "unreadable") {
        out.warnings.push(unreadableWarning(GLOBAL_MCP_CONFIG_LABEL, globalProbe.reason));
    }
    else if (globalProbe.status === "ok") {
        out.reviewedSources.push(GLOBAL_MCP_CONFIG_LABEL);
        const json = parseTolerantJson(globalProbe.text);
        if (json === undefined) {
            out.warnings.push(malformedWarning(GLOBAL_MCP_CONFIG_LABEL));
        }
        else {
            for (const server of mcpServersFrom(json)) {
                const transport = server.url ? "remote" : "local";
                const hits = server.credentialHits ?? [];
                const first = hits[0];
                out.capabilities.push({
                    kind: "mcpToolAccess",
                    summary: `MCP server "${server.name}" (${transport}, user-scope config) is available to agents in EVERY workspace`,
                    resource: server.name,
                    source: GLOBAL_MCP_CONFIG_LABEL,
                    detail: {
                        transport,
                        scope: "user",
                        ...(server.command ? { command: server.command } : {}),
                        ...(server.url ? { url: server.url } : {}),
                        ...(server.argCount !== undefined ? { argCount: server.argCount } : {}),
                        ...(first !== undefined
                            ? {
                                credentialPattern: first.credentialPattern,
                                argIndex: first.argIndex,
                                credentialPatternCount: hits.length,
                            }
                            : {}),
                        ...(hits.length > 1
                            ? { credentialPatterns: hits.map((h) => `${h.credentialPattern}@${h.argIndex}`).join(",") }
                            : {}),
                        ...(server.cleartextHttp !== undefined
                            ? { cleartextHttp: true, cleartextDeclaredIn: server.cleartextHttp }
                            : {}),
                    },
                });
                if (server.command) {
                    out.capabilities.push({
                        kind: "shellExecution",
                        summary: `MCP server "${server.name}" (user-scope config) launches a local process ("${server.command}")`,
                        resource: server.command,
                        source: GLOBAL_MCP_CONFIG_LABEL,
                        detail: { scope: "user" },
                    });
                }
            }
        }
    }
    return out;
}
export const windsurfDetector = { id: "windsurf", detect };
