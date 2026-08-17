import { parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { isBlankDocument, malformedWarning, mcpCredentialDetail, mcpServersFrom, unreadableWarning, } from "./util.js";
const MCP_CONFIG_PATHS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"];
function detect(workspaceRoot) {
    const out = emptyResult();
    for (const rel of MCP_CONFIG_PATHS) {
        // S1.14: absent evidence must be visible — a present-but-unreadable
        // config degrades to a metadata-only warning, never to silence.
        const probe = probeRead(workspaceRoot, rel);
        if (probe.status === "absent")
            continue;
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(rel, probe.reason));
            continue;
        }
        out.reviewedSources.push(rel);
        const json = parseTolerantJson(probe.text);
        if (json === undefined) {
            // An empty file is nothing configured, not malformed — the guard
            // nests here so the else-branch keeps its type narrowing.
            if (!isBlankDocument(probe.text))
                out.warnings.push(malformedWarning(rel));
            continue;
        }
        for (const server of mcpServersFrom(json)) {
            const transport = server.url ? "remote" : "local";
            // The ADR-013 fragment comes from ONE owner so no family can silently
            // omit it — three of six once did (TEAM-ADR-035).
            const cap = {
                kind: "mcpToolAccess",
                summary: `MCP server "${server.name}" (${transport}) is available to agents`,
                resource: server.name,
                source: rel,
                detail: {
                    transport,
                    ...(server.command ? { command: server.command } : {}),
                    ...(server.url ? { url: server.url } : {}),
                    ...mcpCredentialDetail(server),
                },
            };
            out.capabilities.push(cap);
            if (server.command) {
                out.capabilities.push({
                    kind: "shellExecution",
                    summary: `MCP server "${server.name}" launches a local process ("${server.command}")`,
                    resource: server.command,
                    source: rel,
                });
            }
        }
    }
    return out;
}
export const mcpDetector = { id: "mcp", detect };
