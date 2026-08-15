import { parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { malformedWarning, mcpServersFrom, unreadableWarning } from "./util.js";
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
            out.warnings.push(malformedWarning(rel));
            continue;
        }
        for (const server of mcpServersFrom(json)) {
            const transport = server.url ? "remote" : "local";
            // ADR-013 flattening: detail is a flat primitive record, so the FIRST
            // hit carries the exact {credentialPattern, argIndex} shape, the count
            // covers the rest, and multi-hit servers add a compact "pattern@index"
            // list. Pattern names + indexes only — never an arg's content.
            const hits = server.credentialHits ?? [];
            const first = hits[0];
            const cap = {
                kind: "mcpToolAccess",
                summary: `MCP server "${server.name}" (${transport}) is available to agents`,
                resource: server.name,
                source: rel,
                detail: {
                    transport,
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
