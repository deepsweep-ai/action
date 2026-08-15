import { DETECTORS } from "./detectors/registry.js";
import { countNoun } from "./text.js";
import { canonicalize, sha256Hex } from "./canonical.js";
export function review(workspaceRoot, opts = {}) {
    const ctx = opts.userConfigRoot !== undefined ? { userConfigRoot: opts.userConfigRoot } : {};
    const capabilities = [];
    const reviewedSources = [];
    const protections = [];
    const warnings = [];
    for (const detector of DETECTORS) {
        const result = detector.detect(workspaceRoot, ctx);
        reviewedSources.push(...result.reviewedSources);
        capabilities.push(...result.capabilities);
        protections.push(...result.protections);
        warnings.push(...result.warnings);
    }
    // F6/ADR-020: assign stable content-hash ids AFTER composition (order
    // fixed by the frozen registry) — duplicates disambiguate by "#n" suffix.
    const seen = new Map();
    for (const c of capabilities) {
        const base = `cap_${sha256Hex(canonicalize({ kind: c.kind, resource: c.resource, source: c.source })).slice(0, 16)}`;
        const n = seen.get(base) ?? 0;
        seen.set(base, n + 1);
        c.id = n === 0 ? base : `${base}#${n + 1}`;
    }
    const boundaryGaps = deriveBoundaryGaps(capabilities);
    // Dual emission (deprecation window): ids alongside the legacy indices.
    for (const g of boundaryGaps) {
        // Indices come from idx() over this same array and every element was
        // assigned an id in the loop above — both assertions hold by construction.
        g.relatedCapabilityIds = g.relatedCapabilities.map((i) => capabilities[i].id);
    }
    const critical = boundaryGaps.filter((g) => g.severity === "critical").length;
    const high = boundaryGaps.filter((g) => g.severity === "high").length;
    return {
        schemaVersion: 1,
        workspaceRoot,
        reviewedSources,
        capabilities,
        boundaryGaps,
        protections,
        warnings,
        totals: {
            capabilities: capabilities.length,
            boundaryGaps: boundaryGaps.length,
            critical,
            high,
        },
    };
}
function idx(capabilities, pred) {
    return capabilities.map((c, i) => (pred(c) ? i : -1)).filter((i) => i >= 0);
}
function deriveBoundaryGaps(capabilities) {
    const gaps = [];
    const shell = idx(capabilities, (c) => c.kind === "shellExecution");
    const repo = idx(capabilities, (c) => c.kind === "repositoryWrite");
    const mcp = idx(capabilities, (c) => c.kind === "mcpToolAccess");
    const secrets = idx(capabilities, (c) => c.kind === "secretsExposure");
    const instructions = idx(capabilities, (c) => c.kind === "agentInstructions");
    const privileged = idx(capabilities, (c) => c.kind === "privilegedContainer");
    const socketMounts = idx(capabilities, (c) => c.kind === "containerMount" && c.detail?.["dockerSocket"] === true);
    const plainMounts = idx(capabilities, (c) => c.kind === "containerMount" && c.detail?.["dockerSocket"] !== true);
    const ports = idx(capabilities, (c) => c.kind === "portExposure");
    const broadApprovals = idx(capabilities, (c) => (c.kind === "autoApproval" || c.kind === "shellExecution") && c.detail?.["broad"] === true);
    if (secrets.length > 0 && (shell.length > 0 || mcp.length > 0)) {
        gaps.push({
            severity: "critical",
            summary: "Secrets are readable in a workspace where agents hold shell or MCP tool access — exfiltration requires no additional privilege",
            recommendation: "Move secrets to a manager (or agent-excluded path) and require approval for reads of .env* files",
            relatedCapabilities: [...secrets, ...shell, ...mcp],
        });
    }
    // ADR-013: a static credential pattern embedded in an MCP server
    // definition coexists, by construction, with that server being reachable
    // by agents (a configured server IS the reachability) — critical. The gap
    // cites pattern kinds and counts only; values never reach any surface.
    const credentialed = mcp.filter((i) => {
        const count = capabilities[i]?.detail?.["credentialPatternCount"];
        return typeof count === "number" && count > 0;
    });
    if (credentialed.length > 0) {
        gaps.push({
            severity: "critical",
            summary: `${countNoun(credentialed.length, "MCP server definition embeds", "MCP server definitions embed")} a static credential pattern in launch arguments reachable by agents`,
            recommendation: "Move credentials out of args into a secret-manager reference (or env indirection), and rotate any value that has already been committed or shared",
            relatedCapabilities: credentialed,
        });
    }
    // ADR-013 transport review: cleartext http to a non-loopback host —
    // tool traffic (and any bearer credential riding on it) is interceptable.
    const cleartext = mcp.filter((i) => capabilities[i]?.detail?.["cleartextHttp"] === true);
    if (cleartext.length > 0) {
        gaps.push({
            severity: "high",
            summary: `${countNoun(cleartext.length, "MCP server speaks", "MCP servers speak")} cleartext HTTP to a non-loopback host`,
            recommendation: "Use https (or an ssh/stdio transport) for every non-loopback MCP endpoint",
            relatedCapabilities: cleartext,
        });
    }
    if (broadApprovals.length > 0) {
        gaps.push({
            severity: "critical",
            summary: "Broad pre-approved permission patterns allow agent actions with no human decision point",
            recommendation: "Replace wildcard allows with narrow, resource-scoped rules plus approval gates",
            relatedCapabilities: broadApprovals,
        });
    }
    if (privileged.length > 0 || socketMounts.length > 0) {
        gaps.push({
            severity: "critical",
            summary: "Container configuration grants host-level control (privileged mode or Docker socket) — container isolation is not a boundary for agents",
            recommendation: "Remove privileged flags and Docker-socket mounts, or require approval for container rebuilds and daemon-level actions",
            relatedCapabilities: [...privileged, ...socketMounts],
        });
    }
    if (shell.length > 0) {
        gaps.push({
            severity: "high",
            summary: "Shell execution is available to agents with no configured approval gate",
            recommendation: "Require approval for shell commands outside an allowlist (build/test only)",
            relatedCapabilities: shell,
        });
    }
    if (repo.length > 0 && shell.length > 0) {
        gaps.push({
            severity: "high",
            summary: "Repository write + shell access combine into unreviewed commit/push capability",
            recommendation: "Require approval for git push and protect default-branch operations",
            relatedCapabilities: [...repo, ...shell],
        });
    }
    // ADR-014: additionalDirectories = agent file access beyond the workspace
    // boundary — same risk class as a plain bind mount, same severity.
    const externalDirs = idx(capabilities, (c) => c.kind === "externalDirectoryAccess");
    if (externalDirs.length > 0) {
        gaps.push({
            severity: "medium",
            summary: `${countNoun(externalDirs.length, "additional directory extends", "additional directories extend")} agent file access beyond the workspace boundary`,
            recommendation: "Remove additionalDirectories entries you do not actively need, or scope them to read-only data directories",
            relatedCapabilities: externalDirs,
        });
    }
    if (plainMounts.length > 0) {
        gaps.push({
            severity: "medium",
            summary: `${countNoun(plainMounts.length, "container bind mount extends", "container bind mounts extend")} agent file access beyond the workspace`,
            recommendation: "Mount only required paths (read-only where possible); keep home directories and credential stores out of the container",
            relatedCapabilities: plainMounts,
        });
    }
    if (instructions.length > 0) {
        gaps.push({
            severity: "medium",
            summary: `${countNoun(instructions.length, "auto-applied agent instruction source steers", "auto-applied agent instruction sources steer")} agent behavior with no change review`,
            recommendation: "Review instruction and rule files now, and re-review whenever they change — they alter agent behavior silently",
            relatedCapabilities: instructions,
        });
    }
    if (mcp.length > 0) {
        gaps.push({
            severity: "medium",
            summary: `${countNoun(mcp.length, "MCP tool surface has", "MCP tool surfaces have")} no per-tool authorization policy`,
            recommendation: "Define Principal/Action/Resource/Condition rules per MCP server",
            relatedCapabilities: mcp,
        });
    }
    if (ports.length > 0) {
        gaps.push({
            severity: "info",
            summary: `${countNoun(ports.length, "forwarded port exposes", "forwarded ports expose")} container services on the host`,
            recommendation: "Forward only the ports you need and prefer localhost-only binding",
            relatedCapabilities: ports,
        });
    }
    return gaps;
}
