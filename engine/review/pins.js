import { parseTolerantJson, safeRead } from "./read.js";
import { canonicalize, findDuplicateJsonKeys, sha256Hex } from "./canonical.js";
import { asRecord, asString } from "./detectors/util.js";
/** Fixed allowlist of MCP config sources pinned into the baseline (ADR-002). */
export const PIN_SOURCES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
];
/** Fixed placeholder substituted for secret-bearing values before hashing. */
export const REDACTED_PLACEHOLDER = "<redacted>";
const ENDPOINT_SHAPED_KEY = /(^|_)(URL|URI|HOST|HOSTNAME|ENDPOINT|BASE|ADDR|ADDRESS|SERVER|TARGET)$/i;
/** Heuristic only — never inspects values beyond shape; never echoes them. */
function looksSecretShaped(arg) {
    if (/(secret|token|passw|api[-_]?key|bearer|credential)/i.test(arg))
        return true;
    if (/^(sk|pk|ghp|gho|ghu|xox[a-z])[-_]/i.test(arg))
        return true;
    return (arg.length >= 24 &&
        /^[A-Za-z0-9+/=_.-]+$/.test(arg) &&
        /[A-Za-z]/.test(arg) &&
        /\d/.test(arg));
}
/**
 * Replace env.* / headers.* VALUES with the fixed placeholder; key names are
 * preserved (presence-and-key-names-only invariant, ADR-002/ADR-003).
 */
export function redactServerDefinition(def) {
    const out = { ...def };
    for (const field of ["env", "headers"]) {
        const map = asRecord(def[field]);
        if (!map)
            continue;
        const redacted = {};
        for (const key of Object.keys(map))
            redacted[key] = REDACTED_PLACEHOLDER;
        out[field] = redacted;
    }
    return out;
}
function definitionWarnings(name, source, def) {
    const out = [];
    for (const field of ["env", "headers"]) {
        const map = asRecord(def[field]);
        if (!map)
            continue;
        for (const key of Object.keys(map).sort()) {
            if (ENDPOINT_SHAPED_KEY.test(key)) {
                out.push({
                    source,
                    summary: `MCP server "${name}": its target appears to be configured via ${field} key "${key}" — that value is redacted before pinning, so changes to it will not raise drift. Review the value directly when re-pinning.`,
                });
            }
        }
    }
    const args = def["args"];
    if (Array.isArray(args)) {
        args.forEach((arg, i) => {
            if (typeof arg === "string" && looksSecretShaped(arg)) {
                out.push({
                    source,
                    summary: `MCP server "${name}": argument #${i + 1} matches secret-shaped patterns — args are pinned unredacted; prefer env (redacted at pin time) for secret values.`,
                });
            }
        });
    }
    // URLs are hashed UNREDACTED by design (a re-pointed target must raise
    // drift), but a userinfo/query-bearing URL in a committable baseline is a
    // weak offline oracle — warn, mirroring the args heuristic (S1.4 security
    // review P3). The value itself is never echoed.
    for (const field of ["url", "serverUrl"]) {
        const raw = asString(def[field]);
        if (raw !== undefined && urlCarriesSecrets(raw)) {
            out.push({
                source,
                summary: `MCP server "${name}": its ${field} embeds credentials or query parameters — the full URL is hashed unredacted into the baseline (URL changes must raise drift); move secrets to env/headers (redacted at pin time).`,
            });
        }
    }
    return out;
}
/** Shape check only — the URL value is never surfaced in any warning. */
function urlCarriesSecrets(raw) {
    try {
        const u = new URL(raw);
        return u.username !== "" || u.password !== "" || u.search !== "";
    }
    catch {
        return /\/\/[^/@]+@/.test(raw) || raw.includes("?");
    }
}
function cmpStr(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}
/**
 * Extract pinned entities from the fixed MCP config allowlist.
 * Pure function of workspace file contents; deterministic ordering.
 */
export function extractPins(workspaceRoot) {
    const entities = [];
    const warnings = [];
    const sources = [];
    const rawFileHashes = {};
    for (const rel of PIN_SOURCES) {
        const text = safeRead(workspaceRoot, rel);
        if (text === undefined)
            continue;
        sources.push(rel);
        rawFileHashes[rel] = sha256Hex(text);
        const json = parseTolerantJson(text);
        if (json === undefined)
            continue; // detectors already degrade this to a warning
        const dups = findDuplicateJsonKeys(text);
        if (dups.length > 0) {
            warnings.push({
                source: rel,
                summary: `Duplicate JSON ${dups.length === 1 ? "key" : "keys"} in ${rel} (${dups.join(", ")}) — parsing is deterministic last-wins, but duplicate definitions deserve review.`,
            });
        }
        const root = asRecord(json);
        const servers = asRecord(root?.["mcpServers"]) ?? asRecord(root?.["servers"]);
        if (!servers)
            continue;
        for (const name of Object.keys(servers).sort()) {
            const def = asRecord(servers[name]);
            if (!def)
                continue;
            entities.push({
                entityType: "mcpServer",
                logicalName: name,
                source: rel,
                contentHash: sha256Hex(canonicalize(redactServerDefinition(def))),
            });
            warnings.push(...definitionWarnings(name, rel, def));
            // Tool descriptions declared inline in the config (hashed individually
            // in addition to the enclosing server definition, ADR-003).
            const tools = def["tools"];
            const toolsMap = asRecord(tools);
            if (toolsMap) {
                for (const toolName of Object.keys(toolsMap).sort()) {
                    const toolDef = toolsMap[toolName];
                    /* v8 ignore next -- reason: toolsMap values originate from JSON.parse (via parseTolerantJson), which can never produce an undefined property value for a key returned by Object.keys; the guard exists only to satisfy noUncheckedIndexedAccess narrowing. */
                    if (toolDef === undefined)
                        continue;
                    entities.push({
                        entityType: "toolDescription",
                        logicalName: `${name}/${toolName}`,
                        source: rel,
                        contentHash: sha256Hex(canonicalize(toolDef)),
                    });
                }
            }
            else if (Array.isArray(tools)) {
                for (const t of tools) {
                    const toolRec = asRecord(t);
                    const toolName = asString(toolRec?.["name"]);
                    if (!toolRec || toolName === undefined)
                        continue;
                    entities.push({
                        entityType: "toolDescription",
                        logicalName: `${name}/${toolName}`,
                        source: rel,
                        contentHash: sha256Hex(canonicalize(toolRec)),
                    });
                }
            }
        }
    }
    entities.sort((a, b) => cmpStr(a.entityType, b.entityType) ||
        cmpStr(a.logicalName, b.logicalName) ||
        cmpStr(a.source, b.source));
    return { entities, warnings, sources, rawFileHashes };
}
