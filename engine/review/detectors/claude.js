/**
 * Claude Code settings detector — pre-approved permission posture from
 * .claude/settings.json / settings.local.json. Fixed allowlist per ADR-002.
 *
 * S2.2 (ADR-007): the same files also declare PROTECTIONS — `permissions.deny`
 * rules and `hooks.PreToolUse` entries that gate tool calls before execution.
 * These are detected structurally (presence of the config, never verified
 * runtime efficacy — the ADR-007 honest limit) and reported as
 * `DetectorResult.protections`. Deliberately, NO capability is ever derived
 * from a protection entry: the capability-anchored crediting rule (ADR-007
 * F1) requires anchors to be independent, and this detector keeps
 * self-anchoring structurally impossible. Deny rules / hook matchers that map
 * to no reviewed capability kind are skipped (they could only ever be inert
 * in v0 — crediting them would be the presence-based inflation F1 forbids).
 *
 * ADR-014: hook COMMANDS are additionally surfaced as shellExecution
 * capabilities (PreToolUse AND PostToolUse) — a hook executes an arbitrary
 * local command on every matching tool call, which is a capability in its
 * own right. These carry detail.hook and are EXCLUDED from anchor candidacy
 * in the score (a hook must never credit itself — F1's self-anchoring rule
 * extended to the capability side). permissions.additionalDirectories is
 * surfaced as file access beyond the workspace boundary.
 */
import { parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { asRecord, asString, isBlankDocument, malformedWarning, unreadableWarning } from "./util.js";
const CLAUDE_SETTINGS_PATHS = [".claude/settings.json", ".claude/settings.local.json"];
/** Capability kind a deny rule constrains, or undefined (skip — see header). */
function denyRuleConstrains(rule) {
    if (rule.startsWith("Bash"))
        return "shellExecution";
    if (rule.startsWith("mcp__"))
        return "mcpToolAccess";
    if (rule.startsWith("Read") && rule.includes(".env"))
        return "secretsExposure";
    return undefined;
}
/** Capability kind a PreToolUse hook matcher constrains, or undefined. */
function hookMatcherConstrains(matcher) {
    if (matcher === "" || matcher === "*" || matcher.includes("Bash"))
        return "shellExecution";
    if (matcher.startsWith("mcp__"))
        return "mcpToolAccess";
    return undefined;
}
function detect(workspaceRoot) {
    const out = emptyResult();
    for (const rel of CLAUDE_SETTINGS_PATHS) {
        // S1.14: absent evidence must be visible — a present-but-unreadable
        // settings file degrades to a metadata-only warning, never to silence.
        const probe = probeRead(workspaceRoot, rel);
        if (probe.status === "absent")
            continue;
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(rel, probe.reason));
            continue;
        }
        out.reviewedSources.push(rel);
        const json = asRecord(parseTolerantJson(probe.text));
        if (json === undefined) {
            // An empty file is nothing configured, not malformed — the guard
            // nests here so the else-branch keeps its type narrowing.
            if (!isBlankDocument(probe.text))
                out.warnings.push(malformedWarning(rel));
            continue;
        }
        const permissions = asRecord(json["permissions"]);
        const allow = Array.isArray(permissions?.["allow"]) ? permissions?.["allow"] : [];
        for (const raw of allow.map(String).sort()) {
            const isShell = raw.startsWith("Bash");
            const isBroad = raw.includes("*") || raw === "Bash";
            out.capabilities.push({
                kind: isShell ? "shellExecution" : "autoApproval",
                summary: `Pre-approved agent permission: ${raw}${isBroad ? " (broad pattern)" : ""}`,
                resource: raw,
                source: rel,
                detail: { broad: isBroad },
            });
        }
        // Deny rules: each maps to the capability kind it can constrain.
        const deny = Array.isArray(permissions?.["deny"]) ? permissions?.["deny"] : [];
        for (const raw of deny.map(String).sort()) {
            const constrains = denyRuleConstrains(raw);
            if (constrains === undefined)
                continue;
            out.protections.push({
                constrains,
                summary: `Deny rule "${raw}" blocks matching agent actions before execution`,
                resource: raw,
                source: rel,
            });
        }
        // PreToolUse hooks: gate tool calls before execution (structural
        // presence only — whether the hook actually blocks is E4+ scope).
        const hooks = asRecord(json["hooks"]);
        const pre = hooks?.["PreToolUse"];
        for (const entry of Array.isArray(pre) ? pre : []) {
            const matcher = asString(asRecord(entry)?.["matcher"]) ?? "";
            const constrains = hookMatcherConstrains(matcher);
            if (constrains === undefined)
                continue;
            const label = matcher === "" ? "*" : matcher;
            out.protections.push({
                constrains,
                summary: `PreToolUse hook gates "${label}" tool calls before execution`,
                resource: `PreToolUse:${label}`,
                source: rel,
            });
        }
        // ADR-014: every hook COMMAND (PreToolUse and PostToolUse) is itself a
        // shellExecution capability — an arbitrary local command running on
        // every matching tool call. detail.hook marks these for the score's
        // self-anchor exclusion; the command string is config the operator
        // wrote, not a secret (sanitized at every render choke point anyway).
        for (const event of ["PreToolUse", "PostToolUse"]) {
            const entries = hooks?.[event];
            for (const entry of Array.isArray(entries) ? entries : []) {
                const matcher = asString(asRecord(entry)?.["matcher"]) ?? "";
                const inner = asRecord(entry)?.["hooks"];
                for (const h of Array.isArray(inner) ? inner : []) {
                    const command = asString(asRecord(h)?.["command"]);
                    if (command === undefined)
                        continue;
                    out.capabilities.push({
                        kind: "shellExecution",
                        summary: `${event} hook runs a local command ("${command}") on ${matcher === "" || matcher === "*" ? "every" : `"${matcher}"`} tool call${matcher === "" || matcher === "*" ? "" : "s"}`,
                        resource: command,
                        source: rel,
                        detail: { hook: event, ...(matcher !== "" ? { matcher } : {}) },
                    });
                }
            }
        }
        // ADR-014: additionalDirectories widens agent file access beyond the
        // workspace boundary — surfaced per directory, path string only.
        const extra = permissions?.["additionalDirectories"];
        for (const raw of (Array.isArray(extra) ? extra : []).map(String).sort()) {
            out.capabilities.push({
                kind: "externalDirectoryAccess",
                summary: `Agent file access extends beyond the workspace to an additional directory ("${raw}")`,
                resource: raw,
                source: rel,
                detail: { additionalDirectory: true },
            });
        }
    }
    return out;
}
export const claudeDetector = { id: "claude", detect };
