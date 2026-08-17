/**
 * Cursor detector — workspace rules and hooks.
 * Covers: .cursorrules (legacy root rules), .cursor/rules/ (rule files,
 * NAMES only — contents are agent instructions, not read here), and
 * .cursor/hooks.json (hooks run local commands around agent actions).
 * Cursor's MCP config (.cursor/mcp.json) is covered by the mcp detector.
 * Fixed allowlist per ADR-002 — no globbing, names only for directories.
 */
import { exists, parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { asRecord, asString, dirNamesOrWarn, isBlankDocument, malformedWarning, nameList, unreadableWarning, visibleNames, } from "./util.js";
import { countNoun } from "../text.js";
const RULES_FILE = ".cursorrules";
const RULES_DIR = ".cursor/rules";
const HOOKS_FILE = ".cursor/hooks.json";
function detect(workspaceRoot) {
    const out = emptyResult();
    // 1) Legacy root rules file (presence only — content is instruction text).
    if (exists(workspaceRoot, RULES_FILE)) {
        out.reviewedSources.push(RULES_FILE);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "Cursor rules file auto-loads workspace instructions into every agent session",
            resource: RULES_FILE,
            source: RULES_FILE,
        });
    }
    // 2) Rules directory (entry names only; one nested level — .cursor/rules/**
    // in practice is flat-or-one-subdir; deeper nesting stays out of the
    // allowlist architecture deliberately, no globbing ever).
    const topEntries = visibleNames(dirNamesOrWarn(workspaceRoot, RULES_DIR, out.warnings));
    const nested = topEntries.flatMap((entry) => visibleNames(dirNamesOrWarn(workspaceRoot, `${RULES_DIR}/${entry}`, out.warnings)).map((n) => `${entry}/${n}`));
    const ruleFiles = [...topEntries.filter((e) => !nested.some((n) => n.startsWith(`${e}/`))), ...nested].sort();
    if (ruleFiles.length > 0) {
        out.reviewedSources.push(RULES_DIR);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: `${countNoun(ruleFiles.length, "Cursor rule file auto-applies", "Cursor rule files auto-apply")} workspace instructions to agent sessions`,
            resource: RULES_DIR,
            source: RULES_DIR,
            detail: { fileCount: ruleFiles.length, fileNames: nameList(ruleFiles) },
        });
    }
    // 3) Hooks — each configured hook runs a local command around agent actions.
    // S1.14: absent evidence must be visible — a present-but-unreadable hooks
    // file degrades to a metadata-only warning, never to silence.
    const hooksProbe = probeRead(workspaceRoot, HOOKS_FILE);
    if (hooksProbe.status === "unreadable") {
        out.warnings.push(unreadableWarning(HOOKS_FILE, hooksProbe.reason));
    }
    else if (hooksProbe.status === "ok") {
        out.reviewedSources.push(HOOKS_FILE);
        const json = asRecord(parseTolerantJson(hooksProbe.text));
        const hooks = asRecord(json?.["hooks"]);
        if (json === undefined || hooks === undefined) {
            // An empty file is nothing configured, not malformed — the guard
            // nests here so the else-branch keeps its type narrowing.
            if (!isBlankDocument(hooksProbe.text))
                out.warnings.push(malformedWarning(HOOKS_FILE));
        }
        else {
            for (const event of Object.keys(hooks).sort()) {
                const entries = hooks[event];
                const list = Array.isArray(entries) ? entries : [entries];
                for (const entry of list) {
                    const command = asString(asRecord(entry)?.["command"]) ?? asString(entry);
                    if (command === undefined)
                        continue;
                    out.capabilities.push({
                        kind: "shellExecution",
                        summary: `Cursor hook "${event}" runs a local command ("${command}") around agent actions`,
                        resource: command,
                        source: HOOKS_FILE,
                        detail: { event },
                    });
                }
            }
        }
    }
    return out;
}
export const cursorDetector = { id: "cursor", detect };
