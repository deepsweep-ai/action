/**
 * GitHub Copilot agent-config detector.
 * Covers well-known repository locations:
 *  - .github/copilot-instructions.md   (repo-wide instructions, auto-loaded)
 *  - .github/instructions/             (scoped *.instructions.md — NAMES only)
 *  - .github/workflows/copilot-setup-steps.yml|.yaml (Copilot coding agent
 *    setup steps — presence only; YAML content is not parsed, keeping the
 *    zero-dependency posture, so this degrades to a presence-based
 *    shellExecution capability rather than per-step extraction)
 *  - AGENTS.md                         (open agent-instructions convention)
 *  - .vscode/settings.json             (ADR-014: github.copilot.chat.* keys —
 *    key NAMES and boolean posture only; free-text values such as custom
 *    instructions are never surfaced. Auto-approval-shaped keys set true
 *    surface as autoApproval capabilities; other copilot.chat keys surface
 *    as a key-name-only agentInstructions presence.)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 */
import { exists, parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { asRecord, dirNamesOrWarn, nameList, unreadableWarning, visibleNames } from "./util.js";
import { countNoun } from "../text.js";
const INSTRUCTIONS_FILE = ".github/copilot-instructions.md";
const INSTRUCTIONS_DIR = ".github/instructions";
const SETUP_WORKFLOWS = [
    ".github/workflows/copilot-setup-steps.yml",
    ".github/workflows/copilot-setup-steps.yaml",
];
const AGENTS_FILE = "AGENTS.md";
const VSCODE_SETTINGS = ".vscode/settings.json";
const COPILOT_CHAT_PREFIX = "github.copilot.chat.";
/** Key-name shapes that amount to auto-approval / autonomous-agent posture. */
const AUTO_APPROVE_SHAPED = /(autoApprove|autoAccept|agent\.|terminal|experimental\.agent)/i;
function detect(workspaceRoot) {
    const out = emptyResult();
    if (exists(workspaceRoot, INSTRUCTIONS_FILE)) {
        out.reviewedSources.push(INSTRUCTIONS_FILE);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "Copilot repository instructions auto-load into agent context for every session",
            resource: INSTRUCTIONS_FILE,
            source: INSTRUCTIONS_FILE,
        });
    }
    const scoped = visibleNames(dirNamesOrWarn(workspaceRoot, INSTRUCTIONS_DIR, out.warnings)).filter((n) => n.endsWith(".instructions.md"));
    if (scoped.length > 0) {
        out.reviewedSources.push(INSTRUCTIONS_DIR);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: `${countNoun(scoped.length, "scoped Copilot instruction file auto-applies", "scoped Copilot instruction files auto-apply")} to matching files`,
            resource: INSTRUCTIONS_DIR,
            source: INSTRUCTIONS_DIR,
            detail: { fileCount: scoped.length, fileNames: nameList(scoped) },
        });
    }
    for (const rel of SETUP_WORKFLOWS) {
        if (!exists(workspaceRoot, rel))
            continue;
        out.reviewedSources.push(rel);
        out.capabilities.push({
            kind: "shellExecution",
            summary: "Copilot coding agent setup workflow runs shell steps before agent sessions",
            resource: rel,
            source: rel,
            detail: { presenceOnly: true },
        });
    }
    // ADR-014: VS Code Copilot chat/agent settings — key names + boolean
    // posture only; string values (custom instructions etc.) never surface.
    // S1.14: a present-but-unreadable settings file degrades to a
    // metadata-only warning, never to silence.
    const settingsProbe = probeRead(workspaceRoot, VSCODE_SETTINGS);
    if (settingsProbe.status === "unreadable") {
        out.warnings.push(unreadableWarning(VSCODE_SETTINGS, settingsProbe.reason));
    }
    else if (settingsProbe.status === "ok") {
        const settings = asRecord(parseTolerantJson(settingsProbe.text));
        if (settings !== undefined) {
            const copilotKeys = Object.keys(settings)
                .filter((k) => k.startsWith(COPILOT_CHAT_PREFIX))
                .sort();
            if (copilotKeys.length > 0) {
                out.reviewedSources.push(VSCODE_SETTINGS);
                const autoKeys = copilotKeys.filter((k) => AUTO_APPROVE_SHAPED.test(k.slice(COPILOT_CHAT_PREFIX.length)) && settings[k] === true);
                for (const key of autoKeys) {
                    out.capabilities.push({
                        kind: "autoApproval",
                        summary: `Copilot setting "${key}" enables agent actions without a per-action decision`,
                        resource: key,
                        source: VSCODE_SETTINGS,
                        detail: { broad: true, scope: "workspace" },
                    });
                }
                const rest = copilotKeys.filter((k) => !autoKeys.includes(k));
                if (rest.length > 0) {
                    out.capabilities.push({
                        kind: "agentInstructions",
                        summary: `${countNoun(rest.length, "Copilot chat setting shapes", "Copilot chat settings shape")} agent behavior in this workspace`,
                        resource: VSCODE_SETTINGS,
                        source: VSCODE_SETTINGS,
                        detail: { keyCount: rest.length, keyNames: nameList(rest) },
                    });
                }
            }
        }
        // Malformed settings.json is NOT warned here: the file serves many
        // non-Copilot purposes and the mcp detector already reviews .vscode/;
        // a PARSE failure on a general-purpose settings file is not a malformed
        // agent config. UNREADABLE (above) is different: S1.14 surfaces it.
    }
    if (exists(workspaceRoot, AGENTS_FILE)) {
        out.reviewedSources.push(AGENTS_FILE);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "AGENTS.md instructions auto-load into coding agent context",
            resource: AGENTS_FILE,
            source: AGENTS_FILE,
        });
    }
    return out;
}
export const copilotDetector = { id: "copilot", detect };
