/**
 * Workspace posture detectors — git repository write surface and secrets
 * exposure (.env* presence + KEY NAMES ONLY; values never read into reports).
 * Fixed allowlist per ADR-002.
 */
import { envKeyNames, exists, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { unreadableWarning } from "./util.js";
import { countNoun } from "../text.js";
const ENV_PATHS = [".env", ".env.local", ".env.production"];
function detectGit(workspaceRoot) {
    const out = emptyResult();
    if (exists(workspaceRoot, ".git", "directory")) {
        out.reviewedSources.push(".git");
        out.capabilities.push({
            kind: "repositoryWrite",
            summary: "Workspace is a git repository — agents with file/shell access can commit and push",
            resource: "git repository",
            source: ".git",
        });
    }
    return out;
}
function detectEnv(workspaceRoot) {
    const out = emptyResult();
    for (const rel of ENV_PATHS) {
        // S1.14: absent evidence must be visible — a present-but-unreadable env
        // file degrades to a metadata-only warning (path + reason class; key
        // names and values never ride on a refusal), never to silence.
        const probe = probeRead(workspaceRoot, rel);
        if (probe.status === "absent")
            continue;
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(rel, probe.reason));
            continue;
        }
        out.reviewedSources.push(rel);
        const keys = envKeyNames(probe.text);
        if (keys.length > 0) {
            out.capabilities.push({
                kind: "secretsExposure",
                summary: `${countNoun(keys.length, "secret key")} readable by any agent with file access (${rel})`,
                resource: rel,
                source: rel,
                detail: { keyCount: keys.length, keyNames: keys.slice(0, 10).join(", ") },
            });
        }
    }
    return out;
}
export const gitDetector = { id: "git", detect: detectGit };
export const envDetector = { id: "env", detect: detectEnv };
