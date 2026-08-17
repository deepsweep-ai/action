import { mcpDetector } from "./mcp.js";
import { claudeDetector } from "./claude.js";
import { cursorDetector } from "./cursor.js";
import { devcontainerDetector } from "./devcontainer.js";
import { copilotDetector } from "./copilot.js";
import { windsurfDetector } from "./windsurf.js";
import { antigravityDetector } from "./antigravity.js";
import { traeDetector } from "./trae.js";
import { envDetector, gitDetector } from "./workspace.js";
export const DETECTORS = Object.freeze([
    mcpDetector,
    claudeDetector,
    cursorDetector,
    devcontainerDetector,
    copilotDetector,
    windsurfDetector,
    // Appended, never inserted: the array order is the report's emission order,
    // so placing a new family mid-list would reshuffle every golden vector for
    // reasons unrelated to the new coverage.
    antigravityDetector,
    traeDetector,
    gitDetector,
    envDetector,
]);
