import { mcpDetector } from "./mcp.js";
import { claudeDetector } from "./claude.js";
import { cursorDetector } from "./cursor.js";
import { devcontainerDetector } from "./devcontainer.js";
import { copilotDetector } from "./copilot.js";
import { windsurfDetector } from "./windsurf.js";
import { envDetector, gitDetector } from "./workspace.js";
export const DETECTORS = Object.freeze([
    mcpDetector,
    claudeDetector,
    cursorDetector,
    devcontainerDetector,
    copilotDetector,
    windsurfDetector,
    gitDetector,
    envDetector,
]);
