/**
 * Local review baseline — persistence per ADR-003.
 *  - Single metadata-only JSON file at .deepsweep/baseline.json in the
 *    workspace root; machine-local; recommended for gitignore (Review never
 *    mutates user files, so nothing writes the entry); format is designed to
 *    be safe to commit (redacted, path-free, basename-only workspace id).
 *  - Written at exactly two moments: first-run creation, and explicit re-pin
 *    via --update-baseline. Never implicitly, never on watch shutdown.
 *  - Regenerate-not-migrate: unknown/newer/corrupt schemaVersion or a foreign
 *    workspace basename discards and regenerates (warning severity when a
 *    baseline previously existed; info only on true first-run creation).
 *  - Containment (extends ADR-002 to writes): refuse if .deepsweep/ or
 *    baseline.json is a symlink or its realpath escapes the workspace root;
 *    atomic write via O_CREAT|O_EXCL mode-0600 temp file inside .deepsweep/
 *    (same filesystem → atomic rename); reads enforce realpath containment,
 *    regular-file check, and the MAX_FILE_BYTES cap. The containment/write
 *    primitives live in store.ts (extracted in S2.1 so the identity store
 *    reuses the same audited code); behavior here is byte-identical to the
 *    pre-extraction implementation.
 */
import { basename, resolve } from "node:path";
import { sha256Hex } from "./canonical.js";
import { readStoreText, STORE_DIR, writeStoreAtomic } from "./store.js";
import { countNoun } from "./text.js";
export const BASELINE_DIR = STORE_DIR;
export const BASELINE_FILE = "baseline.json";
export const BASELINE_REL_PATH = `${BASELINE_DIR}/${BASELINE_FILE}`;
/** Raised when containment invariants forbid touching the baseline at all. */
export class BaselineRefusalError extends Error {
    constructor(reason) {
        super(`baseline refused: ${reason} — remove the offending symlink/path and re-run the review`);
        this.name = "BaselineRefusalError";
    }
}
/** Refusal-error factory handed to the shared contained-store primitives. */
const refuse = (reason) => new BaselineRefusalError(reason);
function readBaselineText(workspaceRoot) {
    return readStoreText(workspaceRoot, BASELINE_FILE, refuse);
}
function isStringArray(v) {
    return Array.isArray(v) && v.every((x) => typeof x === "string");
}
function isPinnedEntity(v) {
    if (typeof v !== "object" || v === null)
        return false;
    const r = v;
    return ((r["entityType"] === "mcpServer" || r["entityType"] === "toolDescription") &&
        typeof r["logicalName"] === "string" &&
        typeof r["source"] === "string" &&
        typeof r["contentHash"] === "string");
}
/**
 * Load the baseline with full containment checks.
 * Throws BaselineRefusalError only for containment violations; every other
 * failure degrades to a regenerable status (regenerate-not-migrate).
 */
export function loadBaseline(workspaceRoot) {
    const text = readBaselineText(workspaceRoot);
    if (text === undefined)
        return { status: "absent" };
    const fileHash = sha256Hex(text);
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return { status: "invalid", reason: "corrupt" };
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return { status: "invalid", reason: "corrupt" };
    }
    const r = parsed;
    if (r["schemaVersion"] !== 1)
        return { status: "invalid", reason: "unknownSchemaVersion" };
    if (typeof r["workspace"] !== "string" || r["workspace"] !== basename(resolve(workspaceRoot))) {
        return { status: "invalid", reason: "foreignWorkspace" };
    }
    const entities = r["entities"];
    if (typeof r["createdAt"] !== "string" ||
        typeof r["lastPinnedAt"] !== "string" ||
        typeof r["entityCount"] !== "number" ||
        !isStringArray(r["reviewedSources"]) ||
        typeof r["rawFileHashes"] !== "object" ||
        r["rawFileHashes"] === null ||
        !Array.isArray(entities) ||
        !entities.every(isPinnedEntity)) {
        return { status: "invalid", reason: "corrupt" };
    }
    return { status: "ok", baseline: r, fileHash };
}
/** Pure construction; preserves createdAt across explicit re-pins. */
export function buildBaseline(workspaceBasename, extraction, nowIso, previous) {
    return {
        schemaVersion: 1,
        workspace: workspaceBasename,
        createdAt: previous?.createdAt ?? nowIso,
        lastPinnedAt: nowIso,
        entityCount: extraction.entities.length,
        reviewedSources: extraction.sources,
        rawFileHashes: extraction.rawFileHashes,
        entities: extraction.entities,
    };
}
/**
 * Atomic, contained baseline write (ADR-003 moments only: first-run creation
 * or explicit re-pin). Returns the SHA-256 of the written bytes so the watch
 * session can track its in-memory tamper-check hash.
 */
export function writeBaseline(workspaceRoot, baseline) {
    // Containment + atomic-write mechanics (check → mkdir → re-check → atomic
    // rename, incl. the accepted S1.4 P3 TOCTOU residual) live in store.ts,
    // extracted verbatim from this write path.
    const text = `${JSON.stringify(baseline, null, 2)}\n`;
    return writeStoreAtomic(workspaceRoot, BASELINE_FILE, text, refuse);
}
/**
 * Hash the on-disk baseline for the in-session tamper check (ADR-003
 * mitigation 3). Returns undefined when absent/unreadable — the caller
 * treats any divergence from the in-memory hash as baseline.tampered
 * (fail-suspicious by design).
 */
export function hashBaselineOnDisk(workspaceRoot) {
    let text;
    try {
        text = readBaselineText(workspaceRoot);
    }
    catch {
        return undefined; // refusal at check time is also suspicious
    }
    return text === undefined ? undefined : sha256Hex(text);
}
// ---- Baseline lifecycle findings (event kinds per ADR-004) ----
export function baselineCreatedFinding(entityCount) {
    return {
        kind: "baseline.created",
        severity: "info",
        resource: BASELINE_REL_PATH,
        source: BASELINE_REL_PATH,
        entityHash: null,
        explanation: `Baseline created at ${BASELINE_REL_PATH} — ${countNoun(entityCount, "entity", "entities")} pinned. Recommended: add ${BASELINE_DIR}/ to .gitignore (Review never mutates your files, so it will not write that entry for you).`,
    };
}
export function baselineRegeneratedFinding(reason) {
    return {
        kind: "baseline.regenerated",
        severity: "warning",
        resource: BASELINE_REL_PATH,
        source: BASELINE_REL_PATH,
        entityHash: null,
        explanation: `Baseline was discarded and regenerated (${reason}) — all pinned trust state was reset; a full re-review is required before continuing to trust this environment.`,
    };
}
export function baselineTamperedFinding(expectedHash, foundHash) {
    return {
        kind: "baseline.tampered",
        severity: "high",
        resource: BASELINE_REL_PATH,
        source: BASELINE_REL_PATH,
        entityHash: foundHash ?? null,
        explanation: `Baseline file changed on disk outside this watch session (expected sha256 ${expectedHash.slice(0, 12)}…, found ${foundHash ? `${foundHash.slice(0, 12)}…` : "missing"}) — possible drift suppression over a poisoned environment. Verify: re-run the review and compare the disclosed provenance. A legitimate concurrent --update-baseline from another process also raises this (fail-suspicious by design).`,
    };
}
