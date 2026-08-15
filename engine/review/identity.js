/**
 * S2.1 — AgentIdentity records + stable Agent IDs (ADR-005, the BINDING
 * contract for this module).
 *
 * An Agent is an agent *installation observed in a workspace*, keyed by
 * (agentType, workspace):
 *  - `agentType` is derived from which allowlisted config surfaces exist —
 *    the detectors already discriminate them; the set evolves ADDITIVELY like
 *    CapabilityKind. Generic surfaces attributable to no specific agent
 *    product (.env*, .git, AGENTS.md, .deepsweep/*) map to no agent type.
 *  - `workspace` is the root BASENAME only (ADR-003). Same-basename clones
 *    collide by design, exactly as pins do.
 *  - agentId = "agt_" + first 16 hex of
 *    SHA-256(canonicalize({ schemaVersion: 1, agentType, workspace }))
 *    using the ONE canonicalizer (canonical.ts). 64 bits is sufficient
 *    because agentId is an ATTRIBUTION identifier, never an authority bearer.
 *
 * Trust model (ADR-005, binding): everything here is a CLAIM by the subject
 * about itself — attestation level `claimed`. Every rendered surface must use
 * the "agent claiming to be X" phrasing (claimedIdentityClaim below is the
 * single source of that copy) and never present a claimed identity as
 * authenticated. Containment of authority (binding-before-E4): the identity
 * store is attribution-for-explainability ONLY — no code path may treat a
 * store-resolved record as ground truth or broaden any outcome on agentId
 * equality; principal fill uses fresh derivation (principalFor), never a
 * store lookup. A contract test (tests/identity.test.ts) guards this.
 *
 * Storage: `.deepsweep/identity.json` — a registry of observed agents,
 * SEPARATE from the baseline so attribution continuity SURVIVES baseline
 * resets. Inherits every ADR-003 containment/content invariant verbatim via
 * the shared store primitives (store.ts): symlink/realpath refusal,
 * regular-file check, size cap, atomic 0600 writes, metadata-only,
 * basename-only, safe-to-commit, regenerate-not-migrate (warning-severity
 * `identity.regenerated`), and the agent-writable threat note unchanged. The
 * store has NO tamper story until S2.3/E4 (ADR-005 F2) — records are
 * explainability, never authority.
 *
 * Owner (ADR-005 F1, transient-only): the claimed owner (git `user.email`,
 * read under ADR-002 containment via safeRead) is held at runtime for local
 * human display only. It is NEVER written to identity.json, any event, the
 * --json dump, or any artifact. The OS username is NEVER read at any tier.
 * ADR-002 allowlist extension (S2.1): `.git/config` — presence + the
 * user.email value, read transiently, never persisted.
 */
import { basename, resolve } from "node:path";
import { canonicalize, sha256Hex } from "./canonical.js";
import { safeRead } from "./read.js";
import { readStoreText, STORE_DIR, writeStoreAtomic } from "./store.js";
export const IDENTITY_FILE = "identity.json";
export const IDENTITY_REL_PATH = `${STORE_DIR}/${IDENTITY_FILE}`;
/** Raised when containment invariants forbid touching the identity store. */
export class IdentityRefusalError extends Error {
    constructor(reason) {
        super(`identity store refused: ${reason} — remove the offending symlink/path and re-run the review`);
        this.name = "IdentityRefusalError";
    }
}
const refuse = (reason) => new IdentityRefusalError(reason);
// ------------------------------------------------------------- derivation
/**
 * The stable Agent ID (ADR-005): deterministic, metadata-only, byte-stable
 * across runs and machines. Reuses the ONE canonicalizer + hash (ADR-003).
 * Deliberately excludes owner and session data so the ID cannot churn when
 * they change.
 */
export function deriveAgentId(agentType, workspace) {
    return `agt_${sha256Hex(canonicalize({ schemaVersion: 1, agentType, workspace })).slice(0, 16)}`;
}
/**
 * Map an allowlisted reviewed-source path to the agent surface it belongs to.
 * Returns undefined for generic surfaces attributable to no specific agent
 * product (.env*, .git, AGENTS.md — an open convention, not one product —
 * and .deepsweep/*). `.mcp.json` is the Claude Code project-level MCP config;
 * `.vscode/mcp.json` is the VS Code (Copilot agent mode) MCP config.
 */
export function agentTypeForSource(source) {
    if (source === ".cursorrules" || source.startsWith(".cursor/"))
        return "cursor";
    if (source === ".mcp.json" || source.startsWith(".claude/"))
        return "claude-code";
    if (source === ".vscode/mcp.json" ||
        source === ".github/copilot-instructions.md" ||
        source.startsWith(".github/instructions/") ||
        source.startsWith(".github/workflows/copilot-setup-steps.")) {
        return "copilot";
    }
    if (source === ".windsurfrules" || source.startsWith(".windsurf/"))
        return "windsurf";
    if (source === ".devcontainer.json" || source.startsWith(".devcontainer/"))
        return "devcontainer";
    return undefined;
}
/** Distinct agent types observed in a run's reviewed sources, sorted. */
export function observedAgentTypes(reviewedSources) {
    const types = new Set();
    for (const source of reviewedSources) {
        const t = agentTypeForSource(source);
        if (t !== undefined)
            types.add(t);
    }
    return [...types].sort();
}
/**
 * The `principal` fill for drift events (ADR-004 promise, ADR-005 semantics):
 * the agentId STRING claimed by the config surface a finding originates from,
 * derived FRESH from (agentType, workspace) — never resolved from the store
 * (containment of authority: the store is display/continuity only). Returns
 * undefined (→ `principal: null`) for sources owned by no specific agent.
 */
export function principalFor(source, workspace) {
    const agentType = agentTypeForSource(source);
    return agentType === undefined ? undefined : deriveAgentId(agentType, workspace);
}
/**
 * The ONE place the claimed-identity phrasing is defined (ADR-005 normative
 * rule: never present claimed identity as authenticated). Every surface
 * renders this copy through its S1.9 sanitizer.
 */
export function claimedIdentityClaim(agentType) {
    return `agent claiming to be ${agentType}`;
}
// ------------------------------------------------------------------ store
function isIdentityRecord(v) {
    if (typeof v !== "object" || v === null)
        return false;
    const r = v;
    return (typeof r["agentId"] === "string" &&
        /^agt_[0-9a-f]{16}$/.test(r["agentId"]) &&
        typeof r["agentType"] === "string" &&
        typeof r["workspace"] === "string" &&
        typeof r["firstObservedAt"] === "string" &&
        (r["lastObservedAt"] === undefined || typeof r["lastObservedAt"] === "string") &&
        r["attestation"] === "claimed");
}
/**
 * Load the identity registry with full containment checks. Throws
 * IdentityRefusalError only for containment violations; every other failure
 * degrades to a regenerable status (regenerate-not-migrate, ADR-003 rule
 * inherited by ADR-005).
 */
export function loadIdentity(workspaceRoot) {
    const text = readStoreText(workspaceRoot, IDENTITY_FILE, refuse);
    if (text === undefined)
        return { status: "absent" };
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
    const agents = r["agents"];
    if (!Array.isArray(agents) || !agents.every(isIdentityRecord)) {
        return { status: "invalid", reason: "corrupt" };
    }
    return { status: "ok", identity: r };
}
/** Atomic, contained identity-store write (shared store primitives). */
export function writeIdentity(workspaceRoot, identity) {
    writeStoreAtomic(workspaceRoot, IDENTITY_FILE, `${JSON.stringify(identity, null, 2)}\n`, refuse);
}
/**
 * Observe the current run's agents and reconcile the registry: previously
 * observed records are KEPT (continuity survives baseline resets — that is
 * the store's entire reason to exist), newly observed agents are appended
 * with firstObservedAt = nowIso, and an invalid store is discarded and
 * regenerated (warning-severity identity.regenerated — losing the registry
 * resets attribution continuity and must be visible). The store is written
 * only when the registry changed. May throw IdentityRefusalError on
 * containment violations (CLI exit 3).
 */
export function observeIdentities(workspaceRoot, reviewedSources, nowIso) {
    const workspace = basename(resolve(workspaceRoot));
    const findings = [];
    const loaded = loadIdentity(workspaceRoot);
    let records;
    let mustWrite = false;
    if (loaded.status === "ok") {
        records = [...loaded.identity.agents];
    }
    else {
        records = [];
        if (loaded.status === "invalid") {
            findings.push(identityRegeneratedFinding(loaded.reason));
            mustWrite = true; // replace the discarded store even if nothing is observed
        }
    }
    const byId = new Map(records.map((r) => [r.agentId, r]));
    for (const agentType of observedAgentTypes(reviewedSources)) {
        const agentId = deriveAgentId(agentType, workspace);
        const existing = byId.get(agentId);
        if (existing !== undefined) {
            // ADR-011: refresh lastObservedAt at UTC-day granularity only — the
            // staleness detector's unit is days, and day-granular writes bound
            // store churn (no rewrite on every run, no watch-mode feedback risk).
            const lastDay = (existing.lastObservedAt ?? existing.firstObservedAt).slice(0, 10);
            if (lastDay !== nowIso.slice(0, 10)) {
                records[records.indexOf(existing)] = { ...existing, lastObservedAt: nowIso };
                mustWrite = true;
            }
            continue;
        }
        records.push({ agentId, agentType, workspace, firstObservedAt: nowIso, attestation: "claimed" });
        mustWrite = true;
    }
    if (mustWrite) {
        // Same check → mkdir → re-check → atomic-rename path as the baseline.
        writeIdentity(workspaceRoot, { schemaVersion: 1, workspace, agents: records });
    }
    return { records, findings };
}
// -------------------------------------------------------- owner (transient)
/**
 * Claimed owner: git `user.email` from `.git/config`, read under ADR-002
 * containment (safeRead — symlink/realpath refusal, size cap). TRANSIENT
 * ONLY (ADR-005 F1): callers may show it on local human surfaces (text
 * report, watch header) and must never persist or emit it — a planted-owner
 * fixture in tests/identity.test.ts proves the composition. Returns
 * undefined when absent or unparseable. The OS username is never read.
 */
export function readClaimedOwner(workspaceRoot) {
    const text = safeRead(workspaceRoot, ".git/config");
    if (text === undefined)
        return undefined;
    let inUserSection = false;
    for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (line.startsWith("[")) {
            inUserSection = /^\[user\]/i.test(line);
            continue;
        }
        if (!inUserSection)
            continue;
        const m = /^email\s*=\s*(.+)$/i.exec(line);
        if (m?.[1] !== undefined) {
            const value = m[1].trim();
            if (value !== "")
                return value;
        }
    }
    return undefined;
}
// ------------------------------------------------- lifecycle finding (ADR-005)
export function identityRegeneratedFinding(reason) {
    return {
        kind: "identity.regenerated",
        severity: "warning",
        resource: IDENTITY_REL_PATH,
        source: IDENTITY_REL_PATH,
        entityHash: null,
        explanation: `Agent identity registry was discarded and regenerated (${reason}) — attribution continuity for previously observed agents was reset. Identity records are claims, not verified identities; re-review before continuing to trust attribution in this environment.`,
    };
}
