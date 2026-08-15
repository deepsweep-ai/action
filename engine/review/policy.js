import { canonicalize, sha256Hex } from "./canonical.js";
import { verifyBundle } from "./bundle.js";
import { readStoreText, STORE_DIR, writeStoreAtomic } from "./store.js";
import { safeReadUser } from "./read.js";
import { sanitizeField } from "./sanitize.js";
import { selfProtectionOverrideAttempts, selfProtectionRefusalReason } from "./self-protect.js";
export const POLICY_SCHEMA_VERSION = 1;
/** The single policy document (ADR-009 storage section). */
export const POLICY_FILE = "policy.json";
export const POLICY_REL_PATH = `${STORE_DIR}/${POLICY_FILE}`;
export const ACTION_VOCABULARY = [
    "environment.change",
    "tool.invoke",
    "shell.execute",
    "repository.write",
    "secrets.access",
    "container.mount",
    "network.expose",
    "approval.auto",
];
/**
 * The 1:1 CapabilityKind → action mapping table AS CODE (ADR-009): a detected
 * capability and the policy action that governs it are the same word. Total
 * over CapabilityKind (guarded by a unit test); actions may be shared by
 * several kinds (many kinds, one governing verb). `approval.auto` is the
 * S1.x autoApproval capability rendered policy-referenceable so it can be
 * DENIED.
 */
export const CAPABILITY_ACTION = {
    shellExecution: "shell.execute",
    repositoryWrite: "repository.write",
    mcpToolAccess: "tool.invoke",
    secretsExposure: "secrets.access",
    autoApproval: "approval.auto",
    agentInstructions: "environment.change",
    externalDirectoryAccess: "environment.change",
    containerMount: "container.mount",
    portExposure: "network.expose",
    privilegedContainer: "container.mount",
};
/**
 * Agent types keyable by the `{agentType}` selector (ADR-005 derivation
 * inputs). Kept in lockstep with `AgentType` via `satisfies`; a unit test
 * guards totality so a new agent type cannot silently become unkeyable.
 */
export const AGENT_TYPES = [
    "cursor",
    "claude-code",
    "copilot",
    "windsurf",
    "devcontainer",
];
const ATTESTATION_TIERS = ["claimed", "session-observed"];
// -------------------------------------------------------- canonical + hash
/**
 * Byte-identical canonical serialization via the ONE canonicalizer (ADR-003,
 * reused not forked): sorted keys, minimal escaping, string values
 * byte-preserved. Two policies differing in any code point serialize (and
 * hash) differently.
 */
export function canonicalPolicy(policy) {
    return canonicalize(policy);
}
/**
 * SHA-256 of a single rule's canonicalized content — the version-pinning half
 * of a future PolicyDecision's `policyRef` (ADR-009 explainability). Defined
 * here so S3.2 fills it rather than inventing it.
 */
export function policyRuleHash(rule) {
    return sha256Hex(canonicalize(rule));
}
// -------------------------------------------------------------- refusal
/** Raised when containment invariants forbid touching the policy store. */
export class PolicyRefusalError extends Error {
    constructor(reason) {
        super(`policy store refused: ${reason} — remove the offending symlink/path and re-run the review`);
        this.name = "PolicyRefusalError";
    }
}
const policyRefuse = (reason) => new PolicyRefusalError(reason);
/** Bounds attacker fan-out from a maliciously huge broken policy file. */
export const MAX_POLICY_REASONS = 20;
// --------------------------------------------------------------- helpers
function isPlainObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
/** Sanitize any authored token before it enters a reason/finding surface. */
function tok(s) {
    return sanitizeField(s);
}
/**
 * Resource matcher validation (ADR-009 "Resource matchers", the leak-class
 * defense). Resource patterns are MATCH-ONLY and never dereferenced, so
 * path-traversal is structurally inapplicable. REJECT absolute-path / authority
 * shapes (they can never match basename-only, workspace-relative emitted
 * identifiers AND are a leak vector): a leading `/` or `\`, a Windows drive
 * prefix (`X:` / `X:\`), a URL-authority shape (`scheme://host…`). The `*`
 * wildcard is permitted ONLY as a single trailing character (`github/*`); full
 * glob/regex is rejected. Returns an error reason, or undefined when valid.
 */
/**
 * The absolute-path / authority shapes REJECTED from any free-text matcher slot
 * (ADR-009 "Resource matchers", the leak-class defense): a leading `/` or `\`
 * (POSIX absolute path), a Windows drive prefix (`X:` / `X:\`), or a
 * URL-authority shape (`scheme://host…`). Findings emit basename-only,
 * workspace-relative identifiers, so any of these is both unmatchable and a
 * leak vector. Factored so the resource slot AND `PolicySet.workspace`
 * (forward-note c) reject the SAME shapes through one predicate. Returns the
 * offending shape, or undefined when the value carries none.
 */
function absPathOrAuthorityShape(value) {
    if (value[0] === "/" || value[0] === "\\")
        return "abs";
    if (/^[A-Za-z]:/.test(value))
        return "drive";
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value))
        return "url";
    return undefined;
}
function resourceError(resource) {
    if (typeof resource !== "string")
        return "resource must be a string";
    if (resource.length === 0)
        return "resource must be a non-empty pattern";
    const shape = absPathOrAuthorityShape(resource);
    if (shape === "abs") {
        return `resource pattern "${tok(resource)}" has an absolute-path shape (leading / or \\); findings emit workspace-relative identifiers only`;
    }
    if (shape === "drive") {
        return `resource pattern "${tok(resource)}" has a Windows drive-absolute shape (X:); findings emit workspace-relative identifiers only`;
    }
    if (shape === "url") {
        return `resource pattern "${tok(resource)}" has a URL-authority shape (scheme://host); findings emit logical identifiers only`;
    }
    const star = resource.indexOf("*");
    if (star !== -1 && star !== resource.length - 1) {
        return `resource pattern "${tok(resource)}" uses "*" other than as a single trailing prefix wildcard; full glob/regex is rejected`;
    }
    return undefined;
}
/**
 * Action matcher validation (ADR-009 "Action vocabulary"). Valid: an exact
 * vocabulary word; a trailing `.*` prefix whose stem is a real vocabulary
 * namespace (so `foo.*`, matching nothing, is a rejected dead rule); or the
 * bare `*` — the last ONLY for narrowing variants. Returns an error reason, or
 * undefined when valid.
 */
function actionError(action, allowBareWildcard) {
    if (typeof action !== "string")
        return "action must be a string";
    if (action === "*") {
        return allowBareWildcard
            ? undefined
            : 'the bare "*" action is not available to the allow variant ("allow everything" is unwritable by design)';
    }
    if (action.endsWith(".*")) {
        const stem = action.slice(0, -2);
        if (stem.length === 0)
            return `action "${tok(action)}" has an empty wildcard stem`;
        const known = ACTION_VOCABULARY.some((a) => a.startsWith(`${stem}.`));
        return known
            ? undefined
            : `action "${tok(action)}" wildcards an unknown namespace; the action vocabulary is closed`;
    }
    return ACTION_VOCABULARY.includes(action)
        ? undefined
        : `action "${tok(action)}" is not in the closed action vocabulary`;
}
const PRINCIPAL_ID_RE = /^agt_[0-9a-f]{16}$/;
/**
 * Principal selector validation for the NARROWING variants. `"*"`, an exact
 * `{agentId}` (the ADR-005 derived-ID shape), or an `{agentType}` from the
 * closed set. Any other object shape (notably an owner selector) is rejected.
 */
function principalError(sel) {
    if (sel === "*")
        return undefined;
    if (!isPlainObject(sel)) {
        return 'principal must be "*" or a single-key {agentId} / {agentType} selector';
    }
    const keys = Object.keys(sel);
    if (keys.length !== 1) {
        return `principal selector must have exactly one key, found: ${keys.map((k) => tok(k)).join(", ")}`;
    }
    // switch on the KEY NAME (not on any identity value) — schema shape
    // dispatch, never an authority branch (ADR-005 guard, identity.test.ts).
    const key = keys[0];
    switch (key) {
        case "agentId": {
            const id = sel[key];
            return typeof id === "string" && PRINCIPAL_ID_RE.test(id)
                ? undefined
                : "principal agentId must be an agt_<16 hex> derived identifier";
        }
        case "agentType": {
            const t = sel[key];
            return typeof t === "string" && AGENT_TYPES.includes(t)
                ? undefined
                : `principal agentType "${typeof t === "string" ? tok(t) : String(t)}" is not a known agent type`;
        }
        default:
            return `unknown principal selector "${tok(key)}"; only {agentId} and {agentType} exist (no owner selector)`;
    }
}
/** Validate one condition atom (exactly one known key, correct value type). */
function conditionAtomError(atom) {
    if (!isPlainObject(atom))
        return "condition atom must be an object";
    const keys = Object.keys(atom);
    if (keys.length !== 1) {
        return `condition atom must have exactly one key, found: ${keys.map((k) => tok(k)).join(", ")}`;
    }
    const key = keys[0];
    if (key === "postureBelow") {
        const n = atom["postureBelow"];
        if (typeof n !== "number" || !Number.isInteger(n)) {
            return "postureBelow must be an integer (posture is integer-only, ADR-007)";
        }
        if (n < 0 || n > 100)
            return "postureBelow must be within 0–100";
        return undefined;
    }
    if (key === "attestationAtMost") {
        const t = atom["attestationAtMost"];
        return typeof t === "string" && ATTESTATION_TIERS.includes(t)
            ? undefined
            : `attestationAtMost "${typeof t === "string" ? tok(t) : String(t)}" is not a known attestation tier`;
    }
    if (key === "driftOutstanding") {
        return atom["driftOutstanding"] === true
            ? undefined
            : "driftOutstanding must be the literal true";
    }
    return `unknown condition atom "${tok(key)}"`;
}
const ALLOW_FIELDS = new Set(["effect", "name", "rationale", "principal", "action", "resource"]);
const NARROWING_FIELDS = new Set([
    "effect",
    "name",
    "rationale",
    "principal",
    "action",
    "resource",
    "condition",
]);
const NARROWING_EFFECTS = new Set(["deny", "require-approval", "observe"]);
/** Locator for a rule in reason strings: its name if valid, else its index. */
function ruleLocator(rule, index) {
    const name = rule["name"];
    return typeof name === "string" && name.length > 0 ? `rule "${tok(name)}"` : `rule #${index}`;
}
/**
 * Validate a single rule, appending every reason found to `out`. Strict: any
 * unknown field for the variant is a rejection (fail-closed on authored input).
 */
function validateRule(value, index, out) {
    if (!isPlainObject(value)) {
        out.push(`rule #${index} must be an object`);
        return;
    }
    const loc = ruleLocator(value, index);
    const effect = value["effect"];
    if (typeof effect !== "string") {
        out.push(`${loc}: effect must be a string`);
        return;
    }
    // Explainability fields required on every variant (Principle 5).
    if (typeof value["name"] !== "string" || value["name"].length === 0) {
        out.push(`${loc}: name is required (non-empty, unique)`);
    }
    if (typeof value["rationale"] !== "string" || value["rationale"].length === 0) {
        out.push(`${loc}: rationale is required (the human "why")`);
    }
    const isAllow = effect === "allow";
    const isNarrowing = NARROWING_EFFECTS.has(effect);
    if (!isAllow && !isNarrowing) {
        out.push(`${loc}: unknown effect "${tok(effect)}"; expected allow | deny | require-approval | observe`);
        return;
    }
    // Strict unknown-field rejection, per variant.
    const allowed = isAllow ? ALLOW_FIELDS : NARROWING_FIELDS;
    for (const k of Object.keys(value)) {
        if (!allowed.has(k)) {
            out.push(isAllow && k === "condition"
                ? `${loc}: the allow variant has no condition field — conditioning a broadening effect is structurally forbidden (ADR-009 crux)`
                : `${loc}: unknown field "${tok(k)}" for effect "${tok(effect)}"`);
        }
    }
    const aErr = actionError(value["action"], /* allowBareWildcard */ isNarrowing);
    if (aErr)
        out.push(`${loc}: ${aErr}`);
    const rErr = resourceError(value["resource"]);
    if (rErr)
        out.push(`${loc}: ${rErr}`);
    if (isAllow) {
        // The crux, enforced on parsed input: the allow selector must be the
        // literal "*". Read into a token-free local so the shape check reads as
        // schema validation, not an identity-value branch (ADR-005 guard).
        const declared = value["principal"];
        if (declared !== "*") {
            out.push(`${loc}: the allow variant's principal must be the literal "*" — broadening on a specific or sub-verified principal is structurally forbidden (ADR-009 crux)`);
        }
        return;
    }
    // Narrowing variant.
    const pErr = principalError(value["principal"]);
    if (pErr)
        out.push(`${loc}: ${pErr}`);
    const condition = value["condition"];
    if (condition !== undefined) {
        if (!Array.isArray(condition)) {
            out.push(`${loc}: condition must be an array of atoms`);
        }
        else {
            for (const atom of condition) {
                const cErr = conditionAtomError(atom);
                if (cErr)
                    out.push(`${loc}: ${cErr}`);
            }
        }
    }
}
/**
 * Strict, deterministic validation of a parsed policy document. On ANY problem
 * this returns a WHOLE-SET refusal — no rule is returned, ever a partial apply
 * (ADR-009: a half-applied policy is undebuggable false assurance). Reasons are
 * collected top-down (deterministic given input order) and bounded.
 *
 * @param parsed the result of JSON.parse (the caller owns parsing).
 * @param source workspace-relative source path for the emitted finding(s).
 */
export function validatePolicy(parsed, source = POLICY_REL_PATH) {
    const reasons = [];
    const push = (r) => {
        if (reasons.length < MAX_POLICY_REASONS)
            reasons.push(tok(r));
    };
    if (!isPlainObject(parsed)) {
        push("policy document must be a JSON object");
        return refuse(reasons, source);
    }
    if (parsed["schemaVersion"] !== POLICY_SCHEMA_VERSION) {
        push(`unknown schemaVersion ${tok(String(parsed["schemaVersion"]))}; this runtime speaks schemaVersion ${POLICY_SCHEMA_VERSION}`);
    }
    if (typeof parsed["workspace"] !== "undefined" && typeof parsed["workspace"] !== "string") {
        push("workspace, when present, must be a string");
    }
    else if (typeof parsed["workspace"] === "string") {
        // Forward-note c (ADR-009): the workspace field is a basename-only
        // identifier (ADR-003/005), so it rejects the SAME absolute-path/authority
        // shapes as a resource pattern — a whole-set policy.invalid, closing the
        // one other free-text slot a leak could hide in.
        const wsShape = absPathOrAuthorityShape(parsed["workspace"]);
        if (wsShape !== undefined) {
            push(`workspace "${tok(parsed["workspace"])}" has an ${wsShape === "abs" ? "absolute-path (leading / or \\)" : wsShape === "drive" ? "Windows drive-absolute (X:)" : "URL-authority (scheme://host)"} shape; the workspace is a basename-only identifier`);
        }
    }
    for (const k of Object.keys(parsed)) {
        if (k !== "schemaVersion" &&
            k !== "workspace" &&
            k !== "rules" &&
            k !== "name" &&
            k !== "mode" &&
            k !== "defaultEffect") {
            push(`unknown top-level field "${tok(k)}"`);
        }
    }
    // ADR-021 operator fields — optional, strictly typed, fail-closed.
    if (typeof parsed["name"] !== "undefined" && typeof parsed["name"] !== "string") {
        push("name, when present, must be a string");
    }
    if (typeof parsed["mode"] !== "undefined" && parsed["mode"] !== "observe" && parsed["mode"] !== "enforce") {
        push(`mode, when present, must be observe or enforce (got "${tok(String(parsed["mode"]))}")`);
    }
    if (typeof parsed["defaultEffect"] !== "undefined") {
        const de = parsed["defaultEffect"];
        if (de === "allow") {
            push("defaultEffect may never be allow — a permissive default is fail-open by construction (ADR-021; the ADR-009 crux extended to the default)");
        }
        else if (de !== "observe" && de !== "require-approval" && de !== "deny") {
            push(`defaultEffect, when present, must be observe, require-approval, or deny (got "${tok(String(de))}")`);
        }
    }
    const rules = parsed["rules"];
    if (!Array.isArray(rules)) {
        push("rules must be an array");
        return refuse(reasons, source);
    }
    const names = new Set();
    for (let i = 0; i < rules.length && reasons.length < MAX_POLICY_REASONS; i++) {
        const tmp = [];
        validateRule(rules[i], i, tmp);
        for (const r of tmp)
            push(r);
        // Duplicate-name detection (ADR-009 explainability: names are unique).
        const rule = rules[i];
        if (isPlainObject(rule) && typeof rule["name"] === "string" && rule["name"].length > 0) {
            if (names.has(rule["name"])) {
                push(`duplicate rule name "${tok(rule["name"])}"; rule names must be unique`);
            }
            else {
                names.add(rule["name"]);
            }
        }
    }
    if (reasons.length > 0)
        return refuse(reasons, source);
    // Every check passed — the cast is sound (validation established the shape).
    return { ok: true, policy: parsed };
}
function refuse(reasons, source) {
    // The `??` default below is provably unreachable defensive code: every refuse()
    // call site provides a non-empty reasons list (validatePolicy's early-refuse paths
    // each push before refusing; its final refuse is guarded by reasons.length > 0;
    // loadPolicy passes a literal one-element array). Kept as a fail-safe for future
    // call sites; excluded from branch coverage for exactly that reason.
    /* v8 ignore next -- reason: unreachable defensive default, see comment above */
    const first = reasons[0] ?? "policy document is not conforming";
    const summary = reasons.length <= 1
        ? first
        : `${first} (policy set refused; ${reasons.length}${reasons.length >= MAX_POLICY_REASONS ? "+" : ""} issue(s))`;
    const finding = {
        kind: "policy.invalid",
        severity: "high",
        resource: "policy set",
        source,
        entityHash: null,
        explanation: tok(`policy refused: ${summary} — no rule from this file is evaluated (whole-set refusal)`),
    };
    return { ok: false, reasons, findings: [finding] };
}
// --------------------------------------------------------------- matchers
/**
 * Match a VALIDATED action matcher against a concrete action word — the MATCH
 * half of the same grammar `actionError` VALIDATES, factored here so every
 * consumer shares ONE semantics: S3.3's authorization-gap reader (is this
 * capability's action named by any rule?) and S3.2's future decision engine
 * must never disagree on what a matcher names. Mirrors the grammar exactly:
 * the bare `*` matches any action; a trailing `.*` matches its namespace
 * (`tool.*` → every `tool.` word); otherwise an exact vocabulary word.
 *
 * Precondition: `matcher` is a matcher the validator accepted. Called on other
 * strings it simply returns false for non-matches — it never widens.
 */
export function matchesAction(matcher, action) {
    if (matcher === "*")
        return true;
    if (matcher.endsWith(".*")) {
        const stem = matcher.slice(0, -2);
        return stem.length > 0 && action.startsWith(`${stem}.`);
    }
    return matcher === action;
}
/**
 * Match a VALIDATED resource matcher against a concrete emitted logical
 * identifier — the MATCH half of the grammar `resourceError` VALIDATES (exact
 * string, or a single trailing-`*` prefix; `*` alone matches all). MATCH-ONLY
 * and never dereferenced (ADR-009): the pattern is compared as a string
 * against finding-emitted identifiers, never opened or resolved as a path.
 * Shared by S3.3 and the S3.2 evaluator for the same reason as matchesAction.
 */
export function matchesResource(matcher, resource) {
    if (matcher.endsWith("*"))
        return resource.startsWith(matcher.slice(0, -1));
    return matcher === resource;
}
/**
 * Load `.deepsweep/policy.json` through the shared contained store (reused, not
 * forked): symlink / realpath-escape / non-regular-file all throw
 * `PolicyRefusalError` (CLI exit 3, ADR-008 reviewed-wiring). Absent → absent.
 * Present-but-unparseable or schema-nonconforming → a whole-set `invalid`
 * refusal carrying the `policy.invalid` finding. Present-and-valid → ok.
 */
export const POLICY_KEYS_FILE = "policy-keys.json";
export const POLICY_KEYS_REL_PATH = `${STORE_DIR}/${POLICY_KEYS_FILE}`;
export const POLICY_FLOOR_FILE = "policy-version.json";
function loadTrustConfig(workspaceRoot) {
    const text = readStoreText(workspaceRoot, POLICY_KEYS_FILE, policyRefuse);
    if (text === undefined)
        return undefined;
    try {
        const parsed = JSON.parse(text);
        if (typeof parsed !== "object" || parsed === null || parsed["schemaVersion"] !== 1)
            return "malformed";
        const rawKeys = parsed["keys"];
        if (!Array.isArray(rawKeys) || rawKeys.length === 0)
            return "malformed";
        const keys = [];
        for (const k of rawKeys) {
            const rec = k;
            if (typeof rec?.["keyId"] !== "string" || typeof rec?.["publicKey"] !== "string")
                return "malformed";
            keys.push({ keyId: rec["keyId"], publicKey: rec["publicKey"] });
        }
        const min = parsed["minBundleVersion"];
        const minBundleVersion = typeof min === "number" && Number.isInteger(min) && min >= 0 ? min : 0;
        return { keys, minBundleVersion };
    }
    catch {
        return "malformed";
    }
}
/** High-water mark of the last ACCEPTED bundleVersion (0 when absent/torn). */
function readAcceptedFloor(workspaceRoot) {
    const text = readStoreText(workspaceRoot, POLICY_FLOOR_FILE, policyRefuse);
    if (text === undefined)
        return 0;
    try {
        const parsed = JSON.parse(text);
        const v = parsed?.["acceptedBundleVersion"];
        return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : 0;
    }
    catch {
        return 0; // torn/tampered floor degrades to 0 — the CONFIG floor still holds
    }
}
/** Envelope shape probe — routing only; verification decides everything else. */
function looksSealed(parsed) {
    const r = parsed;
    return typeof r === "object" && r !== null && "bundle" in r && "signature" in r && "keyId" in r;
}
export function loadPolicy(workspaceRoot) {
    const text = readStoreText(workspaceRoot, POLICY_FILE, policyRefuse);
    if (text === undefined)
        return { status: "absent" };
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return {
            status: "invalid",
            refusal: refuse(["policy.json is not valid JSON"], POLICY_REL_PATH),
        };
    }
    // ADR-016 — sealed-bundle path. A pinned trust config makes signing
    // MANDATORY (fail-closed): unsigned-where-pinned is a downgrade refusal;
    // any verification failure is a whole-set refusal; only a VERIFIED bundle
    // proceeds to schema validation, and the accepted floor advances only
    // after the entire chain succeeds.
    const trust = loadTrustConfig(workspaceRoot);
    if (trust === "malformed") {
        return {
            status: "invalid",
            refusal: refuse([`${POLICY_KEYS_REL_PATH} is malformed — signing is unverifiable, refusing the whole set (never fail open)`], POLICY_REL_PATH),
        };
    }
    if (looksSealed(parsed)) {
        if (trust === undefined) {
            return {
                status: "invalid",
                refusal: refuse([`policy.json is a sealed bundle but no ${POLICY_KEYS_REL_PATH} pins any verification key`], POLICY_REL_PATH),
            };
        }
        const floor = Math.max(trust.minBundleVersion, readAcceptedFloor(workspaceRoot));
        const verdict = verifyBundle(parsed, trust.keys, floor);
        if (!verdict.ok) {
            return {
                status: "invalid",
                refusal: refuse([`sealed bundle refused (${verdict.reason}): ${verdict.detail}`], POLICY_REL_PATH),
            };
        }
        const result = validatePolicy(verdict.bundle.policy, POLICY_REL_PATH);
        if (!result.ok)
            return { status: "invalid", refusal: result };
        writeStoreAtomic(workspaceRoot, POLICY_FLOOR_FILE, `${JSON.stringify({ schemaVersion: 1, acceptedBundleVersion: verdict.bundle.bundleVersion }, null, 2)}\n`, policyRefuse);
        return { status: "ok", policy: result.policy };
    }
    if (trust !== undefined) {
        return {
            status: "invalid",
            refusal: refuse([`policy.json is UNSIGNED but ${POLICY_KEYS_REL_PATH} pins signing keys — downgrade refused (never fail open)`], POLICY_REL_PATH),
        };
    }
    const result = validatePolicy(parsed, POLICY_REL_PATH);
    if (!result.ok)
        return { status: "invalid", refusal: result };
    return { status: "ok", policy: result.policy };
}
const DEFAULT_EFFECT_RANK = {
    observe: 0,
    "require-approval": 1,
    deny: 2,
};
/**
 * Three-layer operator policy (ADR-021): org bundle (signed, ADR-016) >
 * workspace `.deepsweep/policy.json` > user `<userRoot>/.deepsweep/policy.json`,
 * merged DENY-WINS so lower layers can only tighten:
 *  - rules concatenate under "layer:name" qualification and the ADR-009
 *    most-restrictive-wins evaluation does the rest — a user rule can never
 *    outrank a workspace/org narrowing;
 *  - USER-layer `allow` rules are a layer refusal (the user layer may only
 *    narrow — an allow there would broaden the merged default);
 *  - merged defaultEffect is the MOST RESTRICTIVE across layers;
 *  - a SEALED user policy is a layer refusal (bundles are org-distribution
 *    artifacts).
 * With today's single-file topology, `.deepsweep/policy.json` serves as the
 * org layer when sealed+pinned and as the workspace layer when plain; the
 * merge machinery is N-layer so a separate org-bundle file (cloud sync) is
 * an additive follow-up, not a redesign.
 * `userConfigRoot` is injection-only (ADR-014/ADR-005: the engine cannot
 * locate the user profile).
 */
export function loadLayeredPolicy(workspaceRoot, opts = {}) {
    const refusals = [];
    const layersLoaded = [];
    const merged = [];
    let mode;
    let defaultEffect = "observe";
    /**
     * TEAM-ADR-028 — the self-protection rule sits ABOVE this merge. A layer
     * that explicitly names `.deepsweep/` in an `allow` rule is trying to grant
     * an agent write access to the evidence that makes it accountable, and that
     * is REFUSED as a whole layer (ADR-021 layer-refusal semantics: zero rules
     * contributed, surfaced loudly) rather than silently dropped — an operator
     * who wrote it must find out that it did not take effect. Enforcement does
     * not depend on this check: `guardFsMutation` denies the mutation anyway.
     * This exists so the misconfiguration is visible, not so the protection is.
     */
    const absorb = (layer, set, source) => {
        const attempts = selfProtectionOverrideAttempts(set.rules);
        if (attempts.length > 0) {
            refusals.push({ layer, source, reasons: [selfProtectionRefusalReason(attempts)] });
            return false;
        }
        layersLoaded.push(layer);
        for (const rule of set.rules) {
            merged.push({ ...rule, name: `${layer}:${rule.name}` });
        }
        if (mode === undefined && layer !== "user" && set.mode !== undefined)
            mode = set.mode;
        const de = set.defaultEffect ?? "observe";
        if (DEFAULT_EFFECT_RANK[de] > DEFAULT_EFFECT_RANK[defaultEffect])
            defaultEffect = de;
        return true;
    };
    // Org/workspace slot: the existing loader (sealed bundle => org layer;
    // plain => workspace layer; its refusal semantics are ADR-016/ADR-009).
    const primary = loadPolicy(workspaceRoot);
    if (primary.status === "invalid") {
        refusals.push({ layer: "workspace", source: POLICY_REL_PATH, reasons: primary.refusal.reasons });
    }
    else if (primary.status === "ok") {
        const sealed = loadTrustConfig(workspaceRoot) !== undefined;
        absorb(sealed ? "org" : "workspace", primary.policy, POLICY_REL_PATH);
    }
    // User layer: plain policy only, narrowing only.
    if (opts.userConfigRoot !== undefined) {
        const userSource = "~/.deepsweep/policy.json";
        const text = safeReadUser(opts.userConfigRoot, `.deepsweep/${POLICY_FILE}`);
        if (text !== undefined) {
            let parsed;
            try {
                parsed = JSON.parse(text);
            }
            catch {
                parsed = undefined;
            }
            if (parsed === undefined) {
                refusals.push({ layer: "user", source: userSource, reasons: ["user policy is not valid JSON"] });
            }
            else if (typeof parsed === "object" && parsed !== null && "signature" in parsed) {
                refusals.push({
                    layer: "user",
                    source: userSource,
                    reasons: ["sealed bundles are org-distribution artifacts — the user layer must be a plain policy"],
                });
            }
            else {
                const result = validatePolicy(parsed, userSource);
                if (!result.ok) {
                    refusals.push({ layer: "user", source: userSource, reasons: result.reasons });
                }
                else if (result.policy.rules.some((r) => r.effect === "allow")) {
                    refusals.push({
                        layer: "user",
                        source: userSource,
                        reasons: [
                            "the user layer may only narrow (deny / require-approval / observe) — an allow rule here would loosen the merged policy (ADR-021)",
                        ],
                    });
                }
                else {
                    absorb("user", result.policy, userSource);
                }
            }
        }
    }
    // Fail-closed mode (ADR-021): a refused org/workspace layer must not
    // silently un-enforce a policy that may have declared enforce — the safe
    // default posture ACTS (require-approval via ADR-010), so mode is forced
    // to enforce whenever the primary layer refused.
    const primaryRefused = refusals.some((r) => r.layer !== "user");
    return {
        policy: { schemaVersion: POLICY_SCHEMA_VERSION, defaultEffect, rules: merged },
        mode: primaryRefused ? "enforce" : (mode ?? "observe"),
        refusals,
        layersLoaded,
    };
}
