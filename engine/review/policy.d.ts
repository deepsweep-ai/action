/**
 * S3.1 — Policy schema + strict validator (ADR-009, the BINDING contract).
 *
 * The Authorization stage's typed, versioned Principal / Action / Resource /
 * Condition policy — "least agency" as reviewable code. This module is SCHEMA
 * + VALIDATOR + contained loader ONLY: no enforcement, no decision engine, no
 * evaluation of rules against actions (S3.2/S3.3/E4). It parses authored
 * policy, proves it conforms to the schema, and refuses the whole set — loudly,
 * atomically — when it does not.
 *
 * The crux (ADR-009 "Structural narrow-not-broaden"): the rule schema is a
 * DISCRIMINATED UNION on `effect`, and the broadening `allow` variant has a
 * deliberately smaller grammar — `principal` is the LITERAL "*" only (its type
 * admits no other value) and the variant has NO `condition` field at all.
 * Broadening on a sub-verified principal or on posture is therefore
 * STRUCTURALLY inexpressible: `{"effect":"allow","principal":{"agentId":…}}`
 * fails the variant's principal type, and `{"effect":"allow","condition":[…]}`
 * fails as an unknown field on that variant. There is no checker rule to forget
 * and no lint to suppress — such a document does not parse as policy. This is a
 * PERMANENT invariant of schemaVersion 1 and every additive successor (ADR-009
 * crux-permanence): no additive field may EVER add a condition to `allow` or
 * admit a sub-`verified-signed` principal to it; only an attestation floor whose
 * type admits ONLY `verified-signed`-or-stronger may ever be added, and only by
 * ADR.
 *
 * Versioning + the deliberate strict-reject inversion: `schemaVersion 1` under
 * the ADR-003 additive-evolution rule governs what future runtimes may ADD
 * (new effects, atoms, selectors, optional fields — additive). But validation
 * INVERTS ADR-003's tolerate-unknown rule: ADR-003 tolerance exists for EMITTED
 * output consumed by others, where a tolerated typo is harmless; policy is
 * AUTHORED SECURITY INPUT, where a tolerated typo ("efect":"deny") is a
 * silently vanished protection (fail-open). So validation is STRICT: unknown
 * fields / effects / atoms / actions, out-of-variant fields, duplicate names,
 * non-integer posture thresholds — all reject, as WHOLE-SET refusal (a
 * high-severity `policy.invalid` finding; NO rule from the file is evaluated —
 * never partial application). A mixed-version team using a newer runtime's
 * additive field is refused loudly by an older runtime — fail-suspicious and
 * actionable, never half-applied.
 *
 * Containment + exit codes: policy lives in `.deepsweep/policy.json` and
 * inherits every `store.ts` containment invariant verbatim (reused, not forked).
 * A containment violation throws `PolicyRefusalError`, wired into the CLI's
 * exit-3 catch (ADR-008 reviewed-wiring). `policy.invalid` itself maps to NO
 * exit code in v1 (ADR-009 N2): all policy output is advisory pre-E4, so a run
 * whose only finding is `policy.invalid` still exits 0 absent other triggers.
 *
 * Zero runtime dependencies. Reuses the ONE canonicalizer (canonical.ts) for
 * byte-identical serialization and the ONE sanitizer choke point (sanitize.ts)
 * for every rendered token.
 */
import type { CapabilityKind } from "./types.js";
import type { AgentType } from "./identity.js";
import type { DriftFinding } from "./diff.js";
export declare const POLICY_SCHEMA_VERSION: 1;
/** The single policy document (ADR-009 storage section). */
export declare const POLICY_FILE = "policy.json";
export declare const POLICY_REL_PATH = ".deepsweep/policy.json";
/**
 * The closed, ADDITIVE action vocabulary (ADR-009 "Action vocabulary"),
 * aligned to the ADR-005 AuditEvent forward map so a policy action and an
 * audit action are the same word. New capabilities add vocabulary additively;
 * existing words are never renamed or re-meaning'd without a version bump.
 */
export type PolicyAction = "environment.change" | "tool.invoke" | "shell.execute" | "repository.write" | "secrets.access" | "container.mount" | "network.expose" | "approval.auto";
export declare const ACTION_VOCABULARY: readonly PolicyAction[];
/**
 * The 1:1 CapabilityKind → action mapping table AS CODE (ADR-009): a detected
 * capability and the policy action that governs it are the same word. Total
 * over CapabilityKind (guarded by a unit test); actions may be shared by
 * several kinds (many kinds, one governing verb). `approval.auto` is the
 * S1.x autoApproval capability rendered policy-referenceable so it can be
 * DENIED.
 */
export declare const CAPABILITY_ACTION: Record<CapabilityKind, PolicyAction>;
/**
 * Agent types keyable by the `{agentType}` selector (ADR-005 derivation
 * inputs). Kept in lockstep with `AgentType` via `satisfies`; a unit test
 * guards totality so a new agent type cannot silently become unkeyable.
 */
export declare const AGENT_TYPES: readonly ["cursor", "claude-code", "copilot", "windsurf", "devcontainer"];
/** Attestation tiers a `attestationAtMost` atom may name (ADR-005 tiers). */
export type ConditionAttestationTier = "claimed" | "session-observed";
/**
 * Principal selectors for the NARROWING variants only. `"*"` matches any
 * principal including `null` (unattributed findings); `{agentId}` the exact
 * fresh-derived ID; `{agentType}` by derivation input (S3.4 pack portability).
 * NO owner selector exists in the grammar (ADR-005 F1 — structurally absent,
 * not filtered).
 */
export type PrincipalSelector = "*" | {
    readonly agentId: string;
} | {
    readonly agentType: AgentType;
};
/**
 * The closed, additive condition-atom union — ANDed, and by construction only
 * ever present on narrowing variants (the `allow` variant has no condition
 * field, so "posture may never broaden at any tier" needs no validator rule —
 * the grammar already says it).
 */
export type ConditionAtom = {
    readonly postureBelow: number;
} | {
    readonly attestationAtMost: ConditionAttestationTier;
} | {
    readonly driftOutstanding: true;
};
/**
 * Action matchers. Both variants admit an exact vocabulary word or a trailing
 * `.*` prefix segment (`tool.*`). Only the narrowing variants additionally
 * admit the bare `*` wildcard — the `allow` variant's matcher does NOT, so
 * "allow everything" is structurally unwritable (ADR-009). The template
 * `${string}.*` excludes the bare `"*"` at the TYPE level (a one-char `"*"`
 * cannot end in `.*`), so `allow` + bare-`*` action is a type error, not only
 * a validation rejection.
 */
export type ActionWildcard = `${string}.*`;
export type AllowActionMatcher = PolicyAction | ActionWildcard;
export type NarrowingActionMatcher = PolicyAction | ActionWildcard | "*";
/** Explainability fields required on EVERY rule (ADR-009, Principle 5). */
interface RuleExplainability {
    /** Unique within the policy set — cited by a PolicyDecision's policyRef. */
    readonly name: string;
    /** The human "why" this rule exists. */
    readonly rationale: string;
}
/**
 * The BROADENING variant (ADR-009 crux). `principal` is the literal `"*"` and
 * there is NO `condition` field — scope is expressed solely through `action`
 * and `resource`. An allow states "this action on this resource is within this
 * workspace's least-agency envelope," for everyone, unconditionally.
 */
export interface AllowRule extends RuleExplainability {
    readonly effect: "allow";
    readonly principal: "*";
    readonly action: AllowActionMatcher;
    readonly resource: string;
}
export type NarrowingEffect = "deny" | "require-approval" | "observe";
/**
 * The NARROWING variants — safe to key on ANY principal selector and ANY
 * condition atom because they grant nothing (they restrict or scrutinize).
 */
export interface NarrowingRule extends RuleExplainability {
    readonly effect: NarrowingEffect;
    readonly principal: PrincipalSelector;
    readonly action: NarrowingActionMatcher;
    readonly resource: string;
    readonly condition?: readonly ConditionAtom[];
}
export type PolicyRule = AllowRule | NarrowingRule;
/** Operator surface (ADR-021): rollout mode. `observe` computes + ledgers
 * decisions without acting; `enforce` lets acting surfaces act. */
export type PolicyMode = "observe" | "enforce";
/** Unmatched-action outcome (ADR-021). NEVER "allow" — a permissive default
 * is fail-open by construction and rejected at validation (the ADR-009 crux
 * extended to the default). */
export type PolicyDefaultEffect = "observe" | "require-approval" | "deny";
export interface PolicySet {
    readonly schemaVersion: typeof POLICY_SCHEMA_VERSION;
    /** Workspace basename, optional (committed policy is portable — not pinned). */
    readonly workspace?: string;
    /** Operator-facing policy name, optional (ADR-021). */
    readonly name?: string;
    /** Rollout mode, default "observe" (ADR-021 Detect-mode rollout). */
    readonly mode?: PolicyMode;
    /** Unmatched-action outcome, default "observe" (ADR-021). */
    readonly defaultEffect?: PolicyDefaultEffect;
    readonly rules: readonly PolicyRule[];
}
/**
 * Byte-identical canonical serialization via the ONE canonicalizer (ADR-003,
 * reused not forked): sorted keys, minimal escaping, string values
 * byte-preserved. Two policies differing in any code point serialize (and
 * hash) differently.
 */
export declare function canonicalPolicy(policy: PolicySet): string;
/**
 * SHA-256 of a single rule's canonicalized content — the version-pinning half
 * of a future PolicyDecision's `policyRef` (ADR-009 explainability). Defined
 * here so S3.2 fills it rather than inventing it.
 */
export declare function policyRuleHash(rule: PolicyRule): string;
/** Raised when containment invariants forbid touching the policy store. */
export declare class PolicyRefusalError extends Error {
    constructor(reason: string);
}
export interface PolicyValidationOk {
    readonly ok: true;
    readonly policy: PolicySet;
}
export interface PolicyValidationRefused {
    readonly ok: false;
    /** Deterministic, bounded, sanitized rejection reasons (whole-set refusal). */
    readonly reasons: readonly string[];
    /** The high-severity `policy.invalid` finding(s) — never a partial apply. */
    readonly findings: readonly DriftFinding[];
}
export type PolicyValidation = PolicyValidationOk | PolicyValidationRefused;
/** Bounds attacker fan-out from a maliciously huge broken policy file. */
export declare const MAX_POLICY_REASONS = 20;
/**
 * Strict, deterministic validation of a parsed policy document. On ANY problem
 * this returns a WHOLE-SET refusal — no rule is returned, ever a partial apply
 * (ADR-009: a half-applied policy is undebuggable false assurance). Reasons are
 * collected top-down (deterministic given input order) and bounded.
 *
 * @param parsed the result of JSON.parse (the caller owns parsing).
 * @param source workspace-relative source path for the emitted finding(s).
 */
export declare function validatePolicy(parsed: unknown, source?: string): PolicyValidation;
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
export declare function matchesAction(matcher: string, action: PolicyAction): boolean;
/**
 * Match a VALIDATED resource matcher against a concrete emitted logical
 * identifier — the MATCH half of the grammar `resourceError` VALIDATES (exact
 * string, or a single trailing-`*` prefix; `*` alone matches all). MATCH-ONLY
 * and never dereferenced (ADR-009): the pattern is compared as a string
 * against finding-emitted identifiers, never opened or resolved as a path.
 * Shared by S3.3 and the S3.2 evaluator for the same reason as matchesAction.
 */
export declare function matchesResource(matcher: string, resource: string): boolean;
export type PolicyLoad = {
    status: "absent";
} | {
    status: "invalid";
    refusal: PolicyValidationRefused;
} | {
    status: "ok";
    policy: PolicySet;
};
/**
 * Load `.deepsweep/policy.json` through the shared contained store (reused, not
 * forked): symlink / realpath-escape / non-regular-file all throw
 * `PolicyRefusalError` (CLI exit 3, ADR-008 reviewed-wiring). Absent → absent.
 * Present-but-unparseable or schema-nonconforming → a whole-set `invalid`
 * refusal carrying the `policy.invalid` finding. Present-and-valid → ok.
 */
export declare const POLICY_KEYS_FILE = "policy-keys.json";
export declare const POLICY_KEYS_REL_PATH = ".deepsweep/policy-keys.json";
export declare const POLICY_FLOOR_FILE = "policy-version.json";
export declare function loadPolicy(workspaceRoot: string): PolicyLoad;
export type PolicyLayer = "org" | "workspace" | "user";
export interface LayerRefusal {
    readonly layer: PolicyLayer;
    readonly source: string;
    readonly reasons: readonly string[];
}
export interface LayeredPolicyLoad {
    /** Merged deny-wins policy; rule names are qualified "layer:name". */
    readonly policy: PolicySet;
    /** Operational mode — decided by the highest-priority declaring layer
     * (org > workspace); the user layer can never switch mode. */
    readonly mode: PolicyMode;
    /** Per-layer refusals: a refused layer contributes ZERO rules and is
     * surfaced loudly; other layers still load (fail-closed per layer). */
    readonly refusals: readonly LayerRefusal[];
    readonly layersLoaded: readonly PolicyLayer[];
}
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
export declare function loadLayeredPolicy(workspaceRoot: string, opts?: {
    userConfigRoot?: string;
}): LayeredPolicyLoad;
export {};
