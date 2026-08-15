import { type EnforcementEffect, type ExplainedEnforcement, type PolicyLoadStatus } from "./enforce.js";
import type { PolicyOutcome } from "./evaluate.js";
/** The protected directory name. Identical to the store dir by construction. */
export declare const PROTECTED_DIR = ".deepsweep";
/** The immutable id of the rule. Cited in every refusal (explainability). */
export declare const SELF_PROTECTION_POLICY_ID = "self-protection.deepsweep-store";
/**
 * Every enforcement chokepoint that must consult this rule. The list is a
 * CONTRACT: a registry test crosses it with every evasion class, so adding a
 * chokepoint without wiring it fails the build.
 */
export declare const CHOKEPOINTS: readonly ["firewall", "mcp", "hooks"];
export type Chokepoint = (typeof CHOKEPOINTS)[number];
/** Mutating operations. Reads are NOT denied — the store is metadata-only and
 * readable by design; it is WRITE integrity the ledger depends on. */
export declare const MUTATIONS: readonly ["write", "create", "delete", "rename", "truncate", "chmod"];
export type MutationOperation = (typeof MUTATIONS)[number];
export type EvasionClass = "direct" | "rename-source" | "rename-target" | "symlink" | "hardlink" | "toctou-race" | "unknown-shape";
/** The scope of the store that matched. */
export type ProtectedScope = "workspace-store" | "user-store" | "unrooted-store";
/**
 * One attempted filesystem mutation, as a chokepoint observes it.
 *
 * `attribution` is the chokepoint's judgement of WHO acted. Only the exact
 * literal `"human"` is treated as a human operator; every other value —
 * including a forged one — is treated as agent-attributed, because unknown
 * input is never a permission (invariant 2).
 */
export interface FsMutationAttempt {
    readonly attribution: "agent" | "human";
    /** Claimed agent id (ADR-005 derived hex) or null when unattributed. */
    readonly principal: string | null;
    readonly operation: MutationOperation;
    /** The path as requested. May be relative to the workspace root. */
    readonly path: string;
    /** Destination for a rename. */
    readonly renameTo?: string;
}
/** Roots the rule is evaluated against. `userConfigRoot` is injection-only
 * (ADR-014/ADR-005: the engine never locates the user profile itself). */
export interface SelfProtectionContext {
    readonly workspaceRoot: string;
    readonly userConfigRoot?: string;
    readonly fs?: SelfProtectionFs;
}
/** One probe of a path's on-disk reality. */
export interface PathProbe {
    /** Fully symlink-resolved path, or undefined when it cannot be resolved. */
    readonly realPath: string | undefined;
    /** `${dev}:${ino}` — the only signal that reveals a hard link. */
    readonly identity: string | undefined;
    /**
     * Hard-link count (`st_nlink`). A file with exactly one link CANNOT be a
     * hard link to anything, so this lets the guard skip enumerating the store's
     * inodes on the overwhelmingly common path (an ordinary source write) — the
     * difference between an O(store) directory walk per agent action and none.
     * Undefined (an unknown seam) is treated as "possibly linked": fail closed.
     */
    readonly linkCount?: number | undefined;
}
/** The filesystem seam. Injected so every evasion class is testable and so
 * the rule itself stays a pure function of what the seam reports. */
export interface SelfProtectionFs {
    probe(path: string): PathProbe;
    /** Filesystem identities of every regular file currently under `roots`. */
    storeIdentities(roots: readonly string[]): ReadonlySet<string>;
}
/** The explained verdict: who / what / why / policy / outcome (Principle 5). */
export interface SelfProtectionDecision {
    readonly protected: boolean;
    /** WHO — the attributed principal, or an explicit stand-in. */
    readonly who: string;
    /** WHAT — operation plus the store-relative path that matched. */
    readonly what: string;
    /** WHY — the human sentence carried into audit and approval surfaces. */
    readonly why: string;
    /** POLICY — the citation. Always the self-protection rule when protected. */
    readonly policy: string;
    /** OUTCOME — `deny` when protected; `not-applicable` otherwise. */
    readonly outcome: "deny" | "not-applicable";
    readonly evasion: EvasionClass | null;
    readonly scope: ProtectedScope | null;
    readonly chokepoint: Chokepoint | null;
}
/**
 * Lexical classification: does this absolute path sit AT or UNDER a
 * `.deepsweep` directory?
 *
 * DELIBERATELY OVER-INCLUSIVE (deny-wins): any `.deepsweep` segment matches,
 * even outside the injected roots. That is what lets the rule cover
 * `~/.deepsweep/**` on a host that never injected `userConfigRoot` — the
 * engine cannot locate the user profile (ADR-014), but it can recognize the
 * directory name. Denying a mutation to an unrelated third-party
 * `.deepsweep/` directory is an acceptable false positive; missing the user
 * store is not.
 */
export declare function classifyPath(absolutePath: string, ctx: {
    workspaceRoot: string;
    userConfigRoot?: string;
}): {
    readonly protected: boolean;
    readonly scope: ProtectedScope | null;
    readonly matched: string | null;
};
/** The production seam over node:fs. */
export declare function nodeSelfProtectionFs(): SelfProtectionFs;
/**
 * THE RULE. Returns an explained decision for one attempted mutation.
 *
 * Ladder (deny-wins, first match wins, safest first):
 *  0. malformed attempt        -> deny (unknown-shape)
 *  1. lexical, requested path  -> deny (direct | rename-source | rename-target)
 *  2. double probe disagrees   -> deny (toctou-race)
 *  3. lexical, resolved path   -> deny (symlink)
 *  4. identity under a store   -> deny (hardlink)
 *  5. otherwise                -> not protected
 *
 * A `human`-attributed attempt short-circuits to not-protected: an operator
 * editing their own policy is the supported workflow. Any OTHER attribution
 * value — including a forged one — is treated as an agent.
 */
export declare function guardFsMutation(attempt: FsMutationAttempt, ctx: SelfProtectionContext, chokepoint?: Chokepoint | null): SelfProtectionDecision;
/**
 * The chokepoint entrypoint. EVERY acting surface (firewall, MCP, hooks)
 * calls this and nothing else: it evaluates the self-protection rule and then
 * routes through the ADR-010 ladder in enforce.ts, so no chokepoint can be
 * wired to a raw policy outcome (the ADR-010 enforcement invariant).
 */
export declare function guardAtChokepoint(chokepoint: Chokepoint, attempt: FsMutationAttempt, ctx: SelfProtectionContext, policy: {
    readonly outcome: PolicyOutcome;
    readonly status: PolicyLoadStatus;
}): ExplainedEnforcement & {
    readonly selfProtection: SelfProtectionDecision;
    readonly chokepoint: Chokepoint;
};
/** Convenience for callers that only need the effect. */
export declare function chokepointEffect(chokepoint: Chokepoint, attempt: FsMutationAttempt, ctx: SelfProtectionContext, policy: {
    readonly outcome: PolicyOutcome;
    readonly status: PolicyLoadStatus;
}): EnforcementEffect;
/** The minimal rule shape this check needs (no policy.ts import — policy.ts
 * imports THIS module, and a cycle would be a load-order hazard). */
export interface RuleLike {
    readonly effect: string;
    readonly name: string;
    readonly resource: string;
}
/**
 * Names of rules in a layer that attempt to broaden access to the store.
 *
 * SCOPE, stated precisely so the guarantee is not oversold: an `allow` rule
 * whose resource matcher NAMES the store (contains a `.deepsweep` token) is
 * an explicit override attempt, and its whole layer is refused. A broad
 * wildcard (`resource: "*"`) is NOT refused here — it is simply out-ranked,
 * because `guardFsMutation` runs above the policy merge and never consults
 * the outcome for a protected path. Refusing every wildcard would break every
 * legitimate broad policy for no added protection.
 */
export declare function selfProtectionOverrideAttempts(rules: readonly RuleLike[]): string[];
/** The layer-refusal reason text (ADR-021 refusal machinery). */
export declare function selfProtectionRefusalReason(ruleNames: readonly string[]): string;
