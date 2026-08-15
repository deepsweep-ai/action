/**
 * P29 / TEAM-ADR-028 — LEDGER SELF-PROTECTION.
 *
 * A hard-coded, NON-OVERRIDABLE deny for agent-attributed mutations that
 * touch the DeepSweep store (`.deepsweep/**` in a workspace, and
 * `~/.deepsweep/**` in the user profile). This is the one rule in the system
 * that no policy may loosen.
 *
 * WHY IT SITS ABOVE THE POLICY MERGE
 * ----------------------------------
 * ADR-021 merges org > workspace > user policy deny-wins, and ADR-010 maps
 * the merged outcome to an acted-on effect. Both are *policy*: an operator
 * writes them, and an agent that can write policy can therefore write its own
 * permission. Everything the ledger is for — attribution, evidence, replay —
 * dies the moment an agent can edit the ledger, so the guard for it cannot be
 * expressed as a policy rule. It is evaluated BEFORE any policy outcome is
 * consulted (`guardFsMutation` -> `explainEnforcementAboveLayeredPolicy`), so
 * neither an org bundle, a workspace policy, a user policy, nor a
 * `defaultEffect` can reach it. A policy layer that explicitly names the store
 * in an `allow` rule is REFUSED as a layer (ADR-021 layer-refusal machinery),
 * not honored and not silently dropped.
 *
 * WHAT IT IS NOT
 * --------------
 * This is PREVENTION at DeepSweep's own chokepoints. It is not, and cannot
 * be, a claim that the file is unwritable: an agent that runs as the same OS
 * user and shells out around DeepSweep bypasses every chokepoint here. That
 * residual is why the ledger is ALSO hash-chained (ADR-018), Merkle-committed
 * (TEAM-ADR-025), per-entry signed (ledger-sign.ts) and escrow-anchored
 * (ADR-DS-006), and why the honest guarantee is
 * "tamper-evident, self-protecting, escrow-anchored" — never "proof" of
 * anything. See docs/security.md.
 *
 * EVASION COVERAGE (each class has an adversarial test):
 *  - direct            — the requested path is inside a store
 *  - rename-source     — renaming a store file out of the store
 *  - rename-target     — renaming any file INTO the store
 *  - symlink           — the path (or an ancestor) resolves into a store
 *  - hardlink          — the path shares a filesystem identity (dev:ino) with
 *                        a file currently under a store; no readlink exists
 *                        for a hard link, so identity is the only signal
 *  - toctou-race       — the resolution changed between two probes; a race we
 *                        can observe is itself evidence, and lands in deny
 *  - unknown-shape     — a forged/any-cast attempt object
 *
 * Deterministic and pure apart from the injected `SelfProtectionFs` seam
 * (nowIso is not needed: the verdict is time-independent).
 */
import { lstatSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { STORE_DIR } from "./store.js";
import { explainEnforcementAboveLayeredPolicy, } from "./enforce.js";
/** The protected directory name. Identical to the store dir by construction. */
export const PROTECTED_DIR = STORE_DIR;
/** The immutable id of the rule. Cited in every refusal (explainability). */
export const SELF_PROTECTION_POLICY_ID = "self-protection.deepsweep-store";
/**
 * Every enforcement chokepoint that must consult this rule. The list is a
 * CONTRACT: a registry test crosses it with every evasion class, so adding a
 * chokepoint without wiring it fails the build.
 */
export const CHOKEPOINTS = ["firewall", "mcp", "hooks"];
/** Mutating operations. Reads are NOT denied — the store is metadata-only and
 * readable by design; it is WRITE integrity the ledger depends on. */
export const MUTATIONS = ["write", "create", "delete", "rename", "truncate", "chmod"];
// ------------------------------------------------------------ path handling
/** Split a path into segments, tolerant of both separators (win32 field). */
function segmentsOf(p) {
    return p.split(/[\\/]+/u).filter((s) => s !== "");
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
export function classifyPath(absolutePath, ctx) {
    const segments = segmentsOf(absolutePath);
    const at = segments.indexOf(PROTECTED_DIR);
    if (at === -1)
        return { protected: false, scope: null, matched: null };
    const matched = segments.slice(at).join("/");
    const under = (root) => {
        const r = resolve(root);
        return absolutePath === r || absolutePath.startsWith(r + sep) || absolutePath.startsWith(`${r}/`);
    };
    if (under(ctx.workspaceRoot))
        return { protected: true, scope: "workspace-store", matched };
    if (ctx.userConfigRoot !== undefined && under(ctx.userConfigRoot)) {
        return { protected: true, scope: "user-store", matched };
    }
    return { protected: true, scope: "unrooted-store", matched };
}
/** Resolve a requested path against the workspace root. */
function absolutize(path, workspaceRoot) {
    return isAbsolute(path) ? resolve(path) : resolve(workspaceRoot, path);
}
// ------------------------------------------------------------- the fs seam
function probeWithNodeFs(path) {
    let realPath;
    try {
        realPath = realpathSync(path);
    }
    catch {
        realPath = undefined;
    }
    try {
        const st = lstatSync(path);
        return { realPath, identity: `${st.dev}:${st.ino}`, linkCount: st.nlink };
    }
    catch {
        return { realPath, identity: undefined, linkCount: undefined };
    }
}
function collectIdentities(dir, into) {
    let names;
    try {
        names = readdirSync(dir);
    }
    catch {
        return;
    }
    for (const name of names.sort()) {
        const child = `${dir}${sep}${name}`;
        let st;
        try {
            st = statSync(child);
        }
        catch {
            continue;
        }
        if (st.isDirectory()) {
            collectIdentities(child, into);
        }
        else {
            into.add(`${st.dev}:${st.ino}`);
        }
    }
}
/** The production seam over node:fs. */
export function nodeSelfProtectionFs() {
    return {
        probe: probeWithNodeFs,
        storeIdentities(roots) {
            const out = new Set();
            for (const root of roots)
                collectIdentities(root, out);
            return out;
        },
    };
}
// ------------------------------------------------------------------- guard
function decisionFor(attempt, evasion, scope, matched, chokepoint) {
    const who = attempt.principal ?? "(unattributed agent)";
    const what = `${attempt.operation} ${matched ?? PROTECTED_DIR}`;
    return {
        protected: true,
        who,
        what,
        why: `${who} attempted to ${attempt.operation} the DeepSweep store (${matched ?? PROTECTED_DIR}) via ${evasion}. ` +
            "The store holds the audit ledger, its signatures and its anchors — the evidence that makes agent " +
            "actions attributable. No policy layer may grant an agent write access to it, so this is denied above " +
            "the policy merge and cannot be overridden.",
        policy: SELF_PROTECTION_POLICY_ID,
        outcome: "deny",
        evasion,
        scope,
        chokepoint,
    };
}
const NOT_PROTECTED = (attempt, chokepoint) => ({
    protected: false,
    who: attempt.principal ?? "(unattributed agent)",
    what: `${attempt.operation} (outside the DeepSweep store)`,
    why: "the target is not inside a DeepSweep store — the self-protection rule does not apply; the policy layers decide",
    policy: SELF_PROTECTION_POLICY_ID,
    outcome: "not-applicable",
    evasion: null,
    scope: null,
    chokepoint,
});
function isWellFormed(attempt) {
    const a = attempt;
    return (typeof a === "object" &&
        a !== null &&
        typeof a["path"] === "string" &&
        typeof a["operation"] === "string" &&
        MUTATIONS.includes(a["operation"]) &&
        (a["renameTo"] === undefined || typeof a["renameTo"] === "string") &&
        (a["principal"] === null || typeof a["principal"] === "string"));
}
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
export function guardFsMutation(attempt, ctx, chokepoint = null) {
    if (!isWellFormed(attempt)) {
        const forged = attempt;
        return decisionFor({ attribution: "agent", principal: null, operation: "write", path: "", ...forged }, "unknown-shape", null, null, chokepoint);
    }
    if (attempt.attribution === "human")
        return NOT_PROTECTED(attempt, chokepoint);
    const fs = ctx.fs ?? nodeSelfProtectionFs();
    const targets = attempt.operation === "rename" && attempt.renameTo !== undefined
        ? [
            { path: attempt.path, role: "rename-source" },
            { path: attempt.renameTo, role: "rename-target" },
        ]
        : [{ path: attempt.path, role: "direct" }];
    // 1. lexical on the requested paths
    for (const t of targets) {
        const abs = absolutize(t.path, ctx.workspaceRoot);
        const c = classifyPath(abs, ctx);
        if (c.protected)
            return decisionFor(attempt, t.role, c.scope, c.matched, chokepoint);
    }
    // LAZY, and computed at most once per call: enumerating the store's inodes
    // is the only O(store) work in the guard, and it is needed ONLY to unmask a
    // hard link. See PathProbe.linkCount — a single-linked file skips it
    // entirely, which is every ordinary write.
    let identityCache;
    const storeIdentities = () => (identityCache ??= fs.storeIdentities([
        resolve(ctx.workspaceRoot, PROTECTED_DIR),
        ...(ctx.userConfigRoot === undefined ? [] : [resolve(ctx.userConfigRoot, PROTECTED_DIR)]),
    ]));
    /**
     * The roots as the FILESYSTEM spells them. Found live on macOS, where
     * `/var` is itself a symlink to `/private/var`: a realpath-resolved target
     * never string-prefixes the as-spelled root, so a symlink into the store
     * was correctly DENIED but mis-attributed to `unrooted-store`. The verdict
     * was right for the wrong reason; the explanation has to be right too.
     */
    const resolvedCtx = {
        workspaceRoot: fs.probe(ctx.workspaceRoot).realPath ?? ctx.workspaceRoot,
        ...(ctx.userConfigRoot === undefined
            ? {}
            : { userConfigRoot: fs.probe(ctx.userConfigRoot).realPath ?? ctx.userConfigRoot }),
    };
    for (const t of targets) {
        const abs = absolutize(t.path, ctx.workspaceRoot);
        // 2. TOCTOU: probe twice. A resolution that moves under us is not a
        // benign race to be retried — it is the shape of the attack, so it lands
        // in deny rather than in "probably fine".
        const first = fs.probe(abs);
        const second = fs.probe(abs);
        if (first.realPath !== second.realPath || first.identity !== second.identity) {
            return decisionFor(attempt, "toctou-race", null, null, chokepoint);
        }
        // 3. symlink (path itself or any ancestor) resolving into a store
        if (first.realPath !== undefined) {
            const c = classifyPath(first.realPath, resolvedCtx);
            if (c.protected)
                return decisionFor(attempt, "symlink", c.scope, c.matched, chokepoint);
        }
        // 4. hard link: same inode as a file that lives under a store. `?? 2`
        // keeps an unknown link count on the CHECKING side of the branch.
        if (first.identity !== undefined && (first.linkCount ?? 2) > 1 && storeIdentities().has(first.identity)) {
            return decisionFor(attempt, "hardlink", "workspace-store", PROTECTED_DIR, chokepoint);
        }
    }
    return NOT_PROTECTED(attempt, chokepoint);
}
/**
 * The chokepoint entrypoint. EVERY acting surface (firewall, MCP, hooks)
 * calls this and nothing else: it evaluates the self-protection rule and then
 * routes through the ADR-010 ladder in enforce.ts, so no chokepoint can be
 * wired to a raw policy outcome (the ADR-010 enforcement invariant).
 */
export function guardAtChokepoint(chokepoint, attempt, ctx, policy) {
    const selfProtection = guardFsMutation(attempt, ctx, chokepoint);
    const enforcement = explainEnforcementAboveLayeredPolicy(selfProtection, policy.outcome, policy.status);
    return { ...enforcement, selfProtection, chokepoint };
}
/** Convenience for callers that only need the effect. */
export function chokepointEffect(chokepoint, attempt, ctx, policy) {
    return guardAtChokepoint(chokepoint, attempt, ctx, policy).effect;
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
export function selfProtectionOverrideAttempts(rules) {
    return rules
        .filter((r) => r.effect === "allow" && r.resource.toLowerCase().includes(PROTECTED_DIR))
        .map((r) => r.name)
        .sort();
}
/** The layer-refusal reason text (ADR-021 refusal machinery). */
export function selfProtectionRefusalReason(ruleNames) {
    return (`rule${ruleNames.length === 1 ? "" : "s"} ${ruleNames.join(", ")} attempt to allow access to ` +
        `${PROTECTED_DIR}/ — the DeepSweep store is protected above the policy merge and no layer may grant ` +
        "it (TEAM-ADR-028); the layer is refused rather than silently ignored");
}
