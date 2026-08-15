/**
 * Safe, read-only workspace file access for the review engine.
 * Security invariants (ADR-002, hardened by ADR-015):
 *  - Only allowlisted, root-relative paths are ever probed — EVERY probe
 *    (read, presence, listing) goes through the ONE contained resolver:
 *    lexical containment first, then realpath containment, so no path may
 *    resolve outside the root via traversal or symlink.
 *  - Presence probes are inode-type-aware: a directory can never satisfy a
 *    file probe (or vice versa), so capability presence cannot be forged by
 *    planting the wrong inode type.
 *  - Reads are fd-based with O_NOFOLLOW on the RESOLVED path: the classic
 *    TOCTOU (swap a symlink in after realpath, before read) fails at open,
 *    and size/type are checked via fstat on the SAME fd that is read.
 *  - Secret VALUES are never read into reports — key names / presence only.
 *  - No execution, no network.
 *
 * Residual threat model (documented, accepted): a LOCAL attacker who can
 * win a race on a parent directory component between realpathSync and
 * openSync can still redirect the resolved path (O_NOFOLLOW guards only the
 * final component). Closing that window fully requires openat()-style
 * per-component descent, which Node's portable fs API does not expose. The
 * consequence is bounded by design: reads are read-only, size-capped,
 * value-redacting, and never executed — a race winner can feed the review
 * false config bytes, which is the same power they already have by editing
 * the workspace they control.
 *
 * Windows (ADR-015): path prefix comparisons are case-normalized on win32 —
 * NTFS is case-insensitive, and drive-letter/path casing differs across
 * APIs, so a case-sensitive comparison silently skipped sources (fail
 * direction was missed detection; still a correctness bug). The comparison
 * helper is pure and exported so its win32 semantics are unit-tested on
 * every platform via path.win32.
 */
import { closeSync, constants, fstatSync, openSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
/** Max bytes we will read from any single config file (defensive bound). */
export const MAX_FILE_BYTES = 1_000_000;
/**
 * Pure containment comparison (exported for explicit path.win32 tests).
 * Case-insensitive when the platform's filesystems are (win32): folding is
 * only applied where the filesystem itself folds, because folding on a
 * case-SENSITIVE filesystem would loosen containment (fail-open) instead of
 * fixing missed detection (fail-closed). macOS needs no folding here: both
 * sides of every comparison are realpath-canonicalized to on-disk casing.
 */
export function isPathContained(root, target, opts = {}) {
    const separator = opts.separator ?? sep;
    const fold = opts.caseInsensitive ?? process.platform === "win32";
    const r = fold ? root.toLowerCase() : root;
    const t = fold ? target.toLowerCase() : target;
    return t === r || t.startsWith(r + separator);
}
/**
 * THE contained resolver core — every filesystem probe in this module routes
 * through it (S1.14 classified the outcomes; the containment logic itself is
 * unchanged from ADR-002/ADR-015): lexical containment first, then realpath
 * containment. A containment refusal (lexical traversal or symlink escape)
 * is classed "escaping-symlink"; ENOENT/ENOTDIR is ABSENT; any other
 * filesystem error is "io-error".
 */
function resolveContainedClassified(rootDir, relPath) {
    const root = resolve(rootDir);
    const target = resolve(join(root, relPath));
    if (!isPathContained(root, target))
        return { status: "refused", reason: "escaping-symlink" };
    try {
        const real = realpathSync(target);
        const realRoot = realpathSync(root);
        if (!isPathContained(realRoot, real))
            return { status: "refused", reason: "escaping-symlink" };
        return { status: "ok", real };
    }
    catch (err) {
        const code = err.code;
        // ENOENT: no such entry. ENOTDIR: a parent path component is a file —
        // the probed path cannot exist, which is absence, not refusal.
        if (code === "ENOENT" || code === "ENOTDIR")
            return { status: "absent" };
        return { status: "refused", reason: "io-error" };
    }
}
/** Undefined-collapsing view of the classified resolver (presence probes). */
function resolveContained(rootDir, relPath) {
    const c = resolveContainedClassified(rootDir, relPath);
    return c.status === "ok" ? c.real : undefined;
}
/** O_NOFOLLOW where the platform provides it (win32 lacks it: 0 = no-op). */
/* v8 ignore next -- reason: constants.O_NOFOLLOW is defined on every POSIX platform the suite runs on; the fallback exists solely for win32 field use. */
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
/**
 * S1.14 — probing read with absent-vs-unreadable classification. Same
 * containment core, same fd discipline as the original safeRead; the ONLY
 * addition is that refusals carry a metadata reason class (path is the
 * caller's; content NEVER rides on a refusal — an unreadable result carries
 * no bytes by construction).
 */
export function probeRead(workspaceRoot, relPath) {
    const c = resolveContainedClassified(workspaceRoot, relPath);
    if (c.status === "absent")
        return { status: "absent" };
    if (c.status === "refused")
        return { status: "unreadable", reason: c.reason };
    try {
        // TOCTOU mitigation (ADR-015): open the RESOLVED path with O_NOFOLLOW —
        // a symlink swapped in after realpath fails the open — then fstat and
        // read the SAME fd, so the type/size decision and the bytes read cannot
        // diverge.
        const fd = openSync(c.real, constants.O_RDONLY | NOFOLLOW);
        try {
            const st = fstatSync(fd);
            if (!st.isFile())
                return { status: "unreadable", reason: "not-a-file" };
            if (st.size > MAX_FILE_BYTES)
                return { status: "unreadable", reason: "oversized" };
            return { status: "ok", text: readFileSync(fd, "utf8") };
        }
        finally {
            closeSync(fd);
        }
    }
    catch {
        return { status: "unreadable", reason: "io-error" };
    }
}
/** Undefined-collapsing read (pre-S1.14 contract, kept for presence-style callers). */
export function safeRead(workspaceRoot, relPath) {
    const p = probeRead(workspaceRoot, relPath);
    return p.status === "ok" ? p.text : undefined;
}
/**
 * Inode-type-aware presence probe. A directory can never satisfy a "file"
 * probe (a directory named AGENTS.md is not agent instructions), and a file
 * can never satisfy a "directory" probe (a file named .git is not a
 * repository) — presence capabilities cannot be forged by inode type.
 */
export function exists(workspaceRoot, relPath, expect = "file") {
    const real = resolveContained(workspaceRoot, relPath);
    if (real === undefined)
        return false;
    try {
        const st = statSync(real);
        return expect === "file" ? st.isFile() : st.isDirectory();
    }
    catch {
        return false;
    }
}
/**
 * ADR-014 — user-scope config reads (e.g. ~/.codeium/windsurf/mcp_config.json).
 * Identical invariants to the workspace readers, anchored at an EXPLICIT
 * user-config root instead of the workspace: allowlisted relative paths
 * only, symlinks resolving outside the root refused, size-capped, no
 * execution, no network. The root is injected by the composition layer
 * (the CLI's sanctioned profile-directory lookup in production; a temp dir
 * in tests) — the engine never locates the user profile itself (ADR-005).
 */
export function safeReadUser(userConfigRoot, relPath) {
    return safeRead(userConfigRoot, relPath);
}
/** User-scope sibling of probeRead (ADR-014 invariants; S1.14 classification). */
export function probeReadUser(userConfigRoot, relPath) {
    return probeRead(userConfigRoot, relPath);
}
/** Max directory entries surfaced by listDirNames (bounds attacker fan-out). */
export const MAX_DIR_ENTRIES = 200;
/**
 * List entry NAMES of an allowlisted, workspace-relative directory.
 * Metadata only — entry contents are never read here; no recursion; symlinked
 * directories resolving outside the workspace root are refused. Sorted for
 * determinism and capped at MAX_DIR_ENTRIES (sorted-first) to bound
 * attacker-created fan-out.
 */
export function probeDirNames(workspaceRoot, relPath) {
    const c = resolveContainedClassified(workspaceRoot, relPath);
    if (c.status === "absent")
        return { status: "absent" };
    if (c.status === "refused")
        return { status: "unreadable", reason: c.reason };
    try {
        if (!statSync(c.real).isDirectory())
            return { status: "unreadable", reason: "not-a-file" };
    }
    catch {
        // stat succeeded during containment but fails now, or raced: unknown, not empty.
        return { status: "unreadable", reason: "io-error" };
    }
    try {
        return { status: "ok", names: readdirSync(c.real).sort().slice(0, MAX_DIR_ENTRIES) };
    }
    catch {
        // EACCES/EPERM land here — the directory EXISTS and we cannot enumerate it.
        return { status: "unreadable", reason: "io-error" };
    }
}
/**
 * Undefined-collapsing listing (pre-S1.14 contract, kept for presence-style
 * callers that genuinely do not care why the list is empty).
 *
 * Prefer `probeDirNames` in any detector: collapsing here is exactly what let
 * an unreadable rules directory read as an empty one.
 */
export function listDirNames(workspaceRoot, relPath) {
    const p = probeDirNames(workspaceRoot, relPath);
    return p.status === "ok" ? p.names : [];
}
/**
 * Tolerant JSON parse for config files that may contain JSONC-style
 * line/block comments and trailing commas (e.g. .vscode/settings.json).
 * Deterministic; returns undefined on unrecoverable input.
 */
export function parseTolerantJson(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        /* fall through to tolerant pass */
    }
    let out = "";
    let inString = false;
    let escaped = false;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        const next = text[i + 1];
        if (inString) {
            out += ch;
            if (escaped)
                escaped = false;
            else if (ch === "\\")
                escaped = true;
            else if (ch === '"')
                inString = false;
            continue;
        }
        if (ch === '"') {
            inString = true;
            out += ch;
            continue;
        }
        if (ch === "/" && next === "/") {
            while (i < text.length && text[i] !== "\n")
                i++;
            out += "\n";
            continue;
        }
        if (ch === "/" && next === "*") {
            i += 2;
            while (i < text.length && !(text[i] === "*" && text[i + 1] === "/"))
                i++;
            i++; // skip the '/'
            continue;
        }
        out += ch;
    }
    // Strip trailing commas STRING-AWARE (second walk over the comment-free
    // text): a comma outside a string literal whose next non-whitespace
    // character is `}` or `]` is dropped. A regex post-pass here corrupted
    // string VALUES containing ",}" or ",]" — silently altering reviewed
    // configuration bytes, which a governance tool can never do.
    let stripped = "";
    inString = false;
    escaped = false;
    for (let i = 0; i < out.length; i++) {
        const ch = out[i];
        if (inString) {
            stripped += ch;
            if (escaped)
                escaped = false;
            else if (ch === "\\")
                escaped = true;
            else if (ch === '"')
                inString = false;
            continue;
        }
        if (ch === '"') {
            inString = true;
            stripped += ch;
            continue;
        }
        if (ch === ",") {
            let j = i + 1;
            while (j < out.length && /\s/.test(out[j]))
                j++;
            if (out[j] === "}" || out[j] === "]")
                continue;
        }
        stripped += ch;
    }
    try {
        return JSON.parse(stripped);
    }
    catch {
        return undefined;
    }
}
/** Parse .env-style content returning KEY NAMES ONLY (values are discarded). */
export function envKeyNames(text) {
    const keys = [];
    for (const line of text.split("\n")) {
        const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
        if (m && m[1])
            keys.push(m[1]);
    }
    return keys;
}
