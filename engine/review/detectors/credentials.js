/**
 * ADR-013 — static credential-pattern review for MCP server arguments.
 *
 * Credentials most commonly ride in args (`--conn postgres://user:pass@…`,
 * `--token …`, raw bearer strings), which the detectors previously dropped
 * entirely. This module reviews args for credential SHAPE and returns
 * pattern kinds + arg indexes ONLY — no credential value, nor any arg
 * substring, ever leaves this module (metadata-first; the privacy
 * regression test greps every serialized surface for fixture secrets).
 *
 * Patterns (deliberately few, each named for its shape):
 *  - "url-userinfo"  — any userinfo section in a URL-shaped arg
 *                      (scheme://user:pass@host or scheme://token@host).
 *  - "key-flag"      — a key-like flag carrying a value: --password/--token/
 *                      --api-key/--secret/… (either `--flag=value`, indexed
 *                      at the flag, or `--flag value`, indexed at the VALUE)
 *                      plus bare `-p <value>`.
 *  - "high-entropy"  — a standalone token >20 chars mixing letters and
 *                      digits (≥2 character classes). Bounded against the
 *                      common false positives: path-shaped args (contain a
 *                      path separator) and flag-shaped args (leading dash)
 *                      are never counted; URLs are the url-userinfo
 *                      pattern's job.
 *
 * Transport review (same module, same never-surface rule): the first
 * URL-shaped arg is located so MCP transport checks can classify cleartext
 * HTTP even when the endpoint is passed via args rather than `url`.
 * Loopback hosts are exempt from the cleartext classification (local
 * stdio-adjacent servers legitimately speak http://localhost).
 */
/** Any userinfo in an authority: scheme://user[:pass]@host. */
const URL_USERINFO = /:\/\/[^/@\s]+@/;
/** Key-like flags whose VALUE is a credential. Matched against the flag
 * head only (the part before `=`), case-insensitively. */
const KEY_FLAG = /^--?(password|passwd|passphrase|pass|token|api[-_]?key|apikey|secret|auth(?:orization)?|credentials?|access[-_]?key|private[-_]?key|client[-_]?secret)$/i;
/** The task-named short form: `-p` followed by a value. */
const SHORT_P = /^-p$/;
function highEntropyShaped(arg) {
    if (arg.length <= 20)
        return false;
    if (arg.startsWith("-"))
        return false; // flag-shaped, not a bare token
    if (/[/\\]/.test(arg))
        return false; // path-shaped (bin paths, specifiers)
    if (!/[A-Za-z]/.test(arg) || !/[0-9]/.test(arg))
        return false;
    const classes = Number(/[a-z]/.test(arg)) +
        Number(/[A-Z]/.test(arg)) +
        Number(/[0-9]/.test(arg)) +
        Number(/[^A-Za-z0-9]/.test(arg));
    return classes >= 2;
}
/**
 * Review args for credential shapes. Deterministic: hits are sorted by
 * argIndex; each index is claimed by at most one pattern, in specificity
 * order (url-userinfo > key-flag > high-entropy).
 */
export function reviewArgsForCredentials(args) {
    const hits = [];
    const claimed = new Set();
    const claim = (credentialPattern, argIndex) => {
        if (claimed.has(argIndex))
            return;
        claimed.add(argIndex);
        hits.push({ credentialPattern, argIndex });
    };
    args.forEach((arg, i) => {
        if (URL_USERINFO.test(arg))
            claim("url-userinfo", i);
    });
    args.forEach((arg, i) => {
        const eq = arg.indexOf("=");
        const head = eq > 0 ? arg.slice(0, eq) : arg;
        if (!KEY_FLAG.test(head) && !SHORT_P.test(head))
            return;
        if (eq > 0) {
            claim("key-flag", i); // --flag=value: the flag arg carries the value
        }
        else {
            const next = args[i + 1];
            if (next !== undefined && !next.startsWith("-"))
                claim("key-flag", i + 1);
        }
    });
    args.forEach((arg, i) => {
        if (highEntropyShaped(arg))
            claim("high-entropy", i);
    });
    return hits.sort((a, b) => a.argIndex - b.argIndex);
}
/** Hostnames exempt from the cleartext classification (port-free input). */
function isLoopbackHost(hostname) {
    const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return h === "localhost" || h === "::1" || h === "0.0.0.0" || /^127\.\d+\.\d+\.\d+$/.test(h);
}
/**
 * True when the URL is cleartext http to a NON-loopback host.
 *
 * A WHATWG-URL parse failure is NOT evidence of safety. MCP clients are more
 * permissive than `new URL()`, so returning false on a throw let a hostile
 * `.mcp.json` hide a cleartext endpoint behind a string the parser rejects but
 * the client still dials. On parse failure we fall back to a scheme-prefix
 * check over the raw text and only clear the URL when we can positively see a
 * loopback authority — unknown resolves to "cleartext", not to silence.
 */
export function isCleartextHttpUrl(raw) {
    try {
        const u = new URL(raw);
        // hostname, not host: host carries the port and would defeat the
        // loopback comparison ("localhost:3000" !== "localhost").
        return u.protocol === "http:" && u.hostname !== "" && !isLoopbackHost(u.hostname);
    }
    catch {
        return unparseableLooksCleartext(raw);
    }
}
/**
 * Scheme-prefix fallback for input `new URL()` refuses. Deliberately textual:
 * it must not depend on the parser that just failed.
 */
function unparseableLooksCleartext(raw) {
    const s = raw.trim();
    if (!/^http:\/\//i.test(s))
        return false;
    // Authority = everything up to the first /, ?, or # after the scheme.
    const authority = s.slice("http://".length).split(/[/?#]/, 1)[0] ?? "";
    if (authority === "")
        return false; // "http://" alone declares no endpoint
    // Strip userinfo, then the port, before the loopback comparison.
    const hostPort = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
    const host = hostPort.startsWith("[")
        ? hostPort.slice(0, hostPort.indexOf("]") + 1) // bracketed IPv6 keeps its brackets
        : (hostPort.split(":", 1)[0] ?? "");
    if (host === "")
        return false;
    return !isLoopbackHost(host);
}
/** Index of the first URL-shaped arg (contains ://), or undefined. */
export function firstUrlArgIndex(args) {
    const i = args.findIndex((a) => a.includes("://"));
    return i >= 0 ? i : undefined;
}
