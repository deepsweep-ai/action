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
export type CredentialPattern = "url-userinfo" | "key-flag" | "high-entropy";
export interface ArgCredentialHit {
    readonly credentialPattern: CredentialPattern;
    /** Index into the server's args array — a pointer, never the content. */
    readonly argIndex: number;
}
/**
 * Review args for credential shapes. Deterministic: hits are sorted by
 * argIndex; each index is claimed by at most one pattern, in specificity
 * order (url-userinfo > key-flag > high-entropy).
 */
export declare function reviewArgsForCredentials(args: readonly string[]): ArgCredentialHit[];
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
export declare function isCleartextHttpUrl(raw: string): boolean;
/** Index of the first URL-shaped arg (contains ://), or undefined. */
export declare function firstUrlArgIndex(args: readonly string[]): number | undefined;
