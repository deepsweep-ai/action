/**
 * RFC 8785 (JCS)-style canonicalization + SHA-256 hashing for the pinned
 * baseline identity (ADR-003). Pure, deterministic, zero dependencies.
 *
 * Contract (ADR-003 "Hashing and canonicalization"):
 *  - Object keys sorted by UTF-16 code unit (default Array.prototype.sort).
 *  - No insignificant whitespace; numbers in shortest round-trip form and
 *    strings with minimal JSON escaping (both via JSON.stringify, which
 *    matches JCS serialization for ECMAScript values).
 *  - String VALUES are byte-preserved: no Unicode normalization, no
 *    whitespace collapsing, no escape folding beyond JSON's mandatory
 *    escapes. Two descriptions differing in ANY code point (zero-width,
 *    bidi, CRLF…) hash differently — that is drift, not noise.
 *  - Canonicalization operates only on JSON structure, never on string
 *    content.
 */
import { createHash } from "node:crypto";
export function sha256Hex(text) {
    return createHash("sha256").update(text, "utf8").digest("hex");
}
/**
 * Canonicalize a parsed-JSON value into a deterministic string.
 * Throws on values that cannot appear in parsed JSON (functions, symbols,
 * non-finite numbers) — callers only pass values from JSON.parse.
 */
export function canonicalize(value) {
    if (value === null)
        return "null";
    switch (typeof value) {
        case "boolean":
            return value ? "true" : "false";
        case "number":
            if (!Number.isFinite(value)) {
                throw new TypeError("Cannot canonicalize non-finite number");
            }
            return JSON.stringify(value);
        case "string":
            return JSON.stringify(value);
        case "object": {
            if (Array.isArray(value)) {
                return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
            }
            const rec = value;
            const parts = [];
            for (const key of Object.keys(rec).sort()) {
                const v = rec[key];
                if (v === undefined)
                    continue;
                parts.push(`${JSON.stringify(key)}:${canonicalize(v)}`);
            }
            return `{${parts.join(",")}}`;
        }
        default:
            throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
    }
}
/** Max duplicate key names reported per document (bounds attacker fan-out). */
export const MAX_DUPLICATE_KEYS = 10;
/**
 * Detect duplicate keys within a single JSON object (ADR-003: parsing is
 * deterministic last-wins, but duplicates are a review finding). Operates on
 * raw text with string/escape/JSONC-comment awareness; keys are compared in
 * their raw escaped form (an escape-variant duplicate simply goes unflagged —
 * parsing behavior is unaffected). Returns duplicate key names, bounded.
 */
export function findDuplicateJsonKeys(text, max = MAX_DUPLICATE_KEYS) {
    const dups = [];
    /** Stack of open containers: a Set of seen keys for objects, null for arrays. */
    const stack = [];
    const n = text.length;
    let i = 0;
    while (i < n && dups.length < max) {
        const ch = text[i];
        if (ch === '"') {
            let j = i + 1;
            let escaped = false;
            let raw = "";
            while (j < n) {
                const c = text[j];
                if (escaped) {
                    raw += `\\${c}`;
                    escaped = false;
                    j++;
                    continue;
                }
                if (c === "\\") {
                    escaped = true;
                    j++;
                    continue;
                }
                if (c === '"')
                    break;
                raw += c;
                j++;
            }
            i = j + 1;
            // Look ahead (skipping whitespace/comments) for ':' → this string is a key.
            let k = i;
            while (k < n) {
                const c = text[k];
                if (c === " " || c === "\t" || c === "\n" || c === "\r") {
                    k++;
                    continue;
                }
                if (c === "/" && text[k + 1] === "/") {
                    while (k < n && text[k] !== "\n")
                        k++;
                    continue;
                }
                if (c === "/" && text[k + 1] === "*") {
                    k += 2;
                    while (k < n && !(text[k] === "*" && text[k + 1] === "/"))
                        k++;
                    k += 2;
                    continue;
                }
                break;
            }
            if (text[k] === ":") {
                const top = stack[stack.length - 1];
                if (top instanceof Set) {
                    if (top.has(raw)) {
                        if (!dups.includes(raw))
                            dups.push(raw);
                    }
                    else {
                        top.add(raw);
                    }
                }
            }
            continue;
        }
        if (ch === "/" && text[i + 1] === "/") {
            while (i < n && text[i] !== "\n")
                i++;
            continue;
        }
        if (ch === "/" && text[i + 1] === "*") {
            i += 2;
            while (i < n && !(text[i] === "*" && text[i + 1] === "/"))
                i++;
            i += 2;
            continue;
        }
        if (ch === "{") {
            stack.push(new Set());
            i++;
            continue;
        }
        if (ch === "[") {
            stack.push(null);
            i++;
            continue;
        }
        if (ch === "}" || ch === "]") {
            stack.pop();
            i++;
            continue;
        }
        i++;
    }
    return dups;
}
