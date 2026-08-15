export declare function sha256Hex(text: string): string;
/**
 * Canonicalize a parsed-JSON value into a deterministic string.
 * Throws on values that cannot appear in parsed JSON (functions, symbols,
 * non-finite numbers) — callers only pass values from JSON.parse.
 */
export declare function canonicalize(value: unknown): string;
/** Max duplicate key names reported per document (bounds attacker fan-out). */
export declare const MAX_DUPLICATE_KEYS = 10;
/**
 * Detect duplicate keys within a single JSON object (ADR-003: parsing is
 * deterministic last-wins, but duplicates are a review finding). Operates on
 * raw text with string/escape/JSONC-comment awareness; keys are compared in
 * their raw escaped form (an escape-variant duplicate simply goes unflagged —
 * parsing behavior is unaffected). Returns duplicate key names, bounded.
 */
export declare function findDuplicateJsonKeys(text: string, max?: number): string[];
