/** The single durable-state directory (ADR-003). */
export declare const STORE_DIR = ".deepsweep";
export interface StorePaths {
    root: string;
    dir: string;
    file: string;
}
/**
 * Containment checks per ADR-003; throws the caller's refusal error on
 * violation. `refuse` receives the reason and returns the error to throw.
 */
export declare function checkedStorePaths(workspaceRoot: string, fileName: string, refuse: (reason: string) => Error): StorePaths;
/**
 * Contained read of a store file's text. Returns undefined when absent, not a
 * regular file, over the size cap, or unreadable; throws the caller's refusal
 * error only for containment violations.
 */
export declare function readStoreText(workspaceRoot: string, fileName: string, refuse: (reason: string) => Error): string | undefined;
/**
 * Atomic, contained store write. Returns the SHA-256 of the written bytes so
 * callers can track in-session tamper-check hashes.
 */
export declare function writeStoreAtomic(workspaceRoot: string, fileName: string, text: string, refuse: (reason: string) => Error): {
    fileHash: string;
};
/**
 * Contained O(1) line append (ADR-018 hot-path amendment, 2026-08-01): the
 * audit ledger appends one JSONL line per review, and the atomic
 * temp+fsync+rename rewrite made that O(file) with a multi-ms fsync on the
 * REVIEW hot path (live bench tripwire caught it at 2x the ADR-017 budget).
 * Same containment discipline as writeStoreAtomic (checked paths, mkdir
 * re-check, O_NOFOLLOW so a swapped symlink fails the open). Durability
 * trade, documented: no fsync — a crash may lose the line being appended
 * (a lost record is not tamper; the chain re-links from the surviving
 * tail), and a torn line is TAMPER-EVIDENT by design (readLedger → corrupt
 * sentinel → loud finding). Auditability model unchanged (ADR-018).
 */
export declare function appendStoreLine(workspaceRoot: string, fileName: string, line: string, refuse: (reason: string) => Error): void;
