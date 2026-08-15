import type { DriftFinding } from "./review/diff.js";
export declare const DEBOUNCE_QUIET_MS = 300;
export declare const DEBOUNCE_CEILING_MS = 2000;
/** Parent directories watched non-recursively ("" = workspace root). */
export declare const WATCHED_PARENT_DIRS: readonly string[];
export declare function isRelevantPath(rel: string): boolean;
/** Minimal writable surface (process.stdout/stderr are assignable). */
export interface WatchStream {
    write(chunk: string): boolean;
    once(event: "drain", listener: () => void): unknown;
}
export interface WatchOptions {
    workspaceRoot: string;
    /** JSONL events on stdout, human text on stderr (ADR-004). */
    json?: boolean;
    /** Explicit re-pin at session start (ADR-003 moment 2). */
    updateBaseline?: boolean;
    stdout?: WatchStream;
    stderr?: WatchStream;
    /** CLI installs SIGINT/SIGTERM handlers; tests opt out. */
    installSignalHandlers?: boolean;
    /** Test-only overrides; production defaults are the exported constants. */
    quietMs?: number;
    ceilingMs?: number;
    now?: () => Date;
}
export interface WatchSession {
    /** Close all watchers, run the session-end tamper check, flush output. */
    close(): Promise<void>;
    watcherCount(): number;
    /** Resolves when no review is running or pending (test helper). */
    whenIdle(): Promise<void>;
}
/**
 * Human render of one drift finding (stderr in --json mode, stdout otherwise).
 * The explanation uses the keep-ending sanitizer (QA defect D2, generalized
 * by S1.12): pin.drift, pin.conflict, identity.regenerated, and
 * baseline.tampered copy all end with their remediation/disclosure, which a
 * tail truncation would cut off. Exported for the D2/S1.12 regression tests.
 */
export declare function humanLine(f: DriftFinding): string;
/** May throw BaselineRefusalError before any watcher is created (exit 3). */
export declare function startWatch(opts: WatchOptions): Promise<WatchSession>;
