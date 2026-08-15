export declare const HARDEN_REPORT_SCHEMA_VERSION = 1;
export type HardenControl = "append-only-flag" | "immutable-flag" | "deny-write-acl";
/**
 * `applied`      — the control is now in force.
 * `refused`      — the OS rejected it (usually: needs elevation).
 * `unsupported`  — this platform has no such control.
 * `not-attempted`— a precondition failed (e.g. the target does not exist).
 */
export type HardenStatus = "applied" | "refused" | "unsupported" | "not-attempted";
export interface HardenStep {
    readonly control: HardenControl;
    /** The OS mechanism, named plainly so the report is auditable. */
    readonly mechanism: string;
    readonly status: HardenStatus;
    /** What this control DOES guarantee once applied. null when not applied. */
    readonly guarantees: string | null;
    /** What it does NOT guarantee even when applied. Always present. */
    readonly doesNotGuarantee: string;
    /** The "I could not do X because Y" sentence. Always present. */
    readonly why: string;
}
export interface HardenReport {
    readonly schemaVersion: typeof HARDEN_REPORT_SCHEMA_VERSION;
    readonly platform: string;
    readonly elevated: boolean;
    /** Store-relative target paths, sorted. Never absolute. */
    readonly targets: readonly string[];
    readonly attemptedAt: string;
    readonly steps: readonly HardenStep[];
    readonly overall: "hardened" | "partially-hardened" | "not-hardened";
    /** One honest sentence. The Studio renders this as the headline. */
    readonly summary: string;
    /** What remains possible even after a fully successful hardening run. */
    readonly residualRisks: readonly string[];
}
export interface HardenRunResult {
    readonly ok: boolean;
    readonly code: number | null;
    /** Failure CLASS only — never the child's stderr text (metadata-first). */
    readonly failure: "not-permitted" | "unsupported-filesystem" | "not-found" | "failed" | null;
}
export interface HardenSyscalls {
    readonly platform: string;
    readonly elevated: boolean;
    run(command: string, args: readonly string[]): HardenRunResult;
    exists(absolutePath: string): boolean;
}
/** Map an exit code to a failure class. No stderr ever crosses this boundary:
 * a child's stderr can echo a path or a filename, and the report is a
 * cloud-renderable artifact. */
export declare function classifyHardenExit(code: number | null): HardenRunResult["failure"];
/** The production seam. Fixed command names and argv arrays — no shell, and
 * no user-controlled string ever reaches a command position. */
export declare function nodeHardenSyscalls(): HardenSyscalls;
export interface HardenOptions {
    readonly nowIso: string;
    readonly syscalls?: HardenSyscalls;
}
/**
 * Apply the best OS protection available for the ledger and its signature
 * sidecar, and report exactly what happened.
 *
 * Never throws for a protection failure: a refused control is a reported step.
 */
export declare function hardenLedger(workspaceRoot: string, opts: HardenOptions): HardenReport;
/** Plain-text rendering. The Studio may render the structure itself; this is
 * the canonical wording so both surfaces say the same thing. */
export declare function renderHardenReport(r: HardenReport): string;
