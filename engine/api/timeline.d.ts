import type { LedgerEntry } from "../review/ledger.js";
export interface TimelineParams {
    readonly workspaceRoot: string;
}
export interface TimelineResult {
    /** Empty when the ledger is absent OR malformed — see `status`. */
    readonly entries: readonly LedgerEntry[];
    /**
     * `absent` — no ledger yet · `malformed` — unparseable on disk (left in
     * place so it stays verifiable against an exported anchor) · `ok`.
     */
    readonly status: "ok" | "absent" | "malformed";
    /**
     * ADR-018 hash-chain integrity. FALSE for a malformed ledger — never
     * "unknown", never optimistic: a timeline that cannot be verified is not
     * verified (fail-closed).
     */
    readonly chainVerified: boolean;
    /** RFC 6962 tree head over the entries; null when there is nothing to commit to. */
    readonly treeHead: string | null;
    readonly entryCount: number;
}
/**
 * Read the local audit timeline. May throw LedgerRefusalError on a
 * `.deepsweep/` containment violation (ADR-003 refusal class).
 */
export declare function ledgerTimeline(params: TimelineParams): TimelineResult;
