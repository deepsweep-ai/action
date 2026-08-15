/**
 * Engine library — `timeline` capability (TEAM-ADR-027).
 *
 * The audit timeline (the Studio's Ledger screen, ADR-018) was reachable only
 * as a side effect of rendering the whole Studio artifact. It is now a
 * first-class function so the Studio can refresh the timeline over IPC — and
 * a CI runner can assert chain integrity — without re-rendering an HTML page.
 *
 * Metadata-first: ledger entries are counts and hashes by construction; this
 * function adds no content and reads no workspace files beyond the store.
 */
import { resolve } from "node:path";
import { ledgerTreeHead, readLedger, verifyChain } from "../review/ledger.js";
/**
 * Read the local audit timeline. May throw LedgerRefusalError on a
 * `.deepsweep/` containment violation (ADR-003 refusal class).
 */
export function ledgerTimeline(params) {
    const root = resolve(params.workspaceRoot);
    const entries = readLedger(root);
    if (entries === undefined) {
        return { entries: [], status: "malformed", chainVerified: false, treeHead: null, entryCount: 0 };
    }
    if (entries.length === 0) {
        return { entries: [], status: "absent", chainVerified: true, treeHead: null, entryCount: 0 };
    }
    return {
        entries,
        status: "ok",
        chainVerified: verifyChain(entries),
        treeHead: ledgerTreeHead(entries),
        entryCount: entries.length,
    };
}
