/**
 * ADR-DS-005 — evidence export: the local hash-chained ledger (ADR-018)
 * projected into an RFC 6962 Merkle log, with inclusion and consistency
 * proofs a third party can verify against nothing but the published root.
 *
 * The two structures answer different questions and BOTH ship:
 *  - hash CHAIN (ADR-018): "was this file edited?" — cheap, append-time.
 *  - Merkle LOG (RFC 6962): "is entry k in the log committed to by root R,
 *    and is log R2 an append-only extension of R1?" — the property a
 *    transparency auditor, a regulator, or a court can check offline.
 *
 * Fail-closed: a malformed ledger yields a refusal bundle (status
 * "unverifiable"), never a partial or fabricated proof set.
 */
import { type LedgerEntry } from "../review/ledger.js";
import { type EvidenceRecord } from "./record.js";
import { type SignedTreeHead } from "./treehead.js";
import { type Hex } from "./merkle.js";
export interface InclusionProofExport {
    readonly leafIndex: number;
    readonly leafHash: Hex;
    readonly treeSize: number;
    readonly proof: readonly Hex[];
    /** Self-check performed at export time (never a substitute for the
     * verifier's own check — recorded so a bad export is obvious). */
    readonly selfVerified: boolean;
}
export interface ConsistencyProofExport {
    readonly firstSize: number;
    readonly firstRoot: Hex;
    readonly secondSize: number;
    readonly secondRoot: Hex;
    readonly proof: readonly Hex[];
    readonly selfVerified: boolean;
}
export type EvidenceBundle = {
    readonly status: "ok";
    readonly schemaVersion: 1;
    readonly workspace: string;
    readonly generatedAt: string;
    readonly treeSize: number;
    readonly root: Hex;
    readonly chainIntact: boolean;
    readonly records: readonly EvidenceRecord[];
    readonly inclusion: readonly InclusionProofExport[];
    readonly consistency: readonly ConsistencyProofExport[];
    /** ADR-DS-006: present when the operator signed this export. Absent
     * means internally consistent but UNATTRIBUTED — never "verified". */
    readonly signedTreeHead?: SignedTreeHead;
} | {
    readonly status: "unverifiable";
    readonly reason: string;
};
/** Map one ledger entry to its evidence record (metadata-only by shape). */
export declare function recordFromLedgerEntry(entry: LedgerEntry, workspace: string): EvidenceRecord;
export interface ExportOptions {
    readonly workspace: string;
    readonly generatedAt: string;
    /** Prior published tree size to prove append-only extension from. */
    readonly sinceSize?: number;
    /** Cap on per-leaf inclusion proofs emitted (all leaves by default). */
    readonly maxInclusion?: number;
    /** ADR-DS-006: signs the resulting (size, root) as a tree head. */
    readonly signTreeHeadWith?: import("node:crypto").KeyObject;
}
/**
 * Build the evidence bundle for a workspace: every ledger entry as a
 * canonical record, the Merkle root, an inclusion proof per record, and a
 * consistency proof from `sinceSize` when supplied.
 */
export declare function exportEvidence(workspaceRoot: string, opts: ExportOptions): EvidenceBundle;
