import { type Hex } from "./merkle.js";
export declare const EVIDENCE_SCHEMA_VERSION = 1;
/** Outcomes an evidence record may attest (ADR-009 vocabulary). */
export type EvidenceOutcome = "allow" | "deny" | "require-approval" | "observe";
/** Why the outcome happened, as a closed vocabulary (never free text). */
export type EvidenceReason = "rule-matched" | "default-effect" | "policy-refused" | "review-run";
export interface EvidenceRecordInput {
    readonly occurredAt: string;
    /** Workspace BASENAME only (ADR-003) — never an absolute path. */
    readonly workspace: string;
    readonly outcome: EvidenceOutcome;
    readonly reason: EvidenceReason;
    /** Raw decision tuple — hashed here, never stored or emitted. */
    readonly principal: string | null;
    readonly action: string;
    readonly resource: string;
    /** Deciding rule name (operator-authored) or null for a default effect. */
    readonly ruleName: string | null;
    readonly policyMode: string;
    readonly policyLayers: readonly string[];
    readonly matchedRuleCount: number;
}
export interface EvidenceRecord {
    readonly schemaVersion: typeof EVIDENCE_SCHEMA_VERSION;
    readonly occurredAt: string;
    readonly workspace: string;
    readonly outcome: EvidenceOutcome;
    readonly reason: EvidenceReason;
    /** SHA-256 of the principal, or of "" when unattributed. */
    readonly principalHash: Hex;
    readonly actionHash: Hex;
    readonly resourceHash: Hex;
    readonly ruleName: string | null;
    readonly policyMode: string;
    readonly policyLayers: readonly string[];
    readonly matchedRuleCount: number;
}
/** Build the record — the ONLY place raw tuple values are touched. */
export declare function buildEvidenceRecord(input: EvidenceRecordInput): EvidenceRecord;
/** RFC 8785 canonical serialization of a record (the bytes that get hashed). */
export declare function serializeEvidenceRecord(record: EvidenceRecord): string;
/** The record's Merkle leaf hash: RFC 6962 leaf hashing over JCS bytes. */
export declare function evidenceLeafHash(record: EvidenceRecord): Hex;
