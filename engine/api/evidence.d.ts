import type { EvidenceBundle } from "../evidence/export.js";
import type { VerificationResult } from "../evidence/verify.js";
export interface ExportEvidenceParams {
    readonly workspaceRoot: string;
    /** Injected clock (determinism invariant). */
    readonly nowIso: string;
    /** Prior published tree size to prove append-only extension from. */
    readonly sinceSize?: number;
    /**
     * ADR-DS-006 Ed25519 private key, as PEM TEXT. Absent = an internally
     * consistent but UNATTRIBUTED export, which is never "verified".
     */
    readonly signWithPem?: string;
}
export interface ExportEvidenceResult {
    readonly bundle: EvidenceBundle;
    /** 0 ok · 3 unverifiable (malformed ledger — fail-closed, no partial proofs). */
    readonly exitCode: 0 | 3;
}
/** Raised when supplied credential/trust material cannot be parsed. */
export declare class EvidenceMaterialError extends Error {
    constructor(message: string);
}
/**
 * Build the evidence bundle for a workspace. Read-only. A malformed ledger
 * yields a refusal bundle (status "unverifiable") and exit 3 — never a
 * partial or fabricated proof set.
 */
export declare function exportEvidenceBundle(params: ExportEvidenceParams): ExportEvidenceResult;
/** One trusted public key an auditor checks a signed tree head against. */
export interface TrustedKeyEntry {
    readonly keyId: string;
    readonly publicKey: string;
}
export interface VerifyEvidenceParams {
    /** Parsed bundle document (JSON.parse output, never a path). */
    readonly bundle: unknown;
    /** Pinned trust set. Empty = nothing can be attributed. */
    readonly trustedKeys?: readonly TrustedKeyEntry[];
}
export interface VerifyEvidenceResult {
    readonly result: VerificationResult;
    /** 0 verified · 4 refused (any check failed, including "unattributed"). */
    readonly exitCode: 0 | 4;
}
/**
 * Parse a `policy-keys.json`-shaped trust document into trusted key entries.
 * Tolerant by shape (unknown fields ignored, malformed entries dropped) and
 * strict by type — a non-object document is a refusal, never an empty
 * trust set that would silently downgrade verification to "unattributed".
 */
export declare function parseTrustedKeys(doc: unknown): readonly TrustedKeyEntry[];
/**
 * The auditor's offline check. Pure: no I/O, no clock. Internal consistency
 * is NOT provenance — an unsigned bundle is UNATTRIBUTED (exit 4), never
 * verified.
 */
export declare function verifyEvidence(params: VerifyEvidenceParams): VerifyEvidenceResult;
