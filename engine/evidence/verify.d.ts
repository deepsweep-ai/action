/**
 * ADR-DS-006 — the AUDITOR's side: verify an exported evidence bundle
 * end-to-end, offline, with nothing but the bundle and the pinned public
 * keys. This is the verb that makes the moat usable by someone who does
 * not trust us: `deepsweep verify bundle.json`.
 *
 * Every check is independent of how the bundle was produced:
 *   1. tree head signature + log identity (ADR-DS-006) — is this OUR log?
 *   2. head binds the bundle's (size, root) — the ADR-DS-005 limit closed
 *   3. root recomputed from the records themselves — not taken on faith
 *   4. every inclusion proof re-verified against that root
 *   5. every consistency proof re-verified (append-only)
 *
 * Fail-closed: any failure yields verified:false with typed findings. An
 * UNSIGNED bundle verifies structurally but is reported as unattributed —
 * never as "verified", because internal consistency is not provenance.
 */
import type { TrustedKey } from "../review/bundle.js";
export interface VerificationFinding {
    readonly check: string;
    readonly ok: boolean;
    readonly detail: string;
}
export interface VerificationResult {
    /** True only when EVERY check passed AND the bundle was attributable. */
    readonly verified: boolean;
    readonly attributed: boolean;
    readonly logId: string | null;
    readonly treeSize: number;
    readonly findings: readonly VerificationFinding[];
}
/** Verify a parsed evidence bundle. Pure; no I/O, no clock. */
export declare function verifyEvidenceBundle(bundle: unknown, trustedKeys: readonly TrustedKey[]): VerificationResult;
