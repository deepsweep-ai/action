/**
 * Engine library — `export` and `verify` capabilities (TEAM-ADR-027).
 *
 * The proof machinery already lived in the library (ADR-DS-005/006); what
 * lived in the `deepsweep export|verify` command layer was the credential and
 * trust-file PARSING. That is now here, so the Studio and the sidecar do not
 * each re-implement it — and so the failure shapes are tested once.
 *
 * Credential discipline: these functions take key MATERIAL (PEM / parsed
 * trust entries), never a path. File IO stays at the composition root that
 * the operator actually pointed at a file, which keeps this module free of an
 * IPC-reachable arbitrary-file-read oracle.
 */
import { basename, resolve } from "node:path";
import { createPrivateKey } from "node:crypto";
import { exportEvidence } from "../evidence/export.js";
import { verifyEvidenceBundle } from "../evidence/verify.js";
/** Raised when supplied credential/trust material cannot be parsed. */
export class EvidenceMaterialError extends Error {
    constructor(message) {
        super(message);
        this.name = "EvidenceMaterialError";
    }
}
/**
 * Build the evidence bundle for a workspace. Read-only. A malformed ledger
 * yields a refusal bundle (status "unverifiable") and exit 3 — never a
 * partial or fabricated proof set.
 */
export function exportEvidenceBundle(params) {
    const root = resolve(params.workspaceRoot);
    let signingKey;
    if (params.signWithPem !== undefined) {
        try {
            signingKey = createPrivateKey(params.signWithPem);
        }
        catch {
            // Deliberately generic: the message never echoes key bytes or a path.
            throw new EvidenceMaterialError("signing material is not a readable Ed25519 private key");
        }
    }
    const bundle = exportEvidence(root, {
        workspace: basename(root),
        generatedAt: params.nowIso,
        ...(params.sinceSize !== undefined ? { sinceSize: params.sinceSize } : {}),
        ...(signingKey !== undefined ? { signTreeHeadWith: signingKey } : {}),
    });
    return { bundle, exitCode: bundle.status === "unverifiable" ? 3 : 0 };
}
/**
 * Parse a `policy-keys.json`-shaped trust document into trusted key entries.
 * Tolerant by shape (unknown fields ignored, malformed entries dropped) and
 * strict by type — a non-object document is a refusal, never an empty
 * trust set that would silently downgrade verification to "unattributed".
 */
export function parseTrustedKeys(doc) {
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
        throw new EvidenceMaterialError("trust document must be an object with a keys array");
    }
    const keys = doc.keys;
    if (keys !== undefined && !Array.isArray(keys)) {
        throw new EvidenceMaterialError("trust document must be an object with a keys array");
    }
    return (Array.isArray(keys) ? keys : [])
        .filter((k) => 
    // Null/array/primitive entries are dropped, never dereferenced: the
    // trust document is attacker-reachable whenever the workspace is.
    typeof k === "object" &&
        k !== null &&
        !Array.isArray(k) &&
        typeof k["keyId"] === "string" &&
        typeof k["publicKey"] === "string")
        .map((k) => ({ keyId: k.keyId, publicKey: k.publicKey }));
}
/**
 * The auditor's offline check. Pure: no I/O, no clock. Internal consistency
 * is NOT provenance — an unsigned bundle is UNATTRIBUTED (exit 4), never
 * verified.
 */
export function verifyEvidence(params) {
    const result = verifyEvidenceBundle(params.bundle, params.trustedKeys ?? []);
    return { result, exitCode: result.verified ? 0 : 4 };
}
