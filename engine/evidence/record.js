/**
 * ADR-DS-005 — canonical evidence records (schema
 * contracts/schemas/evidence-record.v1.json).
 *
 * An evidence record is the auditable projection of one governed decision:
 * WHO / WHAT / WHY / POLICY / OUTCOME (invariant 6) expressed entirely as
 * hashes, enumerated codes, counts, and operator-authored rule names
 * (invariant 1). It carries NO principal string, NO resource path, NO file
 * content, NO secret — the tuple travels as SHA-256 digests, so an auditor
 * can prove "this exact decision happened" by re-hashing their own copy of
 * the tuple, while the record itself discloses nothing.
 *
 * Canonicalization is RFC 8785 (JCS) via the engine's existing
 * `canonicalize` — the ADR-003 hashing contract already specifies JCS
 * semantics (UTF-16 code-unit key order, ECMAScript number form, minimal
 * escaping); this module reuses it rather than minting a second
 * canonicalizer, and tests/evidence-record.test.ts pins the JCS behaviors
 * that matter (key order, number forms, nesting, byte preservation).
 *
 * Pure and deterministic: nowIso is injected, output is byte-stable.
 */
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { hashLeaf } from "./merkle.js";
export const EVIDENCE_SCHEMA_VERSION = 1;
/** Build the record — the ONLY place raw tuple values are touched. */
export function buildEvidenceRecord(input) {
    return {
        schemaVersion: EVIDENCE_SCHEMA_VERSION,
        occurredAt: input.occurredAt,
        workspace: input.workspace,
        outcome: input.outcome,
        reason: input.reason,
        principalHash: sha256Hex(input.principal ?? ""),
        actionHash: sha256Hex(input.action),
        resourceHash: sha256Hex(input.resource),
        ruleName: input.ruleName,
        policyMode: input.policyMode,
        policyLayers: [...input.policyLayers].sort(),
        matchedRuleCount: input.matchedRuleCount,
    };
}
/** RFC 8785 canonical serialization of a record (the bytes that get hashed). */
export function serializeEvidenceRecord(record) {
    return canonicalize(record);
}
/** The record's Merkle leaf hash: RFC 6962 leaf hashing over JCS bytes. */
export function evidenceLeafHash(record) {
    return hashLeaf(serializeEvidenceRecord(record));
}
