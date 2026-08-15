/**
 * ADR-DS-006 — signed tree heads (STH): the binding that makes evidence
 * ATTRIBUTABLE, closing the gap ADR-DS-005 documented in its own limits
 * section.
 *
 * ADR-DS-005 ships proofs that are internally consistent — an auditor can
 * confirm "leaf k is under root R" and "R2 extends R1". What they could
 * NOT confirm is that R is *your* log: an unsigned root is just 32 bytes,
 * and anyone can mint a self-consistent tree. RFC 6962 solves this with a
 * Signed Tree Head binding (tree_size, root_hash, timestamp) under the
 * log's key — which is also precisely the `(size, root)` binding the
 * inclusion verifier cannot do alone (ADR-DS-005 "documented RFC limit").
 *
 * Reuses the ADR-016 Ed25519 machinery and the same pinned-key trust set
 * (`.deepsweep/policy-keys.json`), so operators have one key story, not
 * two. Zero new dependencies (node:crypto is a platform builtin).
 *
 * Fail-closed (invariant 2): every verification failure — bad signature,
 * unknown or laundered key id, malformed envelope, size/root shape errors
 * — returns a typed refusal. A refused head NEVER downgrades to "probably
 * fine"; the caller treats the evidence as unattributed.
 */
import { type KeyObject } from "node:crypto";
import { type TrustedKey } from "../review/bundle.js";
import { type Hex } from "./merkle.js";
export declare const TREE_HEAD_SCHEMA_VERSION = 1;
/** The signed facts: size + root + when + which log. Hashes and counts only. */
export interface TreeHead {
    readonly schemaVersion: typeof TREE_HEAD_SCHEMA_VERSION;
    readonly treeSize: number;
    readonly rootHash: Hex;
    /** Operator-supplied ISO timestamp (CLAIMED — no trusted clock exists). */
    readonly signedAt: string;
    /** Log identity = the signing key's id, so heads from two logs never mix. */
    readonly logId: string;
}
export interface SignedTreeHead {
    readonly treeHead: TreeHead;
    /** Ed25519 over canonicalize(treeHead), base64. */
    readonly signature: string;
    readonly keyId: string;
}
export type TreeHeadRefusal = "malformed-envelope" | "unknown-key" | "malformed-key" | "key-id-mismatch" | "log-id-mismatch" | "bad-signature";
export type TreeHeadVerdict = {
    readonly ok: true;
    readonly treeHead: TreeHead;
    readonly keyId: string;
} | {
    readonly ok: false;
    readonly reason: TreeHeadRefusal;
    readonly detail: string;
};
/** Sign a tree head. The private key never leaves this call. */
export declare function signTreeHead(treeSize: number, rootHash: Hex, signedAt: string, privateKey: KeyObject): SignedTreeHead;
/**
 * Verify a signed tree head against the pinned trust set. Total over
 * arbitrary runtime input; every failure is typed.
 */
export declare function verifyTreeHead(signed: unknown, trustedKeys: readonly TrustedKey[]): TreeHeadVerdict;
