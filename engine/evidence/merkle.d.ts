/** A digest as lowercase hex (the engine's canonical hash representation). */
export type Hex = string;
/** The empty-tree root: SHA-256 over zero bytes (RFC 6962 §2.1). */
export declare const EMPTY_TREE_ROOT: Hex;
/** 32 zero bytes as hex — the genesis `prev_hash` for hash-chained logs. */
export declare const GENESIS_PREV_HASH: Hex;
/** Is this a well-formed 32-byte lowercase-hex digest? */
export declare function isDigest(value: unknown): value is Hex;
/** RFC 6962 leaf hash: SHA-256(0x00 || leafData). */
export declare function hashLeaf(leafData: Buffer | string): Hex;
/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export declare function hashChildren(left: Hex, right: Hex): Hex;
/**
 * Merkle Tree Hash over already-hashed leaves (RFC 6962 MTH).
 * Callers pass leaf HASHES (from hashLeaf) so the tree never sees raw
 * record bytes — keeping the log metadata-first by construction.
 */
export declare function merkleRoot(leaves: readonly Hex[]): Hex;
/**
 * Inclusion proof (RFC 6962 PATH(m, D[n])): the audit path proving leaf m
 * belongs to the tree of size n. Returns [] for the single-leaf tree.
 * Throws only on programmer error (index out of range) — verification
 * failures are FALSE, never exceptions.
 */
export declare function inclusionProof(leaves: readonly Hex[], index: number): Hex[];
/**
 * Consistency proof (RFC 6962 PROOF(m, D[n])): proves the tree of size n
 * is an append-only extension of the tree of size m (nothing rewritten,
 * nothing removed). Throws only on programmer error.
 */
export declare function consistencyProof(leaves: readonly Hex[], m: number): Hex[];
/**
 * Recompute the root implied by an inclusion proof, WITHOUT the tree —
 * the operation a third party performs with only (leafHash, index, size,
 * proof). Returns undefined when the proof is structurally impossible.
 */
export declare function rootFromInclusionProof(leafHash: Hex, index: number, treeSize: number, proof: readonly Hex[]): Hex | undefined;
/**
 * A verification outcome with its reason (invariant 6). `ok` is the same
 * value the boolean verifiers return — the explanation never changes the
 * verdict, it only records why.
 */
export interface ProofVerdict {
    readonly ok: boolean;
    readonly why: string;
}
/** Explained inclusion verification (the boolean verifier's own path). */
export declare function explainInclusion(leafHash: Hex, index: number, treeSize: number, proof: readonly Hex[], root: Hex): ProofVerdict;
/** Fail-closed inclusion verification against a known root. */
export declare function verifyInclusion(leafHash: Hex, index: number, treeSize: number, proof: readonly Hex[], root: Hex): boolean;
/**
 * Fail-closed consistency verification (RFC 6962 §2.1.2): proves `second`
 * is an append-only extension of `first`. Rejects size inversion, empty
 * proofs where one is required, over-long proofs, and any digest mismatch
 * — a FORK (history rewritten) fails here, which is the whole point.
 */
export declare function verifyConsistency(firstSize: number, secondSize: number, firstRoot: Hex, secondRoot: Hex, proof: readonly Hex[]): boolean;
/** Explained consistency verification (the boolean verifier's own path). */
export declare function explainConsistency(firstSize: number, secondSize: number, firstRoot: Hex, secondRoot: Hex, proof: readonly Hex[]): ProofVerdict;
