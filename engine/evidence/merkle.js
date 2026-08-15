/**
 * ADR-DS-005 — RFC 6962 (Certificate Transparency) Merkle log.
 *
 * Implemented from the published specification (RFC 6962 §2.1) — the
 * referenced `crates/ds-evidence/src/merkle.ts` was not present on this
 * machine (see the ADR's premise note), so this is a from-spec
 * implementation, cross-checked against the CT known-answer vectors and
 * property-tested rather than a port.
 *
 * Domain separation (the property that makes second-preimage attacks on
 * the tree structurally impossible):
 *   MTH({})        = SHA-256("")
 *   MTH({d0})      = SHA-256(0x00 || d0)                    (leaf hash)
 *   MTH(D[n])      = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
 *                    where k is the largest power of two < n
 *
 * Hashing goes through the engine's existing `sha256Hex` (node:crypto — a
 * PLATFORM BUILTIN, not a third-party dependency, so invariant 3 holds;
 * see the ADR for why hand-rolling SHA-256 would be strictly worse).
 * Everything here is pure and deterministic: no clock, no randomness, no
 * I/O, byte-stable output for byte-identical input.
 *
 * Fail-closed posture (invariant 2): every verifier returns FALSE on any
 * malformed input — wrong proof length, out-of-range index, non-hex or
 * wrong-width digests, size inversions. A verifier NEVER throws to signal
 * "unverified", and never treats an unparsable proof as a pass.
 *
 * Explainability (invariant 6, TEAM-ADR-025): each verifier has an
 * `explain*` twin returning a `ProofVerdict` — the same single code path,
 * plus the reason a proof was accepted or refused, so an operator-facing
 * surface never has to invent one from a bare boolean. The booleans are the
 * released ADR-DS-005 API and stay exactly as they were; the explained
 * twins are additive.
 *
 * ONE Merkle implementation lives in this repo (TEAM-ADR-025 reconciliation):
 * anything needing RFC 6962 — evidence export, the ledger's anchored tree
 * head, future transparency anchoring — imports THIS module.
 */
import { createHash } from "node:crypto";
const HEX32 = /^[0-9a-f]{64}$/;
/** The empty-tree root: SHA-256 over zero bytes (RFC 6962 §2.1). */
export const EMPTY_TREE_ROOT = createHash("sha256").digest("hex");
/** 32 zero bytes as hex — the genesis `prev_hash` for hash-chained logs. */
export const GENESIS_PREV_HASH = "0".repeat(64);
function sha256OfBytes(...parts) {
    const h = createHash("sha256");
    for (const p of parts)
        h.update(p);
    return h.digest("hex");
}
function hexToBuf(hex) {
    return Buffer.from(hex, "hex");
}
/** Is this a well-formed 32-byte lowercase-hex digest? */
export function isDigest(value) {
    return typeof value === "string" && HEX32.test(value);
}
/** RFC 6962 leaf hash: SHA-256(0x00 || leafData). */
export function hashLeaf(leafData) {
    const data = typeof leafData === "string" ? Buffer.from(leafData, "utf8") : leafData;
    return sha256OfBytes(Buffer.from([0x00]), data);
}
/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export function hashChildren(left, right) {
    return sha256OfBytes(Buffer.from([0x01]), hexToBuf(left), hexToBuf(right));
}
/** Largest power of two strictly less than n (n > 1). */
function splitPoint(n) {
    let k = 1;
    while (k * 2 < n)
        k *= 2;
    return k;
}
/**
 * Merkle Tree Hash over already-hashed leaves (RFC 6962 MTH).
 * Callers pass leaf HASHES (from hashLeaf) so the tree never sees raw
 * record bytes — keeping the log metadata-first by construction.
 */
export function merkleRoot(leaves) {
    if (leaves.length === 0)
        return EMPTY_TREE_ROOT;
    if (leaves.length === 1)
        return leaves[0];
    const k = splitPoint(leaves.length);
    return hashChildren(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}
/**
 * Inclusion proof (RFC 6962 PATH(m, D[n])): the audit path proving leaf m
 * belongs to the tree of size n. Returns [] for the single-leaf tree.
 * Throws only on programmer error (index out of range) — verification
 * failures are FALSE, never exceptions.
 */
export function inclusionProof(leaves, index) {
    if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
        throw new RangeError(`inclusion index ${index} outside tree of size ${leaves.length}`);
    }
    if (leaves.length === 1)
        return [];
    const k = splitPoint(leaves.length);
    if (index < k) {
        return [...inclusionProof(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))];
    }
    return [...inclusionProof(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))];
}
/**
 * Consistency proof (RFC 6962 PROOF(m, D[n])): proves the tree of size n
 * is an append-only extension of the tree of size m (nothing rewritten,
 * nothing removed). Throws only on programmer error.
 */
export function consistencyProof(leaves, m) {
    const n = leaves.length;
    if (!Number.isInteger(m) || m < 0 || m > n) {
        throw new RangeError(`consistency size ${m} outside tree of size ${n}`);
    }
    if (m === 0 || m === n)
        return [];
    return subProof(leaves, m, true);
}
function subProof(leaves, m, isCompleteSubtree) {
    const n = leaves.length;
    if (m === n)
        return isCompleteSubtree ? [] : [merkleRoot(leaves)];
    const k = splitPoint(n);
    if (m <= k) {
        return [...subProof(leaves.slice(0, k), m, isCompleteSubtree), merkleRoot(leaves.slice(k))];
    }
    return [...subProof(leaves.slice(k), m - k, false), merkleRoot(leaves.slice(0, k))];
}
// ------------------------------------------------------- verification
function bitLength(x) {
    let n = 0;
    let v = x;
    while (v > 0) {
        v >>>= 1;
        n++;
    }
    return n;
}
function onesCount(x) {
    let n = 0;
    let v = x;
    while (v > 0) {
        n += v & 1;
        v >>>= 1;
    }
    return n;
}
/**
 * Recompute the root implied by an inclusion proof, WITHOUT the tree —
 * the operation a third party performs with only (leafHash, index, size,
 * proof). Returns undefined when the proof is structurally impossible.
 */
export function rootFromInclusionProof(leafHash, index, treeSize, proof) {
    if (!isDigest(leafHash) || !proof.every(isDigest))
        return undefined;
    if (!Number.isInteger(index) || !Number.isInteger(treeSize))
        return undefined;
    if (index < 0 || treeSize <= 0 || index >= treeSize)
        return undefined;
    const inner = bitLength(index ^ (treeSize - 1));
    const border = onesCount(index >>> inner);
    if (proof.length !== inner + border)
        return undefined;
    let res = leafHash;
    for (let i = 0; i < inner; i++) {
        res = ((index >>> i) & 1) === 0 ? hashChildren(res, proof[i]) : hashChildren(proof[i], res);
    }
    for (let i = inner; i < proof.length; i++)
        res = hashChildren(proof[i], res);
    return res;
}
/** Explained inclusion verification (the boolean verifier's own path). */
export function explainInclusion(leafHash, index, treeSize, proof, root) {
    if (!isDigest(root)) {
        return { ok: false, why: "expected root is not a sha256 hex digest — refusing (fail closed)" };
    }
    const computed = rootFromInclusionProof(leafHash, index, treeSize, proof);
    if (computed === undefined) {
        return {
            ok: false,
            why: !isDigest(leafHash) || !proof.every(isDigest)
                ? "leaf or proof element is not a sha256 hex digest — refusing (fail closed)"
                : !Number.isInteger(treeSize) || treeSize <= 0
                    ? `tree size ${treeSize} is not a positive integer — refusing (fail closed)`
                    : !Number.isInteger(index) || index < 0 || index >= treeSize
                        ? `leaf index ${index} is outside a tree of ${treeSize} leaves — refusing`
                        : "proof length does not match the leaf's audit path — malformed proof refused",
        };
    }
    return computed === root
        ? { ok: true, why: `leaf ${index} of ${treeSize} reproduces the root through its audit path` }
        : {
            ok: false,
            why: "recomputed root differs from the expected root — leaf or proof is not from this tree",
        };
}
/** Fail-closed inclusion verification against a known root. */
export function verifyInclusion(leafHash, index, treeSize, proof, root) {
    return explainInclusion(leafHash, index, treeSize, proof, root).ok;
}
/**
 * Fail-closed consistency verification (RFC 6962 §2.1.2): proves `second`
 * is an append-only extension of `first`. Rejects size inversion, empty
 * proofs where one is required, over-long proofs, and any digest mismatch
 * — a FORK (history rewritten) fails here, which is the whole point.
 */
export function verifyConsistency(firstSize, secondSize, firstRoot, secondRoot, proof) {
    return explainConsistency(firstSize, secondSize, firstRoot, secondRoot, proof).ok;
}
/** Explained consistency verification (the boolean verifier's own path). */
export function explainConsistency(firstSize, secondSize, firstRoot, secondRoot, proof) {
    const no = (why) => ({ ok: false, why });
    if (!isDigest(firstRoot) || !isDigest(secondRoot) || !proof.every(isDigest)) {
        return no("root or proof element is not a sha256 hex digest — refusing (fail closed)");
    }
    if (!Number.isInteger(firstSize) || !Number.isInteger(secondSize)) {
        return no("tree sizes must be integers — refusing (fail closed)");
    }
    if (firstSize < 0 || secondSize < 0) {
        return no("tree sizes must be non-negative — refusing (fail closed)");
    }
    if (firstSize > secondSize) {
        return no(`first size ${firstSize} exceeds second size ${secondSize} — a shrunken log is truncation, never consistency`);
    }
    if (firstSize === secondSize) {
        if (proof.length !== 0)
            return no("equal sizes admit no proof elements — malformed proof refused");
        return firstRoot === secondRoot
            ? { ok: true, why: `log unchanged at ${secondSize} entries — roots match` }
            : no("equal sizes with different roots — the log was rewritten, not extended");
    }
    if (firstSize === 0) {
        return proof.length === 0
            ? { ok: true, why: "first log is empty — every log is an append-only extension of the empty log" }
            : no("the empty first log admits no proof elements — malformed proof refused");
    }
    if (proof.length === 0)
        return no("a growing log requires a proof — empty proof refused");
    let node = firstSize - 1;
    let lastNode = secondSize - 1;
    while (node % 2 === 1) {
        node = Math.floor(node / 2);
        lastNode = Math.floor(lastNode / 2);
    }
    let idx = 0;
    let hash1;
    let hash2;
    if (node > 0) {
        hash1 = proof[idx];
        hash2 = proof[idx];
        idx++;
    }
    else {
        hash1 = firstRoot;
        hash2 = firstRoot;
    }
    const short = "proof ends before the audit path does — truncated proof refused";
    while (node > 0) {
        if (node % 2 === 1) {
            if (idx >= proof.length)
                return no(short);
            hash1 = hashChildren(proof[idx], hash1);
            hash2 = hashChildren(proof[idx], hash2);
            idx++;
        }
        else if (node < lastNode) {
            if (idx >= proof.length)
                return no(short);
            hash2 = hashChildren(hash2, proof[idx]);
            idx++;
        }
        node = Math.floor(node / 2);
        lastNode = Math.floor(lastNode / 2);
    }
    if (hash1 !== firstRoot) {
        return no("proof does not reproduce the first root — the claimed history is not a prefix");
    }
    while (lastNode > 0) {
        if (idx >= proof.length)
            return no(short);
        hash2 = hashChildren(hash2, proof[idx]);
        idx++;
        lastNode = Math.floor(lastNode / 2);
    }
    if (hash2 !== secondRoot) {
        return no("proof reproduces the first root but not the second — the appended region is misrepresented");
    }
    return idx === proof.length
        ? { ok: true, why: `log grew ${firstSize} \u2192 ${secondSize} append-only; both roots reproduce` }
        : no("proof carries unused elements — malformed proof refused");
}
