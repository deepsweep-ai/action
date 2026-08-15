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
import { createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalize } from "../review/canonical.js";
import { keyIdFor } from "../review/bundle.js";
import { isDigest } from "./merkle.js";
export const TREE_HEAD_SCHEMA_VERSION = 1;
/** Sign a tree head. The private key never leaves this call. */
export function signTreeHead(treeSize, rootHash, signedAt, privateKey) {
    const publicKey = createPublicKey(privateKey);
    const keyId = keyIdFor(publicKey);
    const treeHead = {
        schemaVersion: TREE_HEAD_SCHEMA_VERSION,
        treeSize,
        rootHash,
        signedAt,
        logId: keyId,
    };
    return {
        treeHead,
        signature: edSign(null, Buffer.from(canonicalize(treeHead), "utf8"), privateKey).toString("base64"),
        keyId,
    };
}
function parsePinned(material) {
    try {
        return material.includes("BEGIN PUBLIC KEY")
            ? createPublicKey(material)
            : createPublicKey({ key: Buffer.from(material, "base64"), format: "der", type: "spki" });
    }
    catch {
        return undefined;
    }
}
/**
 * Verify a signed tree head against the pinned trust set. Total over
 * arbitrary runtime input; every failure is typed.
 */
export function verifyTreeHead(signed, trustedKeys) {
    const env = signed;
    if (typeof env !== "object" || env === null || Array.isArray(env)) {
        return { ok: false, reason: "malformed-envelope", detail: "signed tree head is not an object" };
    }
    const head = env["treeHead"];
    const signature = env["signature"];
    const keyId = env["keyId"];
    if (typeof head !== "object" ||
        head === null ||
        head.schemaVersion !== TREE_HEAD_SCHEMA_VERSION ||
        !Number.isInteger(head.treeSize) ||
        head.treeSize < 0 ||
        !isDigest(head.rootHash) ||
        typeof head.signedAt !== "string" ||
        typeof head.logId !== "string" ||
        typeof signature !== "string" ||
        typeof keyId !== "string") {
        return {
            ok: false,
            reason: "malformed-envelope",
            detail: "envelope must be { treeHead:{schemaVersion,treeSize,rootHash,signedAt,logId}, signature, keyId }",
        };
    }
    const pinned = trustedKeys.find((k) => k.keyId === keyId);
    if (pinned === undefined) {
        return { ok: false, reason: "unknown-key", detail: `tree-head keyId ${keyId} is not pinned` };
    }
    const publicKey = parsePinned(pinned.publicKey);
    if (publicKey === undefined) {
        return { ok: false, reason: "malformed-key", detail: `pinned key ${keyId} is not a valid public key` };
    }
    if (keyIdFor(publicKey) !== keyId) {
        return { ok: false, reason: "key-id-mismatch", detail: `pinned key material does not derive keyId ${keyId}` };
    }
    // The head names its own log; a head signed by key A claiming to be log B
    // is a mixing attempt, refused before the signature even matters.
    if (head.logId !== keyId) {
        return { ok: false, reason: "log-id-mismatch", detail: `treeHead.logId does not match the signing keyId ${keyId}` };
    }
    let sigOk = false;
    try {
        sigOk = edVerify(null, Buffer.from(canonicalize(head), "utf8"), publicKey, Buffer.from(signature, "base64"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk) {
        return { ok: false, reason: "bad-signature", detail: `tree head does not verify under ${keyId}` };
    }
    return { ok: true, treeHead: head, keyId };
}
