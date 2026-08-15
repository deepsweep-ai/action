/**
 * ADR-018 — append-only audit ledger (S4.3 v0) + chain-head anchoring.
 *
 * LEDGER: `.deepsweep/ledger.jsonl`, one JSON entry per line. Every entry
 * carries `prevHash` (the previous entry's `entryHash`; 64 zeros at
 * genesis) and `entryHash` = SHA-256 over canonicalize(entry minus
 * entryHash). Internal chain verification therefore detects any EDIT —
 * but an attacker who replaces the whole file writes a self-consistent
 * chain, which is exactly what anchoring exists to catch.
 *
 * ANCHOR: {chainHead, entryCount, anchoredAt, genesisHash} — hashes and
 * counts ONLY, no event contents (metadata-first) — signed with the
 * ADR-016 Ed25519 machinery and verified against the same TrustedKey
 * shape. Designed to be published to the cloud plane on sync, or printed
 * for manual escrow. `genesisHash` is what upgrades "something diverged"
 * into the replace-vs-fork classification: a replaced ledger has a
 * different genesis; a forked one shares the genesis but not the anchored
 * head.
 *
 * TRUST MODEL (full statement in ADR-018): an anchor proves the keyholder
 * attested that a ledger with this genesis, head, and count existed. It
 * does NOT prove wall-clock time (anchoredAt is claimed), does NOT protect
 * the un-anchored suffix beyond linkage, and canNOT detect deletion of
 * ledger AND anchor together — absence detection requires the escrow side.
 * Refusals carry hashes/counts/classes only.
 */
import { sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
import { explainInclusion, hashLeaf, inclusionProof, isDigest, merkleRoot, } from "../evidence/merkle.js";
import { keyIdFor } from "./bundle.js";
import { createPublicKey } from "node:crypto";
import { appendStoreLine, readStoreText } from "./store.js";
export const LEDGER_FILE = "ledger.jsonl";
export const GENESIS_PREV = "0".repeat(64);
export class LedgerRefusalError extends Error {
    constructor(reason) {
        super(`ledger refused: ${reason}`);
        this.name = "LedgerRefusalError";
    }
}
const refuse = (reason) => new LedgerRefusalError(reason);
function hashEntry(entry) {
    return sha256Hex(canonicalize(entry));
}
/** Parse + structurally validate the ledger file. Malformed → undefined. */
export function readLedger(workspaceRoot) {
    const text = readStoreText(workspaceRoot, LEDGER_FILE, refuse);
    if (text === undefined)
        return [];
    const entries = [];
    for (const line of text.split("\n")) {
        if (line.trim() === "")
            continue;
        try {
            const parsed = JSON.parse(line);
            if (typeof parsed !== "object" ||
                parsed === null ||
                typeof parsed["seq"] !== "number" ||
                typeof parsed["prevHash"] !== "string" ||
                typeof parsed["occurredAt"] !== "string" ||
                typeof parsed["kind"] !== "string" ||
                typeof parsed["entryHash"] !== "string" ||
                typeof parsed["payload"] !== "object" ||
                parsed["payload"] === null) {
                return undefined;
            }
            entries.push(parsed);
        }
        catch {
            return undefined;
        }
    }
    return entries;
}
/** Verify internal hash-chain integrity (detects edits, not replacement). */
export function verifyChain(entries) {
    let prev = GENESIS_PREV;
    for (const [i, e] of entries.entries()) {
        const { entryHash, ...body } = e;
        if (e.seq !== i || e.prevHash !== prev || hashEntry(body) !== entryHash)
            return false;
        prev = entryHash;
    }
    return true;
}
/** Append one entry — O(1) contained fd append (ADR-018 hot-path
 * amendment; see appendStoreLine for the documented durability trade). */
export function appendLedgerEntry(workspaceRoot, kind, payload, nowIso) {
    const existing = readLedger(workspaceRoot);
    // A malformed ledger is NEVER silently rebuilt NOR silently skipped: the
    // caller surfaces the "corrupt" sentinel loudly (ledger.corrupt finding)
    // while the corruption stays on disk for verifyAgainstAnchor. Throws are
    // reserved for store-CONTAINMENT violations (exit-3 class, ADR-008).
    if (existing === undefined)
        return "corrupt";
    const prevHash = existing.length === 0 ? GENESIS_PREV : existing[existing.length - 1].entryHash;
    const body = { seq: existing.length, prevHash, occurredAt: nowIso, kind, payload };
    const entry = { ...body, entryHash: hashEntry(body) };
    appendStoreLine(workspaceRoot, LEDGER_FILE, `${JSON.stringify(entry)}\n`, refuse);
    return entry;
}
/** Leaves of the anchored evidence tree: the RFC 6962 leaf hash of each
 * entry's entryHash bytes. The entryHash already binds the full canonical
 * entry AND its chain position (prevHash/seq are inside the hashed body),
 * so the tree inherits both without re-serializing payloads.
 *
 * TEAM-ADR-025: this tree is a SECOND instantiation of the ONE Merkle
 * module (src/evidence/merkle.ts, ADR-DS-005) — not a second implementation.
 * ADR-DS-005's export tree commits to evidence RECORDS (auditor-facing,
 * frozen by contracts/schemas/evidence-record.v1.json at v0.8.0); this one
 * commits to LEDGER ENTRIES, because an anchor is signed without knowing the
 * workspace label a record carries. Same primitives, same proof format. */
function ledgerLeaves(entries) {
    return entries.map((e) => hashLeaf(Buffer.from(e.entryHash, "hex")));
}
/** RFC 6962 tree head (hex) over the ledger's entries. */
export function ledgerTreeHead(entries) {
    return merkleRoot(ledgerLeaves(entries));
}
/** Prove one entry's inclusion in the current tree. Refuses out-of-range. */
export function proveLedgerInclusion(entries, index) {
    if (!Number.isInteger(index) || index < 0 || index >= entries.length) {
        throw refuse(`cannot prove inclusion of entry ${index} in a ledger of ${entries.length} entries`);
    }
    const leaves = ledgerLeaves(entries);
    return {
        entryHash: entries[index].entryHash,
        index,
        treeSize: entries.length,
        treeHead: merkleRoot(leaves),
        proof: inclusionProof(leaves, index),
    };
}
/** Verify a portable inclusion proof against its tree head (which a verifier
 * takes from a signed anchor, never from the proof's author). The entryHash
 * is re-leaf-hashed here, so a caller cannot substitute a node for a leaf.
 * Malformed hex fails closed with a reason, never throws. */
export function verifyLedgerInclusion(p) {
    if (!isDigest(p.entryHash) || !isDigest(p.treeHead) || !p.proof.every(isDigest)) {
        return { ok: false, why: "proof carries non-sha256-hex material — refusing (fail closed)" };
    }
    return explainInclusion(hashLeaf(Buffer.from(p.entryHash, "hex")), p.index, p.treeSize, p.proof, p.treeHead);
}
/** Export a signed anchor of the CURRENT chain head. Empty ledger refuses. */
export function exportAnchor(entries, privateKey, nowIso) {
    if (entries.length === 0)
        throw refuse("cannot anchor an empty ledger");
    if (!verifyChain(entries))
        throw refuse("cannot anchor a ledger whose own chain does not verify");
    const anchor = {
        chainHead: entries[entries.length - 1].entryHash,
        entryCount: entries.length,
        anchoredAt: nowIso,
        genesisHash: entries[0].entryHash,
        treeHead: ledgerTreeHead(entries),
    };
    const publicKey = createPublicKey(privateKey);
    return {
        anchor,
        signature: edSign(null, Buffer.from(canonicalize(anchor), "utf8"), privateKey).toString("base64"),
        keyId: keyIdFor(publicKey),
    };
}
/**
 * Verify a ledger against a signed anchor. Order of decisions matters and
 * is part of the contract:
 *  1. The ANCHOR itself must verify (pinned key, matching derived keyId,
 *     valid signature, sane shape) — an unverifiable anchor proves nothing.
 *  2. Internal chain integrity ("tampered" — the edit-detection the ledger
 *     already had).
 *  3. entryCount < anchored count → "truncated".
 *  4. genesis differs → "replaced" (wholesale substitution).
 *  5. genesis matches but the entry at the anchored position is not the
 *     anchored head → "forked" (history rewritten after genesis).
 *  6. Head matches at the anchored position: "verified" (exact) or
 *     "verified-appended" (honest growth since the anchor).
 */
export function verifyAgainstAnchor(entries, signed, trustedKeys) {
    const env = signed;
    const anchor = env?.["anchor"];
    const signature = env?.["signature"];
    const keyId = env?.["keyId"];
    if (typeof env !== "object" ||
        env === null ||
        typeof anchor !== "object" ||
        anchor === null ||
        typeof anchor.chainHead !== "string" ||
        typeof anchor.genesisHash !== "string" ||
        typeof anchor.anchoredAt !== "string" ||
        !Number.isInteger(anchor.entryCount) ||
        anchor.entryCount < 1 ||
        typeof signature !== "string" ||
        typeof keyId !== "string") {
        return { status: "untrusted-anchor", detail: "anchor envelope is malformed" };
    }
    const pinned = trustedKeys.find((k) => k.keyId === keyId);
    if (pinned === undefined) {
        return { status: "untrusted-anchor", detail: `anchor keyId ${keyId} is not pinned` };
    }
    let publicKey;
    try {
        publicKey = pinned.publicKey.includes("BEGIN PUBLIC KEY")
            ? createPublicKey(pinned.publicKey)
            : createPublicKey({ key: Buffer.from(pinned.publicKey, "base64"), format: "der", type: "spki" });
    }
    catch {
        return { status: "untrusted-anchor", detail: `pinned key ${keyId} is not a valid public key` };
    }
    if (keyIdFor(publicKey) !== keyId) {
        return { status: "untrusted-anchor", detail: `pinned key material does not derive keyId ${keyId}` };
    }
    let sigOk = false;
    try {
        sigOk = edVerify(null, Buffer.from(canonicalize(anchor), "utf8"), publicKey, Buffer.from(signature, "base64"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk) {
        return { status: "untrusted-anchor", detail: `anchor signature does not verify under ${keyId}` };
    }
    if (!verifyChain(entries)) {
        return { status: "tampered", detail: "internal hash chain does not verify — an entry was edited" };
    }
    if (entries.length < anchor.entryCount) {
        return {
            status: "truncated",
            detail: `ledger has ${entries.length} entries but the anchor attested ${anchor.entryCount}`,
        };
    }
    if (entries[0].entryHash !== anchor.genesisHash) {
        return { status: "replaced", detail: "genesis hash differs from the anchored genesis — wholesale replacement" };
    }
    if (entries[anchor.entryCount - 1].entryHash !== anchor.chainHead) {
        return {
            status: "forked",
            detail: `entry ${anchor.entryCount - 1} is not the anchored chain head — history rewritten after genesis`,
        };
    }
    if (anchor.treeHead !== undefined) {
        // TEAM-ADR-025: the anchored RFC 6962 head must reproduce over the
        // anchored prefix. Signature already binds the field; a wrong type or a
        // mismatch is treated as tampering, never ignored (fail closed).
        if (typeof anchor.treeHead !== "string") {
            return { status: "tampered", detail: "anchor treeHead is not a string — malformed anchored fact" };
        }
        if (ledgerTreeHead(entries.slice(0, anchor.entryCount)) !== anchor.treeHead) {
            return {
                status: "tampered",
                detail: "anchored RFC 6962 tree head does not reproduce over the anchored prefix",
            };
        }
    }
    if (entries.length === anchor.entryCount) {
        return { status: "verified", detail: `chain head matches the anchor at ${anchor.entryCount} entries` };
    }
    return {
        status: "verified-appended",
        appendedEntries: entries.length - anchor.entryCount,
        detail: `anchored prefix intact; ${entries.length - anchor.entryCount} honest entries appended since the anchor`,
    };
}
