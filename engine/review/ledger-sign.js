/**
 * P29 / TEAM-ADR-028 — PER-ENTRY LEDGER SIGNATURES.
 *
 * ADR-018's hash chain detects an EDIT. It cannot detect a REPLACEMENT: an
 * attacker who rewrites the whole file writes a self-consistent chain. The
 * ADR-018 answer was an escrowed anchor over the head; TEAM-ADR-025 added a
 * Merkle head; this module closes the remaining gap by making each entry
 * individually ATTRIBUTABLE at the moment it was written.
 *
 * WHAT IS SIGNED
 * --------------
 * Ed25519 over `canonicalize({schemaVersion, seq, entryHash})`. Binding `seq`
 * ALONGSIDE `entryHash` is deliberate: `entryHash` already commits to the
 * entry body and its chain position, but signing the pair lets a verifier
 * classify a REORDER distinctly from a generic chain break, which matters for
 * the tamper response (a reorder is a rewrite attempt; a chain break may be a
 * torn write).
 *
 * WHERE IT IS STORED — AND WHY NOT IN THE ENTRY
 * ---------------------------------------------
 * Signatures live in a SIDECAR, `.deepsweep/ledger-sig.jsonl`, one line per
 * entry. Putting them inside the entry would either change `entryHash` (the
 * ADR-018 chain contract, replayed byte-for-byte by the frozen evidence
 * vectors — TEAM-ADR-026) or require a hash-exclusion carve-out, and a
 * signature over a hash that excludes the signature is a construction that
 * invites exactly the "which bytes are covered?" confusion this system exists
 * to remove. The sidecar keeps `ledger.jsonl` byte-identical to the frozen
 * contract, keeps the append hot path unchanged (ADR-017 budgets), and makes
 * "the ledger grew but the signatures did not" a first-class detectable state
 * rather than an invisible one.
 *
 * WHERE THE KEY LIVES
 * -------------------
 * OUTSIDE agent-readable paths. The documented default is the OS KEYCHAIN,
 * supplied by the desktop Governance Studio, which owns keychain integration.
 * This engine has ZERO third-party runtime dependencies and node:crypto has no
 * keychain binding, so the engine does NOT reach the keychain: it defines the
 * injection seam (`LedgerSigningKey`) and the host supplies a signer.
 * `describeKeySource` renders that provenance honestly, including the
 * `unavailable` case — an unsigned ledger reports as UNSIGNED, never as
 * verified.
 *
 * DETECTION MATRIX (all four required by P29; see verifyLedger):
 *   edit      -> entryHash changes  -> chain break and/or signature mismatch
 *   forge     -> attacker rebuilds a self-consistent chain but cannot sign
 *   truncate  -> signed tree head (ADR-DS-006) attests a larger tree; and/or
 *                the sidecar outlives the entries it covers
 *   reorder   -> seq/entryHash pairing no longer holds
 *
 * Fail-closed throughout: every failure is a typed refusal, never a downgrade
 * to "probably fine".
 */
import { createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalize } from "./canonical.js";
import { keyIdFor } from "./bundle.js";
import { appendStoreLine, readStoreText } from "./store.js";
import { GENESIS_PREV, ledgerTreeHead, verifyChain } from "./ledger.js";
import { verifyTreeHead } from "../evidence/treehead.js";
export const LEDGER_SIG_FILE = "ledger-sig.jsonl";
export const LEDGER_SIG_SCHEMA_VERSION = 1;
export class LedgerSignatureRefusalError extends Error {
    constructor(reason) {
        super(`ledger signatures refused: ${reason}`);
        this.name = "LedgerSignatureRefusalError";
    }
}
const refuse = (reason) => new LedgerSignatureRefusalError(reason);
/** The bytes actually signed. Exported so a port can reproduce them exactly. */
export function signedBytesFor(seq, entryHash) {
    return Buffer.from(canonicalize({ schemaVersion: LEDGER_SIG_SCHEMA_VERSION, seq, entryHash }), "utf8");
}
/** A signer over key material the HOST already holds (never read from the
 * store). Used by the engine host and by tests; the Studio wraps its keychain
 * handle in the same shape and declares `os-keychain`. */
export function hostInjectedKey(privateKey, provider = "host-injected") {
    const publicKey = createPublicKey(privateKey);
    return {
        provider,
        keyId: keyIdFor(publicKey),
        sign: (message) => edSign(null, message, privateKey),
    };
}
/** Describe the key provenance for a report or a UI. Never leaks key material. */
export function describeKeySource(key) {
    if (key === undefined) {
        return {
            available: false,
            provider: "unavailable",
            keyId: null,
            detail: "No ledger signing key is available, so new entries are recorded UNSIGNED. The key is held outside " +
                "agent-readable paths — by default in the OS keychain, supplied by the Governance Studio — and the " +
                "engine never reads key material from the workspace store.",
        };
    }
    const where = key.provider === "os-keychain"
        ? "the OS keychain (supplied by the Governance Studio)"
        : "the host process (injected; never read from the workspace store)";
    return {
        available: true,
        provider: key.provider,
        keyId: key.keyId,
        detail: `Ledger entries are signed with key ${key.keyId}, held in ${where}.`,
    };
}
// -------------------------------------------------------------- sign / read
/** Sign one entry. Pure given the key's signer. */
export function signLedgerEntry(entry, key) {
    return {
        schemaVersion: LEDGER_SIG_SCHEMA_VERSION,
        seq: entry.seq,
        entryHash: entry.entryHash,
        keyId: key.keyId,
        signature: key.sign(signedBytesFor(entry.seq, entry.entryHash)).toString("base64"),
    };
}
/** Sign a whole ledger (backfill / re-key). Order follows the entries. */
export function signLedger(entries, key) {
    return entries.map((e) => signLedgerEntry(e, key));
}
/** Append one signature line to the sidecar (contained, O(1), same discipline
 * as the ledger append itself). */
export function appendLedgerSignature(workspaceRoot, sig) {
    appendStoreLine(workspaceRoot, LEDGER_SIG_FILE, `${JSON.stringify(sig)}\n`, refuse);
}
/** Parse the sidecar. Malformed -> undefined (never a partial, never a throw
 * outside containment violations) so the caller can refuse loudly. */
export function readLedgerSignatures(workspaceRoot) {
    const text = readStoreText(workspaceRoot, LEDGER_SIG_FILE, refuse);
    if (text === undefined)
        return [];
    const out = [];
    for (const line of text.split("\n")) {
        if (line.trim() === "")
            continue;
        let parsed;
        try {
            parsed = JSON.parse(line);
        }
        catch {
            return undefined;
        }
        if (!isSignatureShape(parsed))
            return undefined;
        out.push(parsed);
    }
    return out;
}
function isSignatureShape(v) {
    const s = v;
    return (typeof s === "object" &&
        s !== null &&
        s["schemaVersion"] === LEDGER_SIG_SCHEMA_VERSION &&
        Number.isInteger(s["seq"]) &&
        s["seq"] >= 0 &&
        typeof s["entryHash"] === "string" &&
        typeof s["keyId"] === "string" &&
        typeof s["signature"] === "string");
}
function headOf(entries) {
    return entries.length === 0 ? null : entries[entries.length - 1].entryHash;
}
/** Would this sequence of entries chain-verify if read in seq order? */
function chainsWhenSorted(entries) {
    return verifyChain([...entries].sort((a, b) => a.seq - b.seq));
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
 * THE VERIFIER. Detects edit, forge, truncate and reorder, in a fixed
 * fail-closed ladder — the order is contract, because a ledger can be several
 * kinds of wrong at once and the response must name the most serious cause it
 * can prove.
 *
 *  1. malformed sidecar          -> malformed-signature
 *  2. entries out of seq order   -> reordered   (checked BEFORE the chain, so
 *                                   a swap is not misreported as a generic edit)
 *  3. chain break                -> edited
 *  4. sidecar longer than ledger -> truncated   (the evidence outlived the
 *                                   entries it covers)
 *  5. signed tree head refused   -> head-refused
 *  6. head attests a bigger tree -> truncated
 *  7. head root does not reproduce -> edited
 *  8. no signatures at all       -> unsigned    (ok, but never "verified")
 *  9. per-entry: missing         -> signature-gap
 *                hash mismatch   -> edited
 *                unpinned key    -> untrusted-key
 *                bad signature   -> forged
 * 10. otherwise                  -> verified
 */
export function verifyLedger(input) {
    const { entries, signatures, trustedKeys } = input;
    const chainHead = headOf(entries);
    const base = { entryCount: entries.length, signedEntries: signatures?.length ?? 0, chainHead };
    if (signatures === undefined) {
        return {
            ok: false,
            status: "malformed-signature",
            ...base,
            signedEntries: 0,
            detail: `${LEDGER_SIG_FILE} is malformed — refusing to verify against unreadable evidence (fail closed)`,
        };
    }
    const outOfOrder = entries.some((e, i) => e.seq !== i);
    if (outOfOrder && chainsWhenSorted(entries)) {
        return {
            ok: false,
            status: "reordered",
            ...base,
            detail: `ledger entries are not in seq order but chain when sorted — history was reordered (${entries.length} entries)`,
        };
    }
    if (!verifyChain(entries)) {
        return {
            ok: false,
            status: "edited",
            ...base,
            detail: `hash chain does not verify over ${entries.length} entries — an entry was edited or removed`,
        };
    }
    if (signatures.length > entries.length) {
        return {
            ok: false,
            status: "truncated",
            ...base,
            detail: `${signatures.length} signatures cover only ${entries.length} entries — the ledger was truncated beneath its own evidence`,
        };
    }
    if (input.signedTreeHead !== undefined) {
        const head = verifyTreeHead(input.signedTreeHead, trustedKeys);
        if (!head.ok) {
            return {
                ok: false,
                status: "head-refused",
                ...base,
                detail: `signed tree head refused (${head.reason}) — evidence is unattributed, refusing to report verified`,
            };
        }
        if (head.treeHead.treeSize > entries.length) {
            return {
                ok: false,
                status: "truncated",
                ...base,
                detail: `signed tree head attests ${head.treeHead.treeSize} entries but only ${entries.length} remain`,
            };
        }
        if (ledgerTreeHead(entries.slice(0, head.treeHead.treeSize)) !== head.treeHead.rootHash) {
            return {
                ok: false,
                status: "edited",
                ...base,
                detail: `signed tree head root does not reproduce over the attested prefix of ${head.treeHead.treeSize} entries`,
            };
        }
    }
    if (signatures.length === 0) {
        return {
            ok: true,
            status: "unsigned",
            ...base,
            detail: entries.length === 0
                ? "ledger is empty and unsigned — nothing is attested (this is not a clean bill of health)"
                : `${entries.length} entries are chain-consistent but UNSIGNED — internal consistency is not attribution`,
        };
    }
    const bySeq = new Map();
    for (const s of signatures)
        bySeq.set(s.seq, s);
    for (const entry of entries) {
        const sig = bySeq.get(entry.seq);
        if (sig === undefined) {
            return {
                ok: false,
                status: "signature-gap",
                ...base,
                detail: `entry ${entry.seq} has no signature — ${signatures.length} of ${entries.length} entries are attested`,
            };
        }
        if (sig.entryHash !== entry.entryHash) {
            return {
                ok: false,
                status: "edited",
                ...base,
                detail: `entry ${entry.seq} does not match the hash its signature covers`,
            };
        }
        const pinned = trustedKeys.find((k) => k.keyId === sig.keyId);
        if (pinned === undefined) {
            return {
                ok: false,
                status: "untrusted-key",
                ...base,
                detail: `entry ${entry.seq} is signed by keyId ${sig.keyId}, which is not pinned`,
            };
        }
        const publicKey = parsePinned(pinned.publicKey);
        if (publicKey === undefined || keyIdFor(publicKey) !== sig.keyId) {
            return {
                ok: false,
                status: "untrusted-key",
                ...base,
                detail: `pinned material for keyId ${sig.keyId} is unusable or does not derive that id`,
            };
        }
        let sigOk = false;
        try {
            sigOk = edVerify(null, signedBytesFor(sig.seq, sig.entryHash), publicKey, Buffer.from(sig.signature, "base64"));
        }
        catch {
            sigOk = false;
        }
        if (!sigOk) {
            return {
                ok: false,
                status: "forged",
                ...base,
                detail: `entry ${entry.seq} carries a signature that does not verify under ${sig.keyId} — forged or re-chained`,
            };
        }
    }
    return {
        ok: true,
        status: "verified",
        ...base,
        detail: `${entries.length} entries chain from ${GENESIS_PREV.slice(0, 8)}… and every one is individually signed and verified`,
    };
}
