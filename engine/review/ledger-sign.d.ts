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
import { type KeyObject } from "node:crypto";
import { type TrustedKey } from "./bundle.js";
import { type LedgerEntry } from "./ledger.js";
import { type SignedTreeHead } from "../evidence/treehead.js";
export declare const LEDGER_SIG_FILE = "ledger-sig.jsonl";
export declare const LEDGER_SIG_SCHEMA_VERSION = 1;
export declare class LedgerSignatureRefusalError extends Error {
    constructor(reason: string);
}
/** One per-entry signature record (the sidecar line). */
export interface LedgerEntrySignature {
    readonly schemaVersion: typeof LEDGER_SIG_SCHEMA_VERSION;
    readonly seq: number;
    readonly entryHash: string;
    readonly keyId: string;
    /** Ed25519 over canonicalize({schemaVersion, seq, entryHash}), base64. */
    readonly signature: string;
}
/** The bytes actually signed. Exported so a port can reproduce them exactly. */
export declare function signedBytesFor(seq: number, entryHash: string): Buffer;
/**
 * Where the signing key came from.
 *  - `os-keychain`   — the host resolved it from the OS keychain (Studio).
 *  - `host-injected` — the host supplied key material directly (tests, CI,
 *                      an HSM-backed signer, the headless engine host).
 *  - `unavailable`   — no key. The ledger is UNSIGNED and says so.
 */
export type LedgerKeyProvider = "os-keychain" | "host-injected" | "unavailable";
/** The injection seam. The engine never constructs one from a filesystem path
 * inside `.deepsweep/` — that would put the key where the agent already is. */
export interface LedgerSigningKey {
    readonly provider: LedgerKeyProvider;
    readonly keyId: string;
    readonly sign: (message: Buffer) => Buffer;
}
/** A signer over key material the HOST already holds (never read from the
 * store). Used by the engine host and by tests; the Studio wraps its keychain
 * handle in the same shape and declares `os-keychain`. */
export declare function hostInjectedKey(privateKey: KeyObject, provider?: LedgerKeyProvider): LedgerSigningKey;
export interface KeySourceReport {
    readonly available: boolean;
    readonly provider: LedgerKeyProvider;
    readonly keyId: string | null;
    /** Renderable, honest sentence — the Studio shows this verbatim. */
    readonly detail: string;
}
/** Describe the key provenance for a report or a UI. Never leaks key material. */
export declare function describeKeySource(key: LedgerSigningKey | undefined): KeySourceReport;
/** Sign one entry. Pure given the key's signer. */
export declare function signLedgerEntry(entry: LedgerEntry, key: LedgerSigningKey): LedgerEntrySignature;
/** Sign a whole ledger (backfill / re-key). Order follows the entries. */
export declare function signLedger(entries: readonly LedgerEntry[], key: LedgerSigningKey): LedgerEntrySignature[];
/** Append one signature line to the sidecar (contained, O(1), same discipline
 * as the ledger append itself). */
export declare function appendLedgerSignature(workspaceRoot: string, sig: LedgerEntrySignature): void;
/** Parse the sidecar. Malformed -> undefined (never a partial, never a throw
 * outside containment violations) so the caller can refuse loudly. */
export declare function readLedgerSignatures(workspaceRoot: string): LedgerEntrySignature[] | undefined;
export type LedgerTamperClass = "edited" | "forged" | "truncated" | "reordered" | "untrusted-key" | "head-refused" | "signature-gap" | "malformed-signature";
/**
 * `verified` and `unsigned` are both `ok`, and they are NOT the same claim.
 * `unsigned` means "nothing here contradicts the record, and nothing here
 * attests to it either" — the honest posture when no key was ever available.
 */
export type LedgerVerdict = {
    readonly ok: true;
    readonly status: "verified" | "unsigned";
    readonly entryCount: number;
    readonly signedEntries: number;
    readonly chainHead: string | null;
    readonly detail: string;
} | {
    readonly ok: false;
    readonly status: LedgerTamperClass;
    readonly entryCount: number;
    readonly signedEntries: number;
    readonly chainHead: string | null;
    readonly detail: string;
};
export interface VerifyLedgerInput {
    readonly entries: readonly LedgerEntry[];
    readonly signatures: readonly LedgerEntrySignature[] | undefined;
    /** The escrowed signed tree head (ADR-DS-006), when one exists. */
    readonly signedTreeHead?: SignedTreeHead | unknown;
    readonly trustedKeys: readonly TrustedKey[];
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
export declare function verifyLedger(input: VerifyLedgerInput): LedgerVerdict;
