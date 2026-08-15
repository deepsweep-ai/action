/**
 * ADR-016 — policy-bundle signing and verification (Ed25519, node:crypto
 * only — zero third-party packages, per the runtime-dependency invariant).
 *
 * A SEALED bundle is the distribution envelope for policy:
 *   { bundle: { schemaVersion, bundleVersion, policy }, signature, keyId }
 * The signature is Ed25519 over the CANONICAL bytes of `bundle`
 * (canonicalize() — the same total, sorted, deterministic serialization the
 * pin/identity hashing already uses), so byte-stability is inherited and
 * re-serialization cannot break verification.
 *
 * FAIL-CLOSED CONTRACT: verifyBundle returns ok:false on ANY failure — bad
 * signature, unknown keyId, malformed envelope, malformed key, downgraded
 * (replayed) bundleVersion — and callers must land in the same posture as
 * an invalid policy: zero rules contributed, whole-set refusal surfaced
 * loudly, advisory default-observe, acted-on require-approval/deny
 * (ADR-009/ADR-010). Refusal reasons carry SHAPE ONLY: key ids, version
 * numbers, and failure classes — never key material or bundle content.
 *
 * Replay protection: `bundleVersion` is a strictly-monotonic integer. A
 * verifier refuses any bundle whose version is <= the floor it is given
 * (the caller persists the high-water mark of the last ACCEPTED bundle and
 * may additionally pin a minimum in the trusted-keys config — the config
 * floor holds even if the agent-writable high-water store is destroyed).
 *
 * Sync API choice: the KeyObject sign/verify API (crypto.sign(null, …)) is
 * used rather than webcrypto.subtle — same Ed25519 curve, but synchronous
 * (the engine is synchronous throughout) and stable since Node 12, while
 * subtle's Ed25519 was still stabilizing across Node 18–20. Both live in
 * node:crypto; nothing third-party.
 */
import { createPublicKey, sign as edSign, verify as edVerify, } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
export const BUNDLE_SCHEMA_VERSION = 1;
/** Derive the pinnable key id from a public key. */
export function keyIdFor(publicKey) {
    const spki = publicKey.export({ type: "spki", format: "der" });
    return `dsk_${sha256Hex(spki.toString("base64")).slice(0, 16)}`;
}
/** Canonical signing bytes — the ONE serialization both sides use. */
function signingBytes(bundle) {
    return Buffer.from(canonicalize(bundle), "utf8");
}
/** Seal a bundle: sign its canonical bytes, attach signature + keyId. */
export function sealBundle(bundle, privateKey) {
    // createPublicKey accepts a private KeyObject at runtime (documented);
    // @types/node's overloads lag — the cast asserts the documented contract.
    const publicKey = createPublicKey(privateKey);
    return {
        bundle,
        signature: edSign(null, signingBytes(bundle), privateKey).toString("base64"),
        keyId: keyIdFor(publicKey),
    };
}
function parsePinnedKey(pem) {
    try {
        if (pem.includes("BEGIN PUBLIC KEY"))
            return createPublicKey(pem);
        // base64 SPKI DER form.
        return createPublicKey({ key: Buffer.from(pem, "base64"), format: "der", type: "spki" });
    }
    catch {
        return undefined;
    }
}
function isPolicyBundle(v) {
    if (typeof v !== "object" || v === null || Array.isArray(v))
        return false;
    const r = v;
    return (r["schemaVersion"] === BUNDLE_SCHEMA_VERSION &&
        typeof r["bundleVersion"] === "number" &&
        Number.isInteger(r["bundleVersion"]) &&
        r["bundleVersion"] >= 1 &&
        "policy" in r);
}
/**
 * Verify a sealed bundle against the pinned trust set and the replay floor.
 * Total over arbitrary runtime input; EVERY failure is a typed refusal.
 * `floor` is the highest bundleVersion already accepted (0 = none yet):
 * a verified bundle must be STRICTLY newer.
 */
export function verifyBundle(sealed, trustedKeys, floor) {
    if (typeof sealed !== "object" || sealed === null || Array.isArray(sealed)) {
        return { ok: false, reason: "malformed-envelope", detail: "sealed bundle is not an object" };
    }
    const env = sealed;
    const bundle = env["bundle"];
    const signature = env["signature"];
    const keyId = env["keyId"];
    if (!isPolicyBundle(bundle) || typeof signature !== "string" || typeof keyId !== "string") {
        return {
            ok: false,
            reason: "malformed-envelope",
            detail: "envelope must be { bundle, signature, keyId } with an integer bundleVersion >= 1",
        };
    }
    const pinned = trustedKeys.find((k) => k.keyId === keyId);
    if (pinned === undefined) {
        return { ok: false, reason: "unknown-key", detail: `keyId ${keyId} is not pinned` };
    }
    const publicKey = parsePinnedKey(pinned.publicKey);
    if (publicKey === undefined) {
        return { ok: false, reason: "malformed-key", detail: `pinned key ${keyId} is not a valid Ed25519 public key` };
    }
    // The pinned entry's DERIVED id must match its claimed id — a config that
    // labels key B with key A's id must not launder trust between them.
    if (keyIdFor(publicKey) !== keyId) {
        return { ok: false, reason: "key-id-mismatch", detail: `pinned key material does not derive keyId ${keyId}` };
    }
    let sigOk = false;
    try {
        sigOk = edVerify(null, signingBytes(bundle), publicKey, Buffer.from(signature, "base64"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk) {
        return { ok: false, reason: "bad-signature", detail: `signature does not verify under ${keyId}` };
    }
    if (bundle.bundleVersion <= floor) {
        return {
            ok: false,
            reason: "replayed-version",
            detail: `bundleVersion ${bundle.bundleVersion} is not newer than the accepted floor ${floor}`,
        };
    }
    return { ok: true, bundle, keyId };
}
