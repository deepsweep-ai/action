/**
 * Shared contained-store primitives for durable metadata files under
 * `.deepsweep/` (ADR-003 containment invariants, extracted verbatim from the
 * baseline write path so the identity store — ADR-005 — reuses the same
 * audited code instead of duplicating it):
 *  - refuse if `.deepsweep/` or the store file is a symlink or its realpath
 *    escapes the workspace root; regular-file / directory checks;
 *  - reads enforce the MAX_FILE_BYTES cap;
 *  - atomic write via O_CREAT|O_EXCL mode-0600 temp file inside `.deepsweep/`
 *    (same filesystem → atomic rename).
 *
 * Callers own their refusal-error type (the CLI maps containment refusals to
 * exit 3) and their file schema; this module owns only containment + bytes.
 * Extraction note (S2.1): behavior for the baseline is byte-identical to the
 * pre-extraction implementation in baseline.ts — its tests prove it.
 */
import { constants, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeSync, } from "node:fs";
import { randomBytes } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { MAX_FILE_BYTES } from "./read.js";
import { sha256Hex } from "./canonical.js";
/** The single durable-state directory (ADR-003). */
export const STORE_DIR = ".deepsweep";
/**
 * Containment checks per ADR-003; throws the caller's refusal error on
 * violation. `refuse` receives the reason and returns the error to throw.
 */
export function checkedStorePaths(workspaceRoot, fileName, refuse) {
    const root = resolve(workspaceRoot);
    const dir = join(root, STORE_DIR);
    const file = join(dir, fileName);
    const realRoot = realpathSync(root);
    for (const [label, p] of [
        [STORE_DIR, dir],
        [`${STORE_DIR}/${fileName}`, file],
    ]) {
        let st;
        try {
            st = lstatSync(p);
        }
        catch {
            continue; // absent is fine
        }
        if (st.isSymbolicLink())
            throw refuse(`${label} is a symlink`);
        const real = realpathSync(p);
        if (real !== realRoot && !real.startsWith(realRoot + sep)) {
            throw refuse(`${label} resolves outside the workspace root`);
        }
        if (p === file && !st.isFile()) {
            throw refuse(`${label} is not a regular file`);
        }
        if (p === dir && !st.isDirectory()) {
            throw refuse(`${label} is not a directory`);
        }
    }
    return { root, dir, file };
}
/**
 * Contained read of a store file's text. Returns undefined when absent, not a
 * regular file, over the size cap, or unreadable; throws the caller's refusal
 * error only for containment violations.
 */
export function readStoreText(workspaceRoot, fileName, refuse) {
    const { file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    let st;
    try {
        st = lstatSync(file);
    }
    catch {
        return undefined;
    }
    if (!st.isFile() || st.size > MAX_FILE_BYTES)
        return undefined;
    try {
        return readFileSync(file, "utf8");
    }
    catch {
        return undefined;
    }
}
/**
 * Atomic, contained store write. Returns the SHA-256 of the written bytes so
 * callers can track in-session tamper-check hashes.
 */
export function writeStoreAtomic(workspaceRoot, fileName, text, refuse) {
    const { dir, file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    try {
        mkdirSync(dir);
    }
    catch (e) {
        if (e.code !== "EEXIST")
            throw e;
    }
    // Re-check after mkdir (a symlink could have been raced into place).
    // ACCEPTED RESIDUAL (S1.4 security review P3, v0): a narrow TOCTOU window
    // remains between this re-check and openSync/renameSync — an agent that can
    // race it can already rewrite the store file outright, which ADR-003's
    // threat note accepts for detection-only v0 and mitigates via O_CREAT|O_EXCL
    // on the temp file, provenance disclosure, and the in-session tamper hash
    // (baseline.tampered). Full closure arrives with E4 signing/attestation.
    checkedStorePaths(workspaceRoot, fileName, refuse);
    const tmp = join(dir, `.${fileName}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
    const fd = openSync(tmp, "wx", 0o600);
    try {
        writeSync(fd, text);
        fsyncSync(fd);
    }
    finally {
        closeSync(fd);
    }
    try {
        renameSync(tmp, file);
    }
    catch (e) {
        try {
            unlinkSync(tmp);
        }
        catch {
            /* best effort */
        }
        throw e;
    }
    return { fileHash: sha256Hex(text) };
}
/**
 * Contained O(1) line append (ADR-018 hot-path amendment, 2026-08-01): the
 * audit ledger appends one JSONL line per review, and the atomic
 * temp+fsync+rename rewrite made that O(file) with a multi-ms fsync on the
 * REVIEW hot path (live bench tripwire caught it at 2x the ADR-017 budget).
 * Same containment discipline as writeStoreAtomic (checked paths, mkdir
 * re-check, O_NOFOLLOW so a swapped symlink fails the open). Durability
 * trade, documented: no fsync — a crash may lose the line being appended
 * (a lost record is not tamper; the chain re-links from the surviving
 * tail), and a torn line is TAMPER-EVIDENT by design (readLedger → corrupt
 * sentinel → loud finding). Auditability model unchanged (ADR-018).
 */
export function appendStoreLine(workspaceRoot, fileName, line, refuse) {
    const { dir, file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    try {
        mkdirSync(dir);
    }
    catch (e) {
        /* v8 ignore next -- reason: non-EEXIST mkdir failures (EACCES/ENOSPC/EROFS) require an environment fault the suite cannot stage portably; the identical arm in writeStoreAtomic is pinned by persistence tests via fs fault injection, and this is the same two-line pattern. */
        if (e.code !== "EEXIST")
            throw e;
    }
    checkedStorePaths(workspaceRoot, fileName, refuse);
    /* v8 ignore next 2 -- reason: constants.O_NOFOLLOW is defined on every POSIX platform the suite runs on; the ?? 0 fallback exists solely for win32 field use (same annotation as read.ts's NOFOLLOW). */
    const fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
        writeSync(fd, line);
    }
    finally {
        closeSync(fd);
    }
}
