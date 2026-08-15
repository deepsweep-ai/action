import { evidenceLeafHash } from "./record.js";
import { merkleRoot, verifyConsistency, verifyInclusion } from "./merkle.js";
import { verifyTreeHead } from "./treehead.js";
const fail = (check, detail) => ({ check, ok: false, detail });
const pass = (check, detail) => ({ check, ok: true, detail });
/** Verify a parsed evidence bundle. Pure; no I/O, no clock. */
export function verifyEvidenceBundle(bundle, trustedKeys) {
    const findings = [];
    const b = bundle;
    if (typeof b !== "object" || b === null || Array.isArray(b)) {
        return {
            verified: false,
            attributed: false,
            logId: null,
            treeSize: 0,
            findings: [fail("envelope", "bundle is not an object")],
        };
    }
    if (b.status !== "ok" || typeof b.root !== "string" || !Array.isArray(b.records) || !Array.isArray(b.inclusion)) {
        return {
            verified: false,
            attributed: false,
            logId: null,
            treeSize: 0,
            findings: [fail("envelope", "bundle must be a status:ok export with root, records, and inclusion")],
        };
    }
    const records = b.records;
    const claimedRoot = b.root;
    // 3. Recompute the root from the records — the bundle's own root is a
    // claim until the records reproduce it.
    const recomputed = merkleRoot(records.map(evidenceLeafHash));
    const rootOk = recomputed === claimedRoot;
    findings.push(rootOk
        ? pass("root-recomputation", `root reproduced from ${records.length} records`)
        : fail("root-recomputation", "records do not reproduce the bundle's root — records were altered"));
    // 1 + 2. Attribution: signature, then the (size, root) binding.
    let attributed = false;
    let logId = null;
    if (b.signedTreeHead === undefined) {
        findings.push(fail("attribution", "bundle carries no signed tree head — internally consistent but UNATTRIBUTED"));
    }
    else {
        const verdict = verifyTreeHead(b.signedTreeHead, trustedKeys);
        if (!verdict.ok) {
            findings.push(fail("attribution", `tree head refused (${verdict.reason}): ${verdict.detail}`));
        }
        else {
            const head = verdict.treeHead;
            const bindsRoot = head.rootHash === claimedRoot;
            const bindsSize = head.treeSize === records.length;
            if (bindsRoot && bindsSize) {
                attributed = true;
                logId = verdict.keyId;
                findings.push(pass("attribution", `signed by log ${verdict.keyId}, binding size ${head.treeSize}`));
            }
            else {
                findings.push(fail("attribution", `tree head does not bind this bundle (head size ${head.treeSize} root ${head.rootHash.slice(0, 12)}… vs bundle size ${records.length} root ${claimedRoot.slice(0, 12)}…)`));
            }
        }
    }
    // 4. Inclusion proofs.
    const inclusion = b.inclusion;
    let inclusionOk = true;
    for (const inc of inclusion) {
        const ok = typeof inc.leafHash === "string" &&
            typeof inc.leafIndex === "number" &&
            typeof inc.treeSize === "number" &&
            Array.isArray(inc.proof) &&
            verifyInclusion(inc.leafHash, inc.leafIndex, inc.treeSize, inc.proof, claimedRoot);
        if (!ok) {
            inclusionOk = false;
            findings.push(fail("inclusion", `proof for leaf ${String(inc.leafIndex)} does not verify against the root`));
        }
    }
    if (inclusionOk) {
        findings.push(pass("inclusion", `${inclusion.length} inclusion proof(s) verified against the root`));
    }
    // Every record SHOULD have a proof; a bundle that proves only some of
    // its records is reported, never silently accepted as complete.
    if (inclusion.length !== records.length) {
        findings.push(fail("inclusion-coverage", `${inclusion.length} proof(s) for ${records.length} record(s) — bundle is partial`));
    }
    // 5. Consistency proofs.
    const consistency = (Array.isArray(b.consistency) ? b.consistency : []);
    let consistencyOk = true;
    for (const c of consistency) {
        const ok = typeof c.firstSize === "number" &&
            typeof c.secondSize === "number" &&
            typeof c.firstRoot === "string" &&
            typeof c.secondRoot === "string" &&
            Array.isArray(c.proof) &&
            c.secondRoot === claimedRoot &&
            verifyConsistency(c.firstSize, c.secondSize, c.firstRoot, c.secondRoot, c.proof);
        if (!ok) {
            consistencyOk = false;
            findings.push(fail("consistency", `append-only proof from size ${String(c.firstSize)} does not verify`));
        }
    }
    if (consistencyOk && consistency.length > 0) {
        findings.push(pass("consistency", `${consistency.length} append-only proof(s) verified`));
    }
    const structurallyOk = rootOk && inclusionOk && consistencyOk && inclusion.length === records.length;
    return {
        verified: structurallyOk && attributed,
        attributed,
        logId,
        treeSize: records.length,
        findings,
    };
}
