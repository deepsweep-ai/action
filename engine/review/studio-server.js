/**
 * ADR-023 — Governance Studio LIVE mode: `deepsweep studio --serve`.
 *
 * A zero-dependency node:http server that brings the studio to life:
 * workspace selection, explicit re-review, and one-click apply of the
 * policy draft — the interactions a static artifact cannot have. Design
 * boundaries, non-negotiable:
 *  - LOCAL ONLY: binds 127.0.0.1; every request must present the session
 *    token AND a loopback Host header (DNS-rebinding + drive-by defense).
 *  - READS are the engine's contained reads; the ONLY write is the
 *    explicit apply-draft action, which validates via validatePolicy and
 *    REFUSES to overwrite an existing policy.json (409 — overwriting is a
 *    deliberate manual act, not a button).
 *  - GET is idempotent: pages serve from the per-workspace cache; ONLY the
 *    explicit re-run action executes a review (each review appends to the
 *    audit ledger by design — refreshes must not).
 *  - CLOUD PLANE: any future cloud call uses exactly the sanctioned bases
 *    below (founder directive 2026-08-01; both /v1/health verified 200).
 *    No cloud call exists in this mode today — local-first.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { runReviewOnce } from "../oneshot.js";
import { computeTrustScores } from "./score.js";
import { readLedger, verifyChain } from "./ledger.js";
import { loadLayeredPolicy, validatePolicy, POLICY_REL_PATH } from "./policy.js";
import { readStoreText, writeStoreAtomic } from "./store.js";
import { renderStudio } from "./studio.js";
import { WEB_SURFACE_CONTEXT } from "./surface.js";
/** The sanctioned cloud-plane bases (founder directive; health-verified). */
export const API_BASE = "https://api.deepsweep.ai/v1";
export const API_BASE_DEV = "https://api-dev.deepsweep.ai/v1";
/** Assemble a StudioInput by running one review over `root` (appends one
 * ledger entry — callers cache the result; see GET idempotence above). */
export function assembleStudioInput(root, toolVersion, userConfigRoot, now) {
    const opts = {};
    if (userConfigRoot !== undefined)
        opts.userConfigRoot = userConfigRoot;
    if (now !== undefined)
        opts.now = now;
    const result = runReviewOnce(root, opts);
    const ledger = readLedger(root);
    const layered = loadLayeredPolicy(root, userConfigRoot !== undefined ? { userConfigRoot } : {});
    return {
        report: result.report,
        findings: result.findings,
        identity: result.identityRecords,
        trust: computeTrustScores({
            report: result.report,
            findings: result.findings,
            identityRecords: result.identityRecords,
        }),
        ledger,
        chainVerified: ledger !== undefined && verifyChain(ledger),
        mode: layered.mode,
        layersLoaded: layered.layersLoaded,
        workspace: basename(root),
        workspaceRoot: root,
        generatedAt: (now?.() ?? new Date()).toISOString(),
        toolVersion,
    };
}
function readBody(req, maxBytes) {
    return new Promise((resolvePromise) => {
        let size = 0;
        const chunks = [];
        req.on("data", (c) => {
            size += c.length;
            if (size > maxBytes) {
                resolvePromise(undefined);
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
        req.on("error", () => resolvePromise(undefined));
    });
}
/**
 * Constant-time session-token comparison. `!==` short-circuits on the first
 * differing byte, which leaks match-prefix length as a timing signal; loopback
 * keeps the oracle low-value (the attacker is already local), but the gate is
 * the ONLY thing between another local process and the policy-apply write
 * path, so it gets the strict comparison anyway. Length mismatch cannot use
 * timingSafeEqual (it throws) — compare the presented value against itself so
 * the work done is identical either way, and fail closed.
 */
function tokenMatches(presented, expected) {
    const a = Buffer.from(presented, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) {
        timingSafeEqual(a, a);
        return false;
    }
    return timingSafeEqual(a, b);
}
export function startStudioServer(options) {
    const token = options.token ?? randomBytes(16).toString("hex");
    let currentRoot = resolve(options.initialRoot);
    let cachedHtml;
    const rebuild = () => {
        const input = assembleStudioInput(currentRoot, options.toolVersion, options.userConfigRoot, options.now);
        cachedHtml = renderStudio({
            ...input,
            serve: { token },
            surfaceContext: options.surfaceContext ?? WEB_SURFACE_CONTEXT,
        });
    };
    rebuild();
    const server = createServer((req, res) => {
        void (async () => {
            const deny = (code, message) => {
                res.writeHead(code, { "content-type": "application/json" });
                res.end(JSON.stringify({ error: message }));
            };
            // Loopback-host + token gate on EVERY route (rebinding/drive-by).
            /* v8 ignore next -- reason: HTTP/1.1 clients always send Host; the fallback covers hand-crafted raw sockets and fails CLOSED (empty string never matches the loopback pattern). */
            const host = req.headers.host ?? "";
            if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(host)) {
                deny(403, "loopback host required");
                return;
            }
            /* v8 ignore next -- reason: node:http always populates req.url for real sockets; the fallback exists for the typing only. */
            const url = new URL(req.url ?? "/", `http://${host}`);
            const presented = url.searchParams.get("t") ?? req.headers["x-studio-token"];
            if (typeof presented !== "string" || !tokenMatches(presented, token)) {
                deny(403, "missing or invalid session token");
                return;
            }
            if (req.method === "GET" && url.pathname === "/") {
                res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
                res.end(cachedHtml);
                return;
            }
            if (req.method === "POST" && url.pathname === "/api/select") {
                const body = await readBody(req, 64_000);
                let path;
                try {
                    path = body === undefined ? undefined : JSON.parse(body).path;
                }
                catch {
                    path = undefined;
                }
                if (typeof path !== "string" || path.length === 0) {
                    deny(400, "body must be {\"path\": \"<workspace directory>\"}");
                    return;
                }
                const target = resolve(path);
                try {
                    if (!statSync(target).isDirectory()) {
                        deny(400, "path is not a directory");
                        return;
                    }
                }
                catch {
                    deny(400, "path does not exist");
                    return;
                }
                currentRoot = target;
                rebuild(); // explicit user action → one review, one ledger append
                res.writeHead(204).end();
                return;
            }
            if (req.method === "POST" && url.pathname === "/api/rerun") {
                rebuild();
                res.writeHead(204).end();
                return;
            }
            if (req.method === "POST" && url.pathname === "/api/apply-policy") {
                const body = await readBody(req, 256_000);
                let doc;
                try {
                    doc = body === undefined ? undefined : JSON.parse(body);
                }
                catch {
                    doc = undefined;
                }
                if (doc === undefined) {
                    deny(400, "body must be a policy JSON document");
                    return;
                }
                const validated = validatePolicy(doc, POLICY_REL_PATH);
                if (!validated.ok) {
                    /* v8 ignore next -- reason: validatePolicy refusals always carry at least one reason (refuse() is guarded); the fallback satisfies noUncheckedIndexedAccess only — same annotation class as policy.ts's refuse(). */
                    deny(400, `draft does not validate: ${validated.reasons[0] ?? "nonconforming"}`);
                    return;
                }
                if (readStoreText(currentRoot, "policy.json", (r) => new Error(r)) !== undefined) {
                    deny(409, "policy.json already exists — overwriting is a deliberate manual act, not a button");
                    return;
                }
                writeStoreAtomic(currentRoot, "policy.json", `${JSON.stringify(doc, null, 2)}\n`, (r) => new Error(r));
                rebuild();
                res.writeHead(201, { "content-type": "application/json" });
                res.end(JSON.stringify({ written: POLICY_REL_PATH }));
                return;
            }
            deny(404, "unknown route");
        })();
    });
    return new Promise((resolvePromise, reject) => {
        server.once("error", reject);
        server.listen(options.port ?? 0, "127.0.0.1", () => {
            const address = server.address();
            /* v8 ignore next -- reason: a TCP listen always yields an AddressInfo object; the string/null arms exist only for pipe/unix-socket typings this server never uses. */
            const port = typeof address === "object" && address !== null ? address.port : 0;
            resolvePromise({
                url: `http://127.0.0.1:${port}/?t=${token}`,
                port,
                token,
                close: () => new Promise((done) => {
                    server.close(() => done());
                }),
            });
        });
    });
}
