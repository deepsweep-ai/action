/**
 * Headless engine host protocol (TEAM-ADR-027).
 *
 * The DeepSweep CLI is retired as a PRODUCT SURFACE. What survives is a
 * headless binary with exactly two consumers:
 *   (a) the Governance Studio, which spawns it as a bundled sidecar;
 *   (b) the CI runner, which executes the same artifact.
 * It is never installed on PATH, never symlinked, never a documented user
 * command.
 *
 * Contract — deliberately minimal and machine-only:
 *   stdin   ONE JSON request object (bounded, see MAX_REQUEST_BYTES)
 *   stdout  ONE canonical JSON response (sorted keys, byte-stable)
 *   stderr  diagnostics only, one line each
 *   exit    the capability's own contract code (0 is the only pass);
 *           1 = protocol/usage error; 3 = contained-store refusal
 *
 * No interactive prompts. No TTY detection. No colors, spinners or banner.
 * No upsell, no pricing, no auto-updater. NO telemetry of its own — the host
 * supplies a correlation id and owns all analytics.
 *
 * This module is PURE: it takes the request text and returns the bytes and
 * exit code the process wrapper should emit. All of the sidecar's behaviour
 * is therefore unit-testable without spawning anything.
 */
import { reviewWorkspace } from "./review.js";
import { authorizeAction } from "./authorize.js";
import { exportEvidenceBundle, EvidenceMaterialError, verifyEvidence } from "./evidence.js";
import { generateStudioArtifact, writeStudioArtifact } from "./studio.js";
import { isSurface } from "../review/surface.js";
import { ledgerTimeline } from "./timeline.js";
import { ACTION_VOCABULARY } from "../review/policy.js";
import { sha256Hex } from "../review/canonical.js";
import { BaselineRefusalError } from "../review/baseline.js";
import { IdentityRefusalError } from "../review/identity.js";
import { LedgerRefusalError } from "../review/ledger.js";
import { PolicyRefusalError } from "../review/policy.js";
/** Wire version of the request/response envelope. Bumped by contract change. */
export const HOST_PROTOCOL_VERSION = 1;
/**
 * Hard bound on a request. The host is trusted, but a wedged or hostile
 * writer must not be able to grow this process without limit — the sidecar
 * fails closed on oversize input rather than buffering it.
 */
export const MAX_REQUEST_BYTES = 1_048_576;
/** Cap on the echoed correlation id (it is host-supplied, so it is bounded). */
export const MAX_CORRELATION_ID_LENGTH = 128;
/** The complete command vocabulary. Anything else is a protocol error. */
export const HOST_COMMANDS = [
    "authorize",
    "export",
    "review",
    "studio",
    "timeline",
    "verify",
];
/** One line of machine-readable help — the sidecar has no marketing surface. */
export const HOST_HELP_LINE = "JSON request on stdin (schema: docs/engine-host-protocol.md); internal component of " +
    "DeepSweep Governance Studio; not a supported standalone interface.";
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
/** Shape AND semantics: "2026-13-45T99:99:99Z" is ISO-shaped but not a time. */
function isInstant(value) {
    return typeof value === "string" && ISO_INSTANT.test(value) && !Number.isNaN(Date.parse(value));
}
function protocolError(message, correlationId) {
    return {
        body: {
            protocolVersion: HOST_PROTOCOL_VERSION,
            correlationId,
            status: "error",
            error: { code: "protocol", message },
        },
        diagnostics: [message],
        exitCode: 1,
    };
}
/**
 * The response for a request that exceeded MAX_REQUEST_BYTES. Exposed so the
 * process wrapper can fail closed the moment the bound is crossed, without
 * first buffering the oversize payload it is refusing.
 */
export function oversizeRequestOutcome() {
    return protocolError(`request exceeds ${MAX_REQUEST_BYTES} bytes`, null);
}
function isPlainObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
function requiredString(params, key) {
    const v = params[key];
    if (typeof v !== "string" || v === "")
        throw new HostParamError(`params.${key} must be a non-empty string`);
    return v;
}
function optionalString(params, key) {
    const v = params[key];
    if (v === undefined)
        return undefined;
    if (typeof v !== "string" || v === "")
        throw new HostParamError(`params.${key} must be a non-empty string`);
    return v;
}
/**
 * TEAM-ADR-030 — build the SurfaceContext from host params.
 *
 * Deliberately NOT `requiredString` + throw: an old Studio build that has
 * not learned to send `surface` must keep working, and it must degrade to
 * 'web'. Equally deliberately NOT tolerant of near-misses — "Desktop",
 * "tauri", or a boolean do not become 'desktop'. The only way to get
 * 'desktop' out of this function is for the caller to say so exactly, which
 * is the whole fail-closed rule expressed at the protocol boundary.
 */
function hostSurfaceContext(params) {
    const claimed = params["surface"];
    const surface = isSurface(claimed) ? claimed : "web";
    const updateStatus = params["updateStatus"];
    const lastAnchorAt = params["lastAnchorAt"];
    return {
        surface,
        ...defined({
            updateStatus: isUpdateStatus(updateStatus) ? updateStatus : undefined,
            lastAnchorAt: typeof lastAnchorAt === "string" && lastAnchorAt !== "" ? lastAnchorAt : undefined,
            desktopDetected: typeof params["desktopDetected"] === "boolean" ? params["desktopDetected"] : undefined,
        }),
    };
}
function isUpdateStatus(v) {
    return v === "up-to-date" || v === "update-available" || v === "unknown";
}
function optionalBoolean(params, key) {
    const v = params[key];
    if (v === undefined)
        return undefined;
    if (typeof v !== "boolean")
        throw new HostParamError(`params.${key} must be a boolean`);
    return v;
}
/** A rejected parameter. Fails the request closed — never a defaulted guess. */
class HostParamError extends Error {
}
function parseFailOn(params) {
    const v = params["failOn"];
    if (v === undefined)
        return undefined;
    if (v !== "critical" && v !== "high" && v !== "none") {
        throw new HostParamError("params.failOn must be one of: critical | high | none");
    }
    return v;
}
function parseAction(params) {
    const v = params["action"];
    if (typeof v !== "string" || !ACTION_VOCABULARY.includes(v)) {
        throw new HostParamError(`params.action must be one of: ${ACTION_VOCABULARY.join(" | ")}`);
    }
    return v;
}
/** `principal` is a neutral identifier; null means unattributed. */
function parsePrincipal(params) {
    const v = params["principal"];
    if (v === null)
        return null;
    if (typeof v !== "string" || v === "") {
        throw new HostParamError("params.principal must be a non-empty string or null");
    }
    return v;
}
function parseSinceSize(params) {
    const v = params["sinceSize"];
    if (v === undefined)
        return undefined;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
        throw new HostParamError("params.sinceSize must be a positive integer");
    }
    return v;
}
/**
 * Drop undefined-valued keys so an absent parameter stays ABSENT rather than
 * becoming an explicit `undefined` (tsconfig runs exactOptionalPropertyTypes;
 * a defaulted `undefined` is also how a silent permissive default sneaks in).
 */
function defined(o) {
    const out = {};
    for (const [k, v] of Object.entries(o))
        if (v !== undefined)
            out[k] = v;
    return out;
}
function dispatch(command, params, nowIso) {
    switch (command) {
        case "review": {
            const r = reviewWorkspace({
                workspaceRoot: requiredString(params, "workspaceRoot"),
                nowIso,
                ...defined({
                    updateBaseline: optionalBoolean(params, "updateBaseline"),
                    userConfigRoot: optionalString(params, "userConfigRoot"),
                    failOn: parseFailOn(params),
                    failOnDrift: optionalBoolean(params, "failOnDrift"),
                    requireBaseline: optionalBoolean(params, "requireBaseline"),
                }),
            });
            return { result: r, exitCode: r.exitCode };
        }
        case "authorize": {
            const r = authorizeAction({
                workspaceRoot: requiredString(params, "workspaceRoot"),
                principal: parsePrincipal(params),
                action: parseAction(params),
                resource: requiredString(params, "resource"),
                nowIso,
                ...defined({ userConfigRoot: optionalString(params, "userConfigRoot") }),
            });
            return { result: r, exitCode: r.exitCode };
        }
        case "export": {
            const r = exportEvidenceBundle({
                workspaceRoot: requiredString(params, "workspaceRoot"),
                nowIso,
                ...defined({
                    sinceSize: parseSinceSize(params),
                    signWithPem: optionalString(params, "signWithPem"),
                }),
            });
            return { result: r.bundle, exitCode: r.exitCode };
        }
        case "verify": {
            const bundle = params["bundle"];
            if (bundle === undefined)
                throw new HostParamError("params.bundle is required");
            const keys = params["trustedKeys"];
            if (keys !== undefined && !Array.isArray(keys)) {
                throw new HostParamError("params.trustedKeys must be an array");
            }
            const trusted = (Array.isArray(keys) ? keys : [])
                .filter((k) => isPlainObject(k) && typeof k["keyId"] === "string" && typeof k["publicKey"] === "string")
                .map((k) => ({ keyId: k.keyId, publicKey: k.publicKey }));
            const r = verifyEvidence({ bundle, trustedKeys: trusted });
            return { result: r.result, exitCode: r.exitCode };
        }
        case "studio": {
            const workspaceRoot = requiredString(params, "workspaceRoot");
            // TEAM-ADR-030: the caller states its surface; the host NEVER infers
            // one. `hostSurfaceContext` accepts only exact Surface literals and
            // falls closed to 'web' on anything else — an unrecognized or absent
            // value can cost a missing acquisition CTA, never a self-advertisement.
            const artifact = generateStudioArtifact({
                workspaceRoot,
                toolVersion: requiredString(params, "toolVersion"),
                nowIso,
                surfaceContext: hostSurfaceContext(params),
                ...defined({ userConfigRoot: optionalString(params, "userConfigRoot") }),
            });
            // Contained write only, and the RESPONSE carries a reference, not the
            // page. Two reasons: there is deliberately NO output-path parameter (an
            // IPC-reachable arbitrary write is a worse abuse case than the
            // convenience is worth), and the response stream is a metadata surface
            // — a 70 KB document does not belong in it. The Studio calls
            // generateStudioArtifact directly over IPC when it wants the markup.
            const writtenTo = writeStudioArtifact(workspaceRoot, artifact.html);
            return {
                result: {
                    writtenTo,
                    sha256: sha256Hex(artifact.html),
                    byteLength: Buffer.byteLength(artifact.html, "utf8"),
                },
                exitCode: 0,
            };
        }
        /* v8 ignore next -- reason: exhaustive over HOST_COMMANDS; TS proves the default unreachable. */
        case "timeline":
            return { result: ledgerTimeline({ workspaceRoot: requiredString(params, "workspaceRoot") }), exitCode: 0 };
    }
}
/**
 * Handle ONE request. Never throws: every failure becomes a structured error
 * response with a non-zero exit code, so a caller can never mistake a crash
 * for a pass (fail-closed).
 */
export function handleHostRequest(raw) {
    if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES)
        return oversizeRequestOutcome();
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return protocolError("stdin must carry one JSON request object", null);
    }
    if (!isPlainObject(parsed)) {
        return protocolError("stdin must carry one JSON request object", null);
    }
    const req = parsed;
    const rawId = req.correlationId;
    if (rawId !== undefined && (typeof rawId !== "string" || rawId.length > MAX_CORRELATION_ID_LENGTH)) {
        return protocolError(`correlationId must be a string of at most ${MAX_CORRELATION_ID_LENGTH} characters`, null);
    }
    const correlationId = typeof rawId === "string" ? rawId : null;
    const version = parsed["protocolVersion"];
    if (version !== undefined && version !== HOST_PROTOCOL_VERSION) {
        return protocolError(`unsupported protocolVersion (this host speaks ${HOST_PROTOCOL_VERSION})`, correlationId);
    }
    const command = req.command;
    if (typeof command !== "string" || !HOST_COMMANDS.includes(command)) {
        return protocolError(`unknown command — expected one of: ${HOST_COMMANDS.join(" | ")}`, correlationId);
    }
    if (!isInstant(req.nowIso)) {
        // Determinism invariant: the host owns the clock. The sidecar refuses to
        // invent one rather than silently producing non-reproducible output.
        return protocolError("nowIso must be an ISO-8601 instant supplied by the host", correlationId);
    }
    const params = req.params === undefined ? {} : req.params;
    if (!isPlainObject(params)) {
        return protocolError("params must be an object", correlationId);
    }
    try {
        const { result, exitCode } = dispatch(command, params, req.nowIso);
        return {
            body: {
                protocolVersion: HOST_PROTOCOL_VERSION,
                correlationId,
                command,
                status: "ok",
                exitCode,
                result,
            },
            diagnostics: [],
            exitCode,
        };
    }
    catch (e) {
        if (e instanceof HostParamError || e instanceof EvidenceMaterialError) {
            return protocolError(e.message, correlationId);
        }
        if (e instanceof BaselineRefusalError ||
            e instanceof IdentityRefusalError ||
            e instanceof PolicyRefusalError ||
            e instanceof LedgerRefusalError) {
            // ADR-003 contained-store refusal class → exit 3, same as every surface.
            return {
                body: {
                    protocolVersion: HOST_PROTOCOL_VERSION,
                    correlationId,
                    command,
                    status: "error",
                    error: { code: "containment", message: e.message },
                },
                diagnostics: [e.message],
                exitCode: 3,
            };
        }
        // Unknown failure: report it, never swallow it into a pass.
        const message = e instanceof Error ? e.message : "unhandled engine failure";
        return {
            body: {
                protocolVersion: HOST_PROTOCOL_VERSION,
                correlationId,
                command,
                status: "error",
                error: { code: "internal", message },
            },
            diagnostics: [message],
            exitCode: 1,
        };
    }
}
