/** Wire version of the request/response envelope. Bumped by contract change. */
export declare const HOST_PROTOCOL_VERSION: 1;
/**
 * Hard bound on a request. The host is trusted, but a wedged or hostile
 * writer must not be able to grow this process without limit — the sidecar
 * fails closed on oversize input rather than buffering it.
 */
export declare const MAX_REQUEST_BYTES = 1048576;
/** Cap on the echoed correlation id (it is host-supplied, so it is bounded). */
export declare const MAX_CORRELATION_ID_LENGTH = 128;
/** The complete command vocabulary. Anything else is a protocol error. */
export declare const HOST_COMMANDS: readonly ["authorize", "export", "review", "studio", "timeline", "verify"];
export type HostCommand = (typeof HOST_COMMANDS)[number];
/** One line of machine-readable help — the sidecar has no marketing surface. */
export declare const HOST_HELP_LINE: string;
export interface HostOutcome {
    /** Canonical JSON response body (the value; the caller renders it). */
    readonly body: unknown;
    /** Diagnostic lines for stderr, in order. Never carries result data. */
    readonly diagnostics: readonly string[];
    readonly exitCode: number;
}
/**
 * The response for a request that exceeded MAX_REQUEST_BYTES. Exposed so the
 * process wrapper can fail closed the moment the bound is crossed, without
 * first buffering the oversize payload it is refusing.
 */
export declare function oversizeRequestOutcome(): HostOutcome;
/**
 * Handle ONE request. Never throws: every failure becomes a structured error
 * response with a non-zero exit code, so a caller can never mistake a crash
 * for a pass (fail-closed).
 */
export declare function handleHostRequest(raw: string): HostOutcome;
