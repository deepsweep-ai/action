import { canonicalize, sha256Hex } from "./canonical.js";
import { sanitizeEventField } from "./sanitize.js";
export const EVENT_SCHEMA_VERSION = 1;
export const EVENT_ACTION = "environment.change";
export function buildEvent(finding, ctx) {
    const workspace = sanitizeEventField(ctx.workspace);
    const resource = sanitizeEventField(finding.resource);
    const source = sanitizeEventField(finding.source);
    const explanation = sanitizeEventField(finding.explanation);
    // Defense-in-depth: derived agentIds are inert hex, but principal passes
    // the choke point like every other event field anyway.
    const principal = ctx.principal === undefined ? null : sanitizeEventField(ctx.principal);
    const eventId = sha256Hex(canonicalize({
        schemaVersion: EVENT_SCHEMA_VERSION,
        workspace,
        kind: finding.kind,
        severity: finding.severity,
        principal,
        action: EVENT_ACTION,
        resource,
        source,
        entityHash: finding.entityHash,
        explanation,
        seq: ctx.seq,
    }));
    return {
        schemaVersion: 1,
        eventId,
        occurredAt: ctx.occurredAt,
        workspace,
        kind: finding.kind,
        severity: finding.severity,
        principal,
        action: EVENT_ACTION,
        resource,
        source,
        entityHash: finding.entityHash,
        explanation,
    };
}
/** The ONLY serializer for event lines (JSON.stringify, never hand-assembled). */
export function eventLine(event) {
    return JSON.stringify(event);
}
