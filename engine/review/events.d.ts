/**
 * Drift event contract v1 (ADR-004) — the JSONL stream `--watch --json`
 * emits, forward-mapped onto the future AuditEvent entity:
 * `principal`/`action`/`resource` mirror the Principal/Action/Resource shape
 * so Epic E4 fills fields instead of renaming them. `principal` was reserved
 * (always null) in the Review stage; S2.1 fills it ADDITIVELY with the
 * claimed agentId STRING (ADR-005: `null → "agt_…"`, never a structured
 * object, no schemaVersion bump — v1 consumers' `string | null` tolerance
 * survives unchanged). When no identity is supplied, principal stays null
 * and event bytes are IDENTICAL to the pre-S2.1 contract (BINDING tests).
 *
 * Serialization: every event line is produced solely by JSON.stringify of the
 * typed object — no hand-assembled JSON, so JSONL framing cannot be broken by
 * content. Workspace-derived string fields route through the single S1.9
 * sanitization choke point (sanitize.ts, sanitizeEventField): strip set +
 * 512-char cap, truncation marked with an ellipsis — the entity hash stays
 * the authoritative reference. Sanitized output bytes are CONTRACT: eventIds
 * are content-derived, so any byte change is a breaking schema rev (see the
 * BINDING note in sanitize.ts and the byte-exact regression test).
 *
 * `eventId` is deterministic: SHA-256 over the canonical event content
 * EXCLUDING `occurredAt` and `eventId` itself, plus a monotonic per-session
 * sequence number to disambiguate genuine repeats. Snapshot tests normalize
 * `occurredAt`.
 */
import type { Severity } from "./types.js";
import type { DriftFinding, DriftKind } from "./diff.js";
export declare const EVENT_SCHEMA_VERSION = 1;
export declare const EVENT_ACTION = "environment.change";
export interface DriftEvent {
    schemaVersion: 1;
    eventId: string;
    occurredAt: string;
    /** Workspace root BASENAME only — never absolute paths (ADR-003/004). */
    workspace: string;
    kind: DriftKind;
    severity: Severity;
    /**
     * The claimed agentId string of the agent surface the finding originates
     * from (ADR-005 fill of the ADR-004 reserved field), or null when no
     * identity applies. CLAIMED-tier attribution — spoofable by design, never
     * verified, and never a basis for broadening any outcome (ADR-005
     * narrow-not-broaden rule).
     */
    principal: string | null;
    action: typeof EVENT_ACTION;
    resource: string;
    source: string;
    entityHash: string | null;
    explanation: string;
}
export interface EventContext {
    workspace: string;
    /** Monotonic per-session sequence number (part of the eventId input). */
    seq: number;
    occurredAt: string;
    /**
     * Optional claimed agentId (ADR-005, derived via principalFor — never a
     * store lookup). Absent → principal null and event bytes identical to the
     * pre-S2.1 contract.
     */
    principal?: string | undefined;
}
export declare function buildEvent(finding: DriftFinding, ctx: EventContext): DriftEvent;
/** The ONLY serializer for event lines (JSON.stringify, never hand-assembled). */
export declare function eventLine(event: DriftEvent): string;
