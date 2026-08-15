/**
 * ADR-011 — identity lifecycle wiring: registry → JML records → review
 * findings. Pure derivation; no I/O, no clock (nowIso is the caller's).
 *
 * v0 derivation semantics (deliberately narrow, documented in ADR-011):
 *  - Every registry record derives as state "active" — no persisted state
 *    machine exists yet, so quarantine/decommission states (and therefore
 *    the zombieActivity detector) cannot fire from this path. transition()
 *    remains the programmatic JML surface for E2 consumers.
 *  - lastSeenAt falls back to firstObservedAt on pre-ADR-011 stores.
 *  - The claimed owner (git user.email) participates as PRESENCE ONLY: a
 *    sentinel string stands in for it so the value itself can never leak
 *    through a lifecycle record, gap summary, finding, or event (ADR-005
 *    transient-owner rule). Gap text carries agentIds (inert derived hex)
 *    and static template copy — metadata-only by construction.
 */
import type { AgentIdentityRecord } from "../review/identity.js";
import type { DriftFinding } from "../review/diff.js";
import type { AgentLifecycleRecord, IdentityGap } from "./lifecycle.js";
/** Presence stand-in for the transient claimed owner — never the value. */
export declare const OWNER_PRESENT = "(claimed-owner-present)";
/** Derive transient JML records from the persisted identity registry. */
export declare function deriveLifecycleRecords(records: readonly AgentIdentityRecord[], ownerPresent: boolean): AgentLifecycleRecord[];
/**
 * Render an IdentityGap as a review finding. Advisory: these kinds have no
 * ADR-006 exit-code mapping and are not on the ADR-004 event stream in v1;
 * they surface in the report / --json and deduct posture via ADR-011's
 * FINDING_DELTAS entries (workspace-shared scope — the registry is a
 * workspace store; per-agent scoping is an ADR-011 noted follow-up).
 */
export declare function identityGapFinding(gap: IdentityGap): DriftFinding;
