import { transition } from "../identity/lifecycle.js";
/** The event name. Frozen: additive, never renamed in place. */
export const TAMPER_EVENT = "ledger:tamper_detected";
export const TAMPER_EVENT_SCHEMA_VERSION = 1;
/** Which `verifyLedger` statuses are attributable to which detector. */
const LEDGER_DETECTOR = {
    edited: "chain",
    reordered: "chain",
    truncated: "tree-head",
    "head-refused": "tree-head",
    forged: "signature",
    "untrusted-key": "signature",
    "signature-gap": "signature",
    "malformed-signature": "signature",
};
/**
 * Normalize a `verifyLedger` verdict. `unsigned` is NOT tamper — it is the
 * honest "nothing attests to this" state, and reporting it as an attack would
 * train operators to ignore the alarm.
 */
export function assessLedger(verdict) {
    return {
        tampered: !verdict.ok,
        detector: LEDGER_DETECTOR[verdict.status] ?? "chain",
        tamperClass: verdict.status,
        entryCount: verdict.entryCount,
        signedEntries: verdict.signedEntries,
        chainHead: verdict.chainHead,
        detail: verdict.detail,
    };
}
/** Normalize an ADR-018 anchor verdict. `verified` and `verified-appended`
 * are both honest growth; everything else is tamper. */
export function assessAnchor(verdict, facts) {
    const clean = verdict.status === "verified" || verdict.status === "verified-appended";
    return {
        tampered: !clean,
        detector: "anchor",
        tamperClass: verdict.status,
        entryCount: facts.entryCount,
        signedEntries: facts.signedEntries,
        chainHead: facts.chainHead,
        detail: verdict.detail,
    };
}
export function buildTamperEvent(a, attributedAgentId, quarantined, nowIso) {
    return {
        event: TAMPER_EVENT,
        schemaVersion: TAMPER_EVENT_SCHEMA_VERSION,
        occurredAt: nowIso,
        detector: a.detector,
        tamperClass: a.tamperClass,
        entryCount: a.entryCount,
        signedEntries: a.signedEntries,
        chainHeadHash: a.chainHead,
        attributedAgentId,
        quarantined,
    };
}
// ------------------------------------------------------------ the gap
export const TAMPER_GAP_SEVERITY = "critical";
/** The CRITICAL boundary gap. Copy is user-facing: it states the impact and
 * the action, and never names a mechanism the operator cannot act on. */
export function tamperBoundaryGap(a) {
    return {
        severity: TAMPER_GAP_SEVERITY,
        summary: `The audit ledger failed verification (${a.tamperClass}, detected by the ${a.detector} check across ${a.entryCount} entries). Its record of what agents did can no longer be trusted.`,
        recommendation: "Treat every action recorded since your last escrowed anchor as unverified. Verify the ledger against that anchor, archive the current file for investigation, re-initialize the ledger, and keep the responsible agent quarantined until you have approved its return.",
        relatedCapabilities: [],
        relatedCapabilityIds: [],
    };
}
/** Fold a tamper gap into a report, keeping the report's own totals honest. */
export function mergeTamperGap(report, gap) {
    return {
        ...report,
        boundaryGaps: [...report.boundaryGaps, gap],
        totals: {
            ...report.totals,
            boundaryGaps: report.totals.boundaryGaps + 1,
            critical: report.totals.critical + (gap.severity === "critical" ? 1 : 0),
        },
    };
}
function isCandidate(v) {
    const c = v;
    return (typeof c === "object" &&
        c !== null &&
        typeof c["agentId"] === "string" &&
        typeof c["source"] === "string" &&
        (c["agentType"] === null || typeof c["agentType"] === "string"));
}
/**
 * Index marks by agent id. A Map LOOKUP, deliberately — not an equality
 * comparison on a claimed identity. ADR-005 AC5 forbids `src/` from branching
 * on agentId equality, because that is the mechanical shape of a
 * "broaden on principal match" bug; registry bookkeeping through a keyed
 * container is the sanctioned pattern (identity.ts uses the same shape).
 * Nothing here BROADENS on a match either way: a hit only ever narrows.
 */
function markIndex(marks) {
    const index = new Map();
    for (const mark of marks)
        index.set(mark.agentId, mark);
    return index;
}
/**
 * Does this registration re-enter under a new name? Fail-closed on a forged
 * candidate shape: an unparseable registration is treated as evasion, because
 * "I could not tell who this is" must never resolve to "let them in".
 */
export function checkQuarantineEvasion(candidate, marks) {
    if (!isCandidate(candidate)) {
        return {
            evaded: true,
            matchedAgentId: null,
            why: "the registration does not carry a readable identity — treated as quarantine evasion (never fail open)",
        };
    }
    const exact = markIndex(marks).get(candidate.agentId);
    if (exact !== undefined) {
        return {
            evaded: true,
            matchedAgentId: exact.agentId,
            why: `agent ${candidate.agentId} is quarantined (marked ${exact.quarantinedAt}) — reactivation requires explicit human approval`,
        };
    }
    const derived = marks.find((m) => m.agentType === candidate.agentType && m.source === candidate.source);
    if (derived !== undefined) {
        return {
            evaded: true,
            matchedAgentId: derived.agentId,
            why: `agent ${candidate.agentId} is new, but its identity derives from the same surface as quarantined agent ${derived.agentId} (same agent type and source) — re-registering under a new id does not exit quarantine`,
        };
    }
    return {
        evaded: false,
        matchedAgentId: null,
        why: `agent ${candidate.agentId} does not match any quarantine mark`,
    };
}
export const TAMPER_POLICY_ID = "ledger.tamper-response";
/**
 * Detect -> emit -> raise -> quarantine, as one decision.
 *
 * A clean assessment produces NO event and NO gap: this path must not cry
 * wolf. A tamper with no attributable agent still emits and still raises —
 * the evidence failing is the finding, whether or not we can name a culprit.
 */
export function respondToTamper(input) {
    const { assessment: a, agent, nowIso } = input;
    if (!a.tampered) {
        return {
            detected: false,
            event: null,
            gap: null,
            quarantine: null,
            mark: null,
            explanation: {
                who: agent?.agentId ?? "(no attributed agent)",
                what: `ledger verification (${a.detector})`,
                why: a.detail,
                policy: TAMPER_POLICY_ID,
                outcome: "no-action",
            },
        };
    }
    const gap = tamperBoundaryGap(a);
    const what = `${a.tamperClass} in the audit ledger, detected by the ${a.detector} check`;
    // Split on attribution FIRST, so `quarantine` is a definite value in the
    // branch that reads it. Nothing below needs a defensive fallback for a state
    // the control flow already rules out.
    if (agent === undefined) {
        return {
            detected: true,
            event: buildTamperEvent(a, null, false, nowIso),
            gap,
            quarantine: null,
            mark: null,
            explanation: {
                who: "(no attributed agent)",
                what,
                why: `${a.detail}. No agent could be attributed, so no identity was quarantined — the evidence failure stands on its own.`,
                policy: TAMPER_POLICY_ID,
                outcome: "no-attributed-agent",
            },
        };
    }
    const quarantine = transition(agent, "quarantined", { actor: "deepsweep:tamper-response" });
    const mark = quarantine.allowed
        ? {
            agentId: agent.agentId,
            agentType: input.derivation?.agentType ?? null,
            source: input.derivation?.source ?? "(unknown-source)",
            quarantinedAt: nowIso,
            reason: `audit-ledger tamper detected: ${a.tamperClass} (${a.detector})`,
        }
        : null;
    return {
        detected: true,
        event: buildTamperEvent(a, agent.agentId, quarantine.allowed, nowIso),
        gap,
        quarantine,
        mark,
        explanation: {
            who: agent.agentId,
            what,
            why: `${a.detail}. ${quarantine.allowed
                ? "The attributed agent was quarantined automatically; its return requires explicit human approval."
                : `The agent could not be quarantined: ${quarantine.reason}`}`,
            policy: TAMPER_POLICY_ID,
            outcome: quarantine.allowed ? "quarantined" : "quarantine-refused",
        },
    };
}
/**
 * The ONLY sanctioned quarantine exit. Requires explicit human approval AND
 * clears the derivation-keyed mark, so an approved return cannot leave a stale
 * mark that would re-quarantine the agent on its next registration. Refuses
 * without approval — `transition` enforces that, and this wrapper never
 * supplies the flag itself.
 */
export function reactivateQuarantinedAgent(agent, marks, opts) {
    const decision = transition(agent, "active", {
        ...(opts.approved === undefined ? {} : { approved: opts.approved }),
        ...(opts.actor === undefined ? {} : { actor: opts.actor }),
    });
    // Set membership, not id equality — see markIndex on the ADR-005 AC5 rule.
    const released = new Set([agent.agentId]);
    return {
        decision,
        marks: decision.allowed ? marks.filter((m) => !released.has(m.agentId)) : marks,
    };
}
