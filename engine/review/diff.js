const SEP = "\u0000";
function cmpStr(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}
function capMap(report) {
    const map = new Map();
    for (const c of report.capabilities) {
        const key = `${c.kind}${SEP}${c.source}${SEP}${c.resource}`;
        if (!map.has(key))
            map.set(key, c);
    }
    return map;
}
function gapMap(report) {
    const map = new Map();
    for (const g of report.boundaryGaps) {
        const key = `${g.severity}${SEP}${g.summary}`;
        if (!map.has(key))
            map.set(key, g);
    }
    return map;
}
function gapSource(gap, report) {
    const sources = gap.relatedCapabilities
        .map((i) => report.capabilities[i]?.source)
        .filter((s) => s !== undefined)
        .sort();
    return sources[0] ?? "review";
}
function pinMap(entities) {
    const map = new Map();
    for (const e of entities) {
        const key = `${e.entityType}${SEP}${e.logicalName}`;
        const list = map.get(key);
        if (list)
            list.push(e);
        else
            map.set(key, [e]);
    }
    return map;
}
function setsEqual(a, b) {
    if (a.size !== b.size)
        return false;
    for (const v of a)
        if (!b.has(v))
            return false;
    return true;
}
function short(hash) {
    return hash.slice(0, 12);
}
export function diffReports(prev, next) {
    const findings = [];
    // Capability delta (vs previous report).
    const prevCaps = capMap(prev.report);
    const nextCaps = capMap(next.report);
    for (const [key, c] of nextCaps) {
        if (prevCaps.has(key))
            continue;
        findings.push({
            kind: "capability.added",
            severity: "info",
            resource: c.resource,
            source: c.source,
            entityHash: null,
            explanation: `Capability added: ${c.summary}`,
        });
    }
    for (const [key, c] of prevCaps) {
        if (nextCaps.has(key))
            continue;
        findings.push({
            kind: "capability.removed",
            severity: "info",
            resource: c.resource,
            source: c.source,
            entityHash: null,
            explanation: `Capability removed: ${c.summary}`,
        });
    }
    // Boundary-gap delta (vs previous report).
    const prevGaps = gapMap(prev.report);
    const nextGaps = gapMap(next.report);
    for (const [key, g] of nextGaps) {
        if (prevGaps.has(key))
            continue;
        findings.push({
            kind: "gap.opened",
            severity: g.severity,
            resource: g.summary,
            source: gapSource(g, next.report),
            entityHash: null,
            explanation: `Boundary gap opened: ${g.summary} — recommended protection: ${g.recommendation}`,
        });
    }
    for (const [key, g] of prevGaps) {
        if (nextGaps.has(key))
            continue;
        findings.push({
            kind: "gap.resolved",
            severity: "info",
            resource: g.summary,
            source: gapSource(g, prev.report),
            entityHash: null,
            explanation: `Boundary gap resolved: ${g.summary}`,
        });
    }
    // Pin drift (vs session baseline entities — sticky until explicit re-pin)
    // and pin conflicts (a property of the CURRENT snapshot; never silently
    // resolved by picking one definition).
    const prevPins = pinMap(prev.entities);
    const nextPins = pinMap(next.entities);
    for (const [key, list] of nextPins) {
        const first = list[0];
        const hashes = new Set(list.map((e) => e.contentHash));
        if (hashes.size > 1) {
            const sources = [...new Set(list.map((e) => e.source))].sort();
            findings.push({
                kind: "pin.conflict",
                severity: "high",
                resource: `${first.entityType}:${first.logicalName}`,
                source: sources.join(", "),
                entityHash: first.contentHash,
                explanation: `Pinned ${first.entityType} "${first.logicalName}" is defined with differing content in multiple sources (${sources.join(", ")}) — name shadowing across configs is never silently resolved; remove or reconcile one definition.`,
            });
        }
        const prevList = prevPins.get(key);
        if (prevList) {
            const prevFirst = prevList[0];
            const prevHashes = new Set(prevList.map((e) => e.contentHash));
            if (!setsEqual(hashes, prevHashes)) {
                findings.push({
                    kind: "pin.drift",
                    severity: "high",
                    resource: `${first.entityType}:${first.logicalName}`,
                    source: first.source,
                    entityHash: first.contentHash,
                    // SRC-6 citation is front-loaded so it survives the 200-char text
                    // render cap; the full explanation ships in the 512-cap JSONL event.
                    explanation: `Agent environment changed since last review — re-review before continuing to trust it (silent re-trust [SRC-6]). Pinned ${first.entityType} "${first.logicalName}": ${short(prevFirst.contentHash)}… → ${short(first.contentHash)}…; re-pin via --update-baseline.`,
                });
            }
        }
    }
    findings.sort((a, b) => cmpStr(a.kind, b.kind) || cmpStr(a.source, b.source) || cmpStr(a.resource, b.resource));
    return findings;
}
