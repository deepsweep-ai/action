/**
 * Dev container detector — .devcontainer/devcontainer.json and root
 * .devcontainer.json: bind mounts, privileged features/flags, port forwards.
 * Metadata-first: structure only; containerEnv/remoteEnv VALUES are never
 * read into the report. Fixed allowlist per ADR-002.
 */
import { parseTolerantJson, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { asRecord, asString, malformedWarning, unreadableWarning } from "./util.js";
const DEVCONTAINER_PATHS = [".devcontainer/devcontainer.json", ".devcontainer.json"];
/** Docker feature ids that grant daemon-level (privileged-equivalent) control. */
const PRIVILEGED_FEATURE_MARKERS = [
    "docker-in-docker",
    "docker-outside-of-docker",
    "docker-from-docker",
];
function parseMount(m) {
    if (typeof m === "string") {
        const parts = {};
        for (const seg of m.split(",")) {
            const eq = seg.indexOf("=");
            if (eq > 0)
                parts[seg.slice(0, eq).trim()] = seg.slice(eq + 1).trim();
        }
        return {
            source: parts["source"] ?? parts["src"],
            target: parts["target"] ?? parts["dst"],
            type: parts["type"],
        };
    }
    const r = asRecord(m);
    if (r === undefined)
        return undefined;
    return { source: asString(r["source"]), target: asString(r["target"]), type: asString(r["type"]) };
}
function portValues(v) {
    const list = Array.isArray(v) ? v : v === undefined ? [] : [v];
    return list
        .filter((p) => typeof p === "string" || typeof p === "number")
        .map(String);
}
function reviewOne(rel, json, out) {
    // Mounts — agent file access beyond the workspace.
    const mounts = Array.isArray(json["mounts"]) ? json["mounts"] : [];
    for (const raw of mounts) {
        const mount = parseMount(raw);
        if (mount === undefined)
            continue;
        const where = mount.source ?? mount.target ?? "unspecified mount";
        const dockerSocket = /docker\.sock/.test(where);
        const cap = {
            kind: "containerMount",
            summary: dockerSocket
                ? `Dev container mounts the Docker socket ("${where}") — agents inside can control the host Docker daemon`
                : `Dev container bind-mounts "${where}" into the agent's container`,
            resource: where,
            source: rel,
            detail: {
                dockerSocket,
                ...(mount.target !== undefined ? { target: mount.target } : {}),
                ...(mount.type !== undefined ? { type: mount.type } : {}),
            },
        };
        out.capabilities.push(cap);
    }
    // Privileged flags and features.
    const runArgs = Array.isArray(json["runArgs"]) ? json["runArgs"].map(String) : [];
    if (json["privileged"] === true || runArgs.includes("--privileged")) {
        out.capabilities.push({
            kind: "privilegedContainer",
            summary: "Dev container runs privileged — container isolation is not a boundary for agents inside it",
            resource: json["privileged"] === true ? "privileged" : "runArgs: --privileged",
            source: rel,
        });
    }
    const features = asRecord(json["features"]);
    if (features !== undefined) {
        for (const featureId of Object.keys(features).sort()) {
            if (PRIVILEGED_FEATURE_MARKERS.some((m) => featureId.includes(m))) {
                out.capabilities.push({
                    kind: "privilegedContainer",
                    summary: `Dev container feature "${featureId}" grants Docker daemon-level control`,
                    resource: featureId,
                    source: rel,
                });
            }
        }
    }
    // Port forwards — container services exposed on the host.
    const ports = [...portValues(json["forwardPorts"]), ...portValues(json["appPort"])];
    for (const port of ports) {
        out.capabilities.push({
            kind: "portExposure",
            summary: `Dev container forwards port ${port} to the host`,
            resource: port,
            source: rel,
        });
    }
}
function detect(workspaceRoot) {
    const out = emptyResult();
    for (const rel of DEVCONTAINER_PATHS) {
        // S1.14: absent evidence must be visible — a present-but-unreadable
        // config degrades to a metadata-only warning, never to silence.
        const probe = probeRead(workspaceRoot, rel);
        if (probe.status === "absent")
            continue;
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(rel, probe.reason));
            continue;
        }
        out.reviewedSources.push(rel);
        const json = asRecord(parseTolerantJson(probe.text));
        if (json === undefined) {
            out.warnings.push(malformedWarning(rel));
            continue;
        }
        reviewOne(rel, json, out);
    }
    return out;
}
export const devcontainerDetector = { id: "devcontainer", detect };
