/**
 * Engine library — `studio` capability (TEAM-ADR-027).
 *
 * The Governance Studio artifact (ADR-022) is now produced by a library
 * function that the Tauri Studio, the headless sidecar and the legacy CLI
 * shim all share. The assembly step was already a library function
 * (`assembleStudioInput`, ADR-023); the CLI kept a SECOND hand-rolled copy of
 * it. That duplicate is gone — one assembly, one renderer, one write path.
 *
 * Containment: `writeStudioArtifact` writes ONLY through the contained store
 * (`.deepsweep/studio.html`). An arbitrary output path is deliberately NOT a
 * library capability — an IPC-reachable arbitrary-write primitive is a far
 * worse abuse case than the convenience is worth. The legacy CLI's `--out`
 * remains at its own composition root, where the operator typed the path.
 */
import { resolve } from "node:path";
import { assembleStudioInput } from "../review/studio-server.js";
import { renderStudio, STUDIO_FILE } from "../review/studio.js";
import { WEB_SURFACE_CONTEXT } from "../review/surface.js";
import { writeStoreAtomic, STORE_DIR } from "../review/store.js";
import { BaselineRefusalError } from "../review/baseline.js";
/**
 * Assemble and render the Studio artifact. Pure with respect to the file
 * system beyond the reads the review itself performs — it writes nothing.
 */
export function generateStudioArtifact(params) {
    const root = resolve(params.workspaceRoot);
    const nowIso = params.nowIso;
    const input = assembleStudioInput(root, params.toolVersion, params.userConfigRoot, () => new Date(nowIso));
    const withSurface = {
        ...input,
        surfaceContext: params.surfaceContext ?? WEB_SURFACE_CONTEXT,
    };
    return { html: renderStudio(withSurface), input: withSurface };
}
/**
 * Persist an artifact inside the contained store and return its path.
 * Refuses (BaselineRefusalError → the ADR-003 refusal class) on any
 * containment violation — symlinked store dir, escape, non-regular file.
 */
export function writeStudioArtifact(workspaceRoot, html) {
    const root = resolve(workspaceRoot);
    writeStoreAtomic(root, STUDIO_FILE, html, (reason) => new BaselineRefusalError(reason));
    return `${root}/${STORE_DIR}/${STUDIO_FILE}`;
}
