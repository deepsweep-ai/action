import type { StudioInput } from "../review/studio.js";
import { type SurfaceContext } from "../review/surface.js";
export interface StudioParams {
    readonly workspaceRoot: string;
    /** Stamped into the artifact; supplied by the composition root. */
    readonly toolVersion: string;
    /** ADR-014 user-scope config root, injected by the composition root. */
    readonly userConfigRoot?: string;
    /** Injected clock (determinism invariant). */
    readonly nowIso: string;
    /**
     * TEAM-ADR-030 — WHICH SURFACE this artifact is being rendered for,
     * resolved once by the caller's composition root (`resolveSurface`).
     *
     * This is the parameter the DESKTOP Studio passes, and passing it is what
     * stops the desktop app from rendering "Get the desktop Studio →" at
     * itself. Optional, defaulting to 'web' — the fail-closed value, whose
     * only failure mode is a missing acquisition CTA rather than a surface
     * advertising itself.
     */
    readonly surfaceContext?: SurfaceContext;
}
export interface StudioArtifact {
    /** Self-contained offline HTML. Never written by this function. */
    readonly html: string;
    /** The assembled data behind the artifact (the same shape live mode serves). */
    readonly input: StudioInput;
}
/**
 * Assemble and render the Studio artifact. Pure with respect to the file
 * system beyond the reads the review itself performs — it writes nothing.
 */
export declare function generateStudioArtifact(params: StudioParams): StudioArtifact;
/**
 * Persist an artifact inside the contained store and return its path.
 * Refuses (BaselineRefusalError → the ADR-003 refusal class) on any
 * containment violation — symlinked store dir, escape, non-regular file.
 */
export declare function writeStudioArtifact(workspaceRoot: string, html: string): string;
