/**
 * DeepSweep engine — public library API (TEAM-ADR-027).
 *
 * THIS is the product. Every capability that a `deepsweep <verb>` command
 * used to reach is a first-class, individually tested function here, callable
 * over Tauri IPC by the Governance Studio and by the headless sidecar through
 * the same code path — so the two surfaces cannot drift.
 *
 * All functions take an injected `nowIso` where time participates; none reads
 * an ambient clock, spawns a process, or writes outside the contained store.
 */
export { reviewWorkspace } from "./review.js";
export type { ReviewParams, ReviewResult } from "./review.js";
export { authorizeAction, DEFAULT_EFFECT_RULE_LABEL } from "./authorize.js";
export type { AuthorizeParams, AuthorizeResult, AuthorizeLayerRefusal } from "./authorize.js";
export { EvidenceMaterialError, exportEvidenceBundle, parseTrustedKeys, verifyEvidence, } from "./evidence.js";
export type { ExportEvidenceParams, ExportEvidenceResult, TrustedKeyEntry, VerifyEvidenceParams, VerifyEvidenceResult, } from "./evidence.js";
export { generateStudioArtifact, writeStudioArtifact } from "./studio.js";
export type { StudioParams, StudioArtifact } from "./studio.js";
/**
 * TEAM-ADR-030 — the Surface primitive. Public because the surfaces that
 * embed this engine (the Tauri Studio, the IDE extension) must resolve their
 * surface with the SAME resolver the renderer's guard is written against; a
 * second, hand-rolled resolver at a shell is how this class of bug is
 * reintroduced.
 */
export { ACQUISITION_CTA_ACQUIRES, ACQUISITION_CTA_IDS, ALL_ACQUISITION_CTA_IDS, isSurface, mayRenderAcquisitionCta, NO_ANCHOR_COPY, readSurfaceSignals, resolveSurface, SURFACES, UPDATE_STATUS_COPY, WEB_SURFACE_CONTEXT, } from "../review/surface.js";
export type { AcquisitionCtaId, Surface, SurfaceContext, SurfaceSignals, UpdateStatus, } from "../review/surface.js";
export { ledgerTimeline } from "./timeline.js";
export type { TimelineParams, TimelineResult } from "./timeline.js";
export { handleHostRequest, HOST_COMMANDS, HOST_HELP_LINE, HOST_PROTOCOL_VERSION, MAX_CORRELATION_ID_LENGTH, MAX_REQUEST_BYTES, oversizeRequestOutcome, } from "./host.js";
export type { HostCommand, HostOutcome } from "./host.js";
/** Watch mode is already a library function; re-exported for one import site. */
export { startWatch } from "../watch.js";
