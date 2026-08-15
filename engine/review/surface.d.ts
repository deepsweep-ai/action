/**
 * TEAM-ADR-030 — the Surface primitive.
 *
 * ROOT CAUSE THIS EXISTS TO KILL: the Studio shell is rendered by ONE
 * function (`renderStudio`) that is embedded in three products — the web
 * Studio, the Tauri desktop Studio, and the IDE extension webview — and that
 * function had no idea which one it was running inside. So the bottom-left
 * rail rendered "Get the desktop Studio →" unconditionally, and the desktop
 * Studio advertised itself to itself.
 *
 * The fix is not a conditional around that one string. The fix is to make
 * "which product am I?" a first-class, resolved-once, typed value, and to
 * make "a CTA that acquires a DeepSweep surface" a first-class, enumerated
 * thing — so that the rule "no surface advertises itself" is checkable by a
 * test instead of by a screenshot.
 *
 * RESOLUTION DISCIPLINE (non-negotiable, and pinned by surface.test.ts):
 *  - Resolved ONCE, at the composition root, from a REAL bootstrap signal:
 *    the Tauri-injected IPC global, a build-time define, or the IDE webview
 *    bridge. Threaded from there; never re-derived at a call site.
 *  - NEVER the user agent. A Tauri webview reports the system WebView's UA
 *    and an Electron-ish UA can be spoofed by anyone; neither answers the
 *    question "is this our desktop app".
 *  - NEVER the viewport width. A narrow window is a narrow window. The
 *    original screenshot that surfaced this bug was a MOBILE-WIDTH WEB
 *    Studio, which is exactly the case a width heuristic gets wrong.
 *  - FAILS CLOSED TO 'web'. 'desktop' requires a positive desktop signal;
 *    absent, ambiguous, or self-contradictory input resolves to 'web' and
 *    never to 'desktop'. Guessing 'web' costs one hidden acquisition CTA in
 *    a desktop build; guessing 'desktop' silently suppresses acquisition
 *    across the entire web funnel. The asymmetry is the whole argument.
 */
/** The three products the shared Studio shell renders inside. */
export type Surface = "web" | "desktop" | "ide-extension";
export declare const SURFACES: readonly Surface[];
export declare function isSurface(value: unknown): value is Surface;
/**
 * Raw bootstrap signals, read once at the composition root.
 *
 * Every field is "whatever the host found", deliberately typed `unknown` —
 * the resolver's job is to be the only place that decides what counts. A
 * caller that pre-interprets a signal into a boolean has already made the
 * decision somewhere else, which is the pattern this module retires.
 */
export interface SurfaceSignals {
    /**
     * Tauri's injected IPC global — `window.__TAURI_INTERNALS__` (v2) or
     * `window.__TAURI__` (v1). Present ONLY inside a Tauri webview; the
     * runtime injects it before any app script runs. Absence is meaningful.
     */
    readonly tauriIpc?: unknown;
    /**
     * A build-time define stamped by the bundler that produced this bundle
     * (desktop: `DEEPSWEEP_SURFACE="desktop"`). The strongest signal available
     * — it is compiled in, not observed — so it wins when it names a known
     * surface. An unrecognized value is IGNORED rather than trusted, and falls
     * through to the runtime signals below.
     */
    readonly buildTimeSurface?: unknown;
    /**
     * The IDE webview bridge — VS Code's `acquireVsCodeApi` function, or the
     * equivalent host bridge object the extension injects into its webview.
     */
    readonly ideWebviewBridge?: unknown;
}
/**
 * Resolve the surface from bootstrap signals. Pure, total, and deterministic.
 *
 * Precedence:
 *   1. `buildTimeSurface`, when it names a known surface (compiled-in truth).
 *   2. Exactly one runtime signal present → that surface.
 *   3. Everything else — no signal, or contradictory signals — → 'web'.
 *
 * Case 3 is the fail-closed branch and it is the reason this function exists
 * rather than a chain of `if`s at three call sites.
 */
export declare function resolveSurface(signals?: SurfaceSignals): Surface;
/**
 * Read the bootstrap signals off a browser-global object. The ONLY place
 * that touches globals; `resolveSurface` itself stays pure and testable.
 *
 * Not used by this package's server-side renderer (which is handed a surface
 * by its host) — it is the shared implementation the three browser-side
 * composition roots call exactly once at bootstrap.
 */
export declare function readSurfaceSignals(globalObject?: Record<string, unknown>): SurfaceSignals;
/**
 * Every CTA whose purpose is to make the user ACQUIRE a DeepSweep surface
 * (download it, install it, sign up for it). This set is the contract the
 * regression tests assert against, so that changing the COPY of a CTA cannot
 * silently unpin the test — the test asserts on ids, never on strings.
 *
 * A CTA that does not acquire a surface does NOT belong here:
 *  - "Open in Cursor →"  — a deeplink into a third-party editor DeepSweep
 *    GOVERNS. Not a competitor, not an acquisition. Stays on every surface.
 *  - "See plans →"       — a TIER upsell within a surface the user already
 *    has. Free→Pro is orthogonal to which product is rendering it.
 *  - "Reveal in Studio →" — a deeplink into an app the user ALREADY has.
 *    Navigation, not acquisition.
 */
export declare const ACQUISITION_CTA_IDS: {
    /** "Get the desktop Studio →" — acquires the Tauri desktop app. */
    readonly DESKTOP_STUDIO: "cta-acquire-desktop-studio";
    /** "Open Governance Studio →" when the desktop app is NOT installed. */
    readonly DESKTOP_STUDIO_FROM_IDE: "cta-acquire-desktop-studio-from-ide";
    /** "Add the IDE extension →" — acquires the VS Code / Cursor extension. */
    readonly IDE_EXTENSION: "cta-acquire-ide-extension";
    /** "Open the web Studio →" — acquires the hosted surface. */
    readonly WEB_STUDIO: "cta-acquire-web-studio";
};
export type AcquisitionCtaId = (typeof ACQUISITION_CTA_IDS)[keyof typeof ACQUISITION_CTA_IDS];
/** The full set, for tests that sweep rendered DOM for any of them. */
export declare const ALL_ACQUISITION_CTA_IDS: readonly AcquisitionCtaId[];
/**
 * Which surface each acquisition CTA acquires. This map is what makes rule
 * (1) mechanical rather than a code-review habit.
 */
export declare const ACQUISITION_CTA_ACQUIRES: Readonly<Record<AcquisitionCtaId, Surface>>;
/**
 * THE RULE, as a function: a surface must not render a CTA to acquire itself.
 *
 * Every acquisition CTA in every renderer goes through this guard. Rendering
 * one without it is caught by the surface-guard test, which greps the
 * renderer sources for the CTA ids and requires each to sit behind a call.
 */
export declare function mayRenderAcquisitionCta(id: AcquisitionCtaId, surface: Surface): boolean;
/**
 * Desktop update state, resolved by the desktop host at bootstrap.
 * 'unknown' is a real, renderable state — the Studio's REAL DATA ONLY
 * invariant forbids claiming "Up to date" when the check has not run.
 */
export type UpdateStatus = "up-to-date" | "update-available" | "unknown";
export declare const UPDATE_STATUS_COPY: Readonly<Record<UpdateStatus, string>>;
/**
 * The resolved surface plus its surface-specific bootstrap facts. Provided
 * once by the composition root; consumed as context by the renderer.
 */
export interface SurfaceContext {
    readonly surface: Surface;
    /**
     * DESKTOP ONLY. Update-channel state for the rail slot that replaces the
     * suppressed self-acquisition CTA. Omitted → 'unknown'.
     */
    readonly updateStatus?: UpdateStatus;
    /**
     * IDE EXTENSION ONLY. Whether the desktop Studio was detected on this
     * machine by the extension host (an installed-app probe, never a UA
     * sniff). Drives "Reveal in Studio →" vs "Open Governance Studio →".
     * Omitted → false, i.e. assume NOT installed, which is the honest default
     * and the one that offers the user the acquisition path.
     */
    readonly desktopDetected?: boolean;
    /**
     * DESKTOP ONLY. ISO-8601 instant of the most recent ledger ANCHOR, as
     * known to the host.
     *
     * Deliberately NOT derived from `input.ledger` by the renderer. The last
     * ledger ENTRY is not an anchor — anchors are signed chain-head exports
     * (ADR-018) and are not persisted in the store, so the renderer has no
     * honest way to infer one. Omitted → the slot says so rather than
     * inventing a timestamp (ADR-022 REAL DATA ONLY).
     */
    readonly lastAnchorAt?: string;
}
/** Copy for the anchor line when the host has no anchor to report. */
export declare const NO_ANCHOR_COPY = "Never anchored";
/** The default context for a host that has not resolved anything yet. */
export declare const WEB_SURFACE_CONTEXT: SurfaceContext;
