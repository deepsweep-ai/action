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
export const SURFACES = ["web", "desktop", "ide-extension"];
export function isSurface(value) {
    return typeof value === "string" && SURFACES.includes(value);
}
function present(signal) {
    return signal !== undefined && signal !== null;
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
export function resolveSurface(signals = {}) {
    // 1. Compiled-in truth beats anything observed at runtime.
    if (isSurface(signals.buildTimeSurface))
        return signals.buildTimeSurface;
    const tauri = present(signals.tauriIpc);
    const ide = present(signals.ideWebviewBridge);
    // 3a. CONTRADICTION. A Tauri webview cannot also be a VS Code webview; if
    // both globals are present, something is shimming one of them and we no
    // longer know what we are. Fail closed — never resolve 'desktop' from a
    // signal set we have already caught lying.
    if (tauri && ide)
        return "web";
    // 2. Exactly one positive runtime signal.
    if (tauri)
        return "desktop";
    if (ide)
        return "ide-extension";
    // 3b. NO SIGNAL. The plain web Studio, and also the genuinely ambiguous
    // case. Both resolve to 'web' — never a guess at 'desktop'.
    return "web";
}
/**
 * Read the bootstrap signals off a browser-global object. The ONLY place
 * that touches globals; `resolveSurface` itself stays pure and testable.
 *
 * Not used by this package's server-side renderer (which is handed a surface
 * by its host) — it is the shared implementation the three browser-side
 * composition roots call exactly once at bootstrap.
 */
export function readSurfaceSignals(globalObject = {}) {
    return {
        tauriIpc: globalObject["__TAURI_INTERNALS__"] ?? globalObject["__TAURI__"],
        buildTimeSurface: globalObject["DEEPSWEEP_SURFACE"],
        ideWebviewBridge: globalObject["acquireVsCodeApi"] ?? globalObject["__DEEPSWEEP_IDE_BRIDGE__"],
    };
}
/* ══════════════════════════════════════════════════════════════════════════
 *  ACQUISITION CTAs — the enumerated class of thing that can commit the bug
 * ══════════════════════════════════════════════════════════════════════════ */
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
export const ACQUISITION_CTA_IDS = {
    /** "Get the desktop Studio →" — acquires the Tauri desktop app. */
    DESKTOP_STUDIO: "cta-acquire-desktop-studio",
    /** "Open Governance Studio →" when the desktop app is NOT installed. */
    DESKTOP_STUDIO_FROM_IDE: "cta-acquire-desktop-studio-from-ide",
    /** "Add the IDE extension →" — acquires the VS Code / Cursor extension. */
    IDE_EXTENSION: "cta-acquire-ide-extension",
    /** "Open the web Studio →" — acquires the hosted surface. */
    WEB_STUDIO: "cta-acquire-web-studio",
};
/** The full set, for tests that sweep rendered DOM for any of them. */
export const ALL_ACQUISITION_CTA_IDS = Object.values(ACQUISITION_CTA_IDS);
/**
 * Which surface each acquisition CTA acquires. This map is what makes rule
 * (1) mechanical rather than a code-review habit.
 */
export const ACQUISITION_CTA_ACQUIRES = {
    [ACQUISITION_CTA_IDS.DESKTOP_STUDIO]: "desktop",
    [ACQUISITION_CTA_IDS.DESKTOP_STUDIO_FROM_IDE]: "desktop",
    [ACQUISITION_CTA_IDS.IDE_EXTENSION]: "ide-extension",
    [ACQUISITION_CTA_IDS.WEB_STUDIO]: "web",
};
/**
 * THE RULE, as a function: a surface must not render a CTA to acquire itself.
 *
 * Every acquisition CTA in every renderer goes through this guard. Rendering
 * one without it is caught by the surface-guard test, which greps the
 * renderer sources for the CTA ids and requires each to sit behind a call.
 */
export function mayRenderAcquisitionCta(id, surface) {
    return ACQUISITION_CTA_ACQUIRES[id] !== surface;
}
export const UPDATE_STATUS_COPY = {
    "up-to-date": "Up to date",
    "update-available": "Update available — restart to install",
    unknown: "Update status unavailable",
};
/** Copy for the anchor line when the host has no anchor to report. */
export const NO_ANCHOR_COPY = "Never anchored";
/** The default context for a host that has not resolved anything yet. */
export const WEB_SURFACE_CONTEXT = { surface: "web" };
