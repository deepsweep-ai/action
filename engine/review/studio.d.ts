/**
 * ADR-022 — Governance Studio: the three-screen desktop-shell artifact
 * (Review · Authorize · Audit) generated as ONE self-contained HTML file
 * from the "Governance Studio Mockups" design (Nocturne design system).
 *
 * NON-NEGOTIABLES, inherited and enforced here:
 *  - REAL DATA ONLY. Every number, row, badge, and verdict comes from this
 *    run's report / layered policy / ledger. Mockup elements that implied
 *    data we do not have (letter grades, "AI-generated %") render as their
 *    HONEST counterparts (the ADR-007 qualified posture composite) — the
 *    studio never fabricates a metric.
 *  - ZERO NETWORK. No font imports, no CDN, no fetch: tokens are inlined,
 *    fonts fall back to the system stack, a restrictive CSP meta seals it.
 *    The only external references are NAVIGATION anchors (docs/download +
 *    the Cursor deeplink) — links, never loads.
 *  - SANITIZE-CHOKED. Every workspace-derived string passes sanitizeField
 *    AND HTML-escaping (S1.9). This module is a registered sanctioned
 *    renderer; interaction script is STATIC (no interpolation inside the
 *    <script> beyond one JSON.stringify → escaped data island).
 *  - Client-side interactions are real: screen tabs, audit filters, matrix
 *    cell selection building an ADR-021 policy draft, WebCrypto SHA-256
 *    re-verification of the EMBEDDED ledger snapshot (labeled as such),
 *    and JSON export of the embedded report. Buttons that would need a
 *    daemon (re-run review) are honest: they show the exact CLI command.
 */
import type { AgentIdentityRecord } from "./identity.js";
import type { AgentTrustScore } from "./score.js";
import type { ReviewReport } from "./types.js";
import type { DriftFinding } from "./diff.js";
import type { LedgerEntry } from "./ledger.js";
import type { PolicyLayer, PolicyMode } from "./policy.js";
import { type SurfaceContext } from "./surface.js";
export declare const STUDIO_FILE = "studio.html";
/** Navigation anchors only — never loaded, never fetched (ADR-022).
 * LINK DISCIPLINE (founder catch 2026-08-01: shipped anchors 404'd): every
 * URL here must be verified live (curl 200) before it lands, and the
 * zero-network test pins the exact allowed set — no speculative paths. */
export declare const STUDIO_DOWNLOAD_URL = "https://platform.deepsweep.ai";
export declare const STUDIO_DOCS_URL = "https://deepsweep.ai/pricing";
/** Deeplink into an ALREADY-INSTALLED desktop Studio (TEAM-ADR-030). Not an
 * https URL, so it is exempt from the curl-200 rule above and from the
 * zero-network test's https allowlist — a custom scheme loads nothing; the
 * OS either has a handler registered or the click is inert. Registered by
 * the desktop bundle, mirroring the `cursor://` deeplink already here. */
export declare const STUDIO_REVEAL_DEEPLINK = "deepsweep://studio/open";
export interface StudioInput {
    report: ReviewReport;
    findings: readonly DriftFinding[];
    identity: readonly AgentIdentityRecord[];
    trust: readonly AgentTrustScore[];
    ledger: readonly LedgerEntry[] | undefined;
    chainVerified: boolean;
    mode: PolicyMode;
    layersLoaded: readonly PolicyLayer[];
    workspace: string;
    workspaceRoot: string;
    generatedAt: string;
    toolVersion: string;
    /** ADR-023 live mode: present when served by `deepsweep studio --serve`.
     * Enables the workspace selector + live re-run + apply-draft controls
     * and widens CSP by exactly `connect-src 'self'`. */
    serve?: {
        readonly token: string;
    };
    /**
     * TEAM-ADR-030 — WHICH PRODUCT is rendering this shell.
     *
     * Resolved ONCE by the composition root from a real bootstrap signal
     * (`resolveSurface`) and threaded here. The renderer never sniffs: no user
     * agent, no viewport width, no `serve` inference. Optional at the type
     * level so an existing host that has not been taught to resolve it still
     * compiles — and it defaults to 'web', the fail-closed value, which can
     * only ever cause a MISSING acquisition CTA, never a self-advertisement.
     */
    surfaceContext?: SurfaceContext;
}
/** The one sanctioned render call for the Studio artifact (S1.9). */
export declare function renderStudio(input: StudioInput): string;
