import { POSTURE_ASSURANCE_NOTE, qualifiedPostureLine } from "./score.js";
import { sanitizeField, sanitizeJsonValue } from "./sanitize.js";
import { AGENTIC_IDE_MARKS, BIG_TECH_MARKS, DEEPSWEEP_LOGO_SVG } from "./studio-assets.js";
import { ACQUISITION_CTA_IDS, mayRenderAcquisitionCta, NO_ANCHOR_COPY, UPDATE_STATUS_COPY, } from "./surface.js";
export const STUDIO_FILE = "studio.html";
/** Navigation anchors only — never loaded, never fetched (ADR-022).
 * LINK DISCIPLINE (founder catch 2026-08-01: shipped anchors 404'd): every
 * URL here must be verified live (curl 200) before it lands, and the
 * zero-network test pins the exact allowed set — no speculative paths. */
export const STUDIO_DOWNLOAD_URL = "https://platform.deepsweep.ai"; // verified 200 2026-08-01
export const STUDIO_DOCS_URL = "https://deepsweep.ai/pricing"; // verified 200 2026-08-01
/** Deeplink into an ALREADY-INSTALLED desktop Studio (TEAM-ADR-030). Not an
 * https URL, so it is exempt from the curl-200 rule above and from the
 * zero-network test's https allowlist — a custom scheme loads nothing; the
 * OS either has a handler registered or the click is inert. Registered by
 * the desktop bundle, mirroring the `cursor://` deeplink already here. */
export const STUDIO_REVEAL_DEEPLINK = "deepsweep://studio/open";
/** The resolved surface for this render. One accessor, one default. */
function surfaceOf(input) {
    return input.surfaceContext?.surface ?? "web";
}
function esc(value) {
    return sanitizeField(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
const SEV_TOKEN = {
    critical: { token: "[FAIL]", color: "#e28f88" },
    high: { token: "[FAIL]", color: "#e28f88" },
    medium: { token: "[WARN]", color: "#dcb475" },
    warning: { token: "[WARN]", color: "#dcb475" },
    info: { token: "[PASS]", color: "#8fc7a2" },
};
/** Nocturne tokens (styles.css source of truth), network import removed;
 * ground retuned darker per founder direction 2026-08-01 (Cursor-like
 * near-black: bg #0b0c12, surface #15161e) — accent/ramps unchanged. */
const TOKENS_CSS = `
:root{--color-bg:#0b0c12;--color-surface:#15161e;--color-text:#e9e9ed;--color-accent:#9184d9;--color-accent-300:#d2cefd;--color-accent-800:#423a6a;--color-accent-900:#2b2741;--color-divider:color-mix(in srgb,#e9e9ed 16%,transparent);--color-neutral-300:#cfd3e5;--color-neutral-400:#b2b6ca;--color-neutral-500:#9397ab;--color-neutral-600:#75798c;--color-neutral-700:#595d6c;--color-neutral-800:#3f424d;--font-heading:system-ui,-apple-system,"Segoe UI",sans-serif;--font-body:system-ui,-apple-system,"Segoe UI",sans-serif;--radius-sm:4px;--radius-md:8px;--radius-lg:14px;--shadow-md:0 0 0 1px #3f424d,0 8px 24px rgba(0,0,0,.7)}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--color-bg);color:var(--color-text);font:400 15px/1.55 var(--font-body)}
h4{font-family:var(--font-heading);font-weight:500;line-height:1.12;letter-spacing:-.015em;margin:0 0 6px;font-size:20px}
a{color:var(--color-accent);text-underline-offset:3px}
:focus-visible{outline:2px solid var(--color-accent);outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;cursor:pointer;text-decoration:none;font-family:var(--font-heading);font-weight:500;font-size:14px;line-height:1.2;color:var(--color-text);background:transparent;border:1px solid transparent;padding:6px 12px;border-radius:var(--radius-md)}
.btn-primary{color:var(--color-accent);border-color:var(--color-accent)}.btn-primary:hover{background:color-mix(in srgb,var(--color-accent) 12%,transparent)}
.btn-secondary{border-color:var(--color-divider)}.btn-secondary:hover{background:color-mix(in srgb,var(--color-text) 7%,transparent)}
.btn-ghost{color:var(--color-accent);padding-inline:4px}.btn-ghost:hover{background:color-mix(in srgb,var(--color-accent) 10%,transparent)}
.btn-block{width:100%;margin-top:6px}
.card{display:flex;flex-direction:column;gap:6px;padding:10px;border-radius:var(--radius-md);background:var(--color-surface)}
.card-kicker{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--color-accent)}
.card-meta{display:flex;align-items:center;gap:6px;font-size:11px;color:color-mix(in srgb,var(--color-text) 50%,transparent)}
.elev-sm{box-shadow:0 0 0 1px #3f424d}
.tag{display:inline-flex;align-items:center;font-size:11px;letter-spacing:.02em;padding:3px 10px;border-radius:6px}
.tag-accent{background:var(--color-accent-800);color:#f5f4ff}.tag-neutral{background:var(--color-neutral-800);color:#f3f5fe}.tag-outline{border:1px solid var(--color-accent);color:var(--color-accent)}
.seg{display:inline-flex;overflow:hidden;border:1px solid var(--color-divider);border-radius:var(--radius-md)}
.seg-opt{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;font-size:13px;cursor:pointer;background:transparent;border:0;color:var(--color-neutral-400);font-family:inherit}
.seg-opt+.seg-opt{border-left:1px solid var(--color-divider)}
.seg-opt[aria-pressed="true"]{color:var(--color-accent);box-shadow:inset 0 0 0 1px var(--color-accent)}
.table{width:100%;border-collapse:collapse;font-size:14px}
.table th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:color-mix(in srgb,var(--color-text) 60%,transparent);padding:6px}
.table td{padding:6px}
.table tbody tr{background:linear-gradient(to right,transparent,color-mix(in srgb,var(--color-text) 8%,transparent) 48px,color-mix(in srgb,var(--color-text) 8%,transparent) calc(100% - 48px),transparent) no-repeat bottom/100% 1px}
.mono{font-family:ui-monospace,Menlo,monospace}
.screen{display:none}.screen.active{display:flex}
.navitem{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--radius-md);color:var(--color-neutral-400);font-size:13px;cursor:pointer;background:transparent;border:0;width:100%;text-align:left;font-family:inherit}
.navitem[aria-current="true"]{background:color-mix(in srgb,var(--color-accent) 12%,transparent);color:var(--color-accent-300);box-shadow:inset 2px 0 0 var(--color-accent)}
.navitem:not([aria-current="true"]):hover{background:color-mix(in srgb,var(--color-text) 6%,transparent)}
@keyframes ds-fade-up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.ease-in{opacity:0;animation:ds-fade-up .6s ease-out forwards}
@keyframes ds-marquee{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.marquee{overflow:hidden;mask-image:linear-gradient(to right,transparent,#000 8%,#000 92%,transparent)}
.marquee-track{display:flex;gap:44px;width:max-content;align-items:center;animation:ds-marquee 42s linear infinite}
.mark{display:flex;align-items:center;gap:8px;filter:grayscale(1) brightness(0) invert(1);opacity:.6;transition:opacity .2s}
.mark:hover{opacity:1}
.mark svg{height:20px;width:auto;display:block}
.mark-label{font-size:11px;color:var(--color-neutral-500);white-space:nowrap}
.bigtech .mark{opacity:.32}
.bigtech .mark svg{height:16px}
@media (prefers-reduced-motion:reduce){.ease-in{animation:none;opacity:1}.marquee-track{animation:none}}
`;
const SHIELD = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 1.5 13.5 4v4c0 3.2-2.3 5.6-5.5 6.5C4.8 13.6 2.5 11.2 2.5 8V4L8 1.5Z" stroke="currentColor" stroke-width="1.3"></path></svg>`;
/** Static interaction script — no interpolation (S1.9: data enters ONLY via
 * the escaped JSON data island). Vanilla, zero dependencies. */
const STUDIO_JS = String.raw `
(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("studio-data").textContent);
  document.querySelectorAll(".navitem").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll(".navitem").forEach(function (b) { b.setAttribute("aria-current", "false"); });
      document.querySelectorAll(".screen").forEach(function (s) { s.classList.remove("active"); });
      btn.setAttribute("aria-current", "true");
      document.getElementById("screen-" + btn.dataset.screen).classList.add("active");
    });
  });
  var exportBtn = document.getElementById("export-json");
  if (exportBtn) exportBtn.addEventListener("click", function () {
    var blob = new Blob([JSON.stringify(data.report, null, 2)], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "deepsweep-review.json";
    a.click();
    URL.revokeObjectURL(a.href);
  });
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.dataset.copy);
      navigator.clipboard.writeText(el.innerText).then(function () {
        var was = btn.textContent; btn.textContent = "Copied ✓";
        setTimeout(function () { btn.textContent = was; }, 1200);
      });
    });
  });
  document.querySelectorAll("[data-audit-filter]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll("[data-audit-filter]").forEach(function (b) { b.setAttribute("aria-pressed", "false"); });
      btn.setAttribute("aria-pressed", "true");
      var want = btn.dataset.auditFilter;
      document.querySelectorAll("[data-entry-kind]").forEach(function (row) {
        row.style.display = want === "all" || row.dataset.entryKind === want ? "" : "none";
      });
    });
  });
  var draft = { schemaVersion: 1, name: "studio-draft", mode: "observe", defaultEffect: "require-approval", rules: [] };
  function renderDraft() {
    var el = document.getElementById("policy-draft");
    if (el) el.textContent = JSON.stringify(draft, null, 2);
  }
  document.querySelectorAll("[data-suggest]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var s = JSON.parse(btn.dataset.suggest);
      if (!draft.rules.some(function (r) { return r.name === s.name; })) draft.rules.push(s);
      renderDraft();
      var badge = document.getElementById("draft-count");
      if (badge) badge.textContent = String(draft.rules.length);
    });
  });
  renderDraft();
  if (data.serve) {
    var tok = new URL(location.href).searchParams.get("t");
    function post(path, body, status, onDone) {
      var el = document.getElementById(status);
      if (el) { el.textContent = "working…"; el.style.color = ""; }
      fetch(path + "?t=" + encodeURIComponent(tok), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      }).then(function (r) {
        if (r.ok) { onDone(r); return; }
        return r.json().then(function (j) {
          if (el) { el.textContent = "[FAIL] " + (j && j.error ? j.error : r.status); el.style.color = "#e28f88"; }
        });
      }).catch(function () {
        if (el) { el.textContent = "[FAIL] studio server unreachable — restart deepsweep studio --serve"; el.style.color = "#e28f88"; }
      });
    }
    var wsSelect = document.getElementById("ws-select");
    if (wsSelect) wsSelect.addEventListener("click", function () {
      post("/api/select", { path: document.getElementById("ws-input").value }, "ws-status", function () { location.reload(); });
    });
    var rerun = document.getElementById("rerun-live");
    if (rerun) rerun.addEventListener("click", function () {
      post("/api/rerun", undefined, "ws-status", function () { location.reload(); });
    });
    var apply = document.getElementById("apply-draft");
    if (apply) apply.addEventListener("click", function () {
      post("/api/apply-policy", draft, "apply-status", function () { location.reload(); });
    });
  }
  var verify = document.getElementById("verify-chain");
  if (verify) verify.addEventListener("click", function () {
    var out = document.getElementById("verify-result");
    var enc = new TextEncoder();
    function canon(v) {
      if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
      if (v && typeof v === "object") return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canon(v[k]); }).join(",") + "}";
      return JSON.stringify(v);
    }
    function sha(text) {
      return crypto.subtle.digest("SHA-256", enc.encode(text)).then(function (buf) {
        return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
      });
    }
    var entries = data.ledger || [];
    var prev = "0".repeat(64);
    var i = 0;
    function step() {
      if (i >= entries.length) { out.textContent = "[PASS] " + entries.length + " embedded entries re-hashed in your browser — chain intact"; out.style.color = "#8fc7a2"; return; }
      var e = entries[i];
      var body = { seq: e.seq, prevHash: e.prevHash, occurredAt: e.occurredAt, kind: e.kind, payload: e.payload };
      sha(canon(body)).then(function (h) {
        if (e.prevHash !== prev || h !== e.entryHash) { out.textContent = "[FAIL] chain breaks at entry " + e.seq; out.style.color = "#e28f88"; return; }
        prev = e.entryHash; i++; step();
      });
    }
    if (entries.length === 0) { out.textContent = "[WARN] no embedded entries to verify"; out.style.color = "#dcb475"; return; }
    out.textContent = "verifying…";
    step();
  });
})();
`;
const RAIL_LINK_STYLE = "font-size:12px;justify-content:flex-start;padding:2px 0";
const RAIL_ROW_STYLE = "display:flex;justify-content:space-between;font-size:11px;color:var(--color-neutral-500)";
/**
 * THE GUARD (TEAM-ADR-030). Every acquisition CTA in this renderer is built
 * here and nowhere else, so rule (1) — a surface must not render a CTA to
 * acquire itself — is enforced by construction rather than by remembering.
 *
 * Returns "" when the CTA would advertise the surface it is rendering on.
 * The `data-cta-id` / `data-surface` attributes are inert markup (no network
 * — ADR-022): they are what the HOST reads to attach the PostHog impression
 * and click events, so the property travels with the element instead of
 * being re-derived by whichever host happens to be listening.
 */
function acquisitionCta(id, surface, href, label) {
    if (!mayRenderAcquisitionCta(id, surface))
        return "";
    return `<a class="btn btn-ghost" data-cta-id="${id}" data-cta-kind="acquisition" data-surface="${surface}" style="${RAIL_LINK_STYLE}" href="${href}">${esc(label)}</a>`;
}
/**
 * The bottom-left rail slot below Policy/Ledger — the exact block that used
 * to render "Get the desktop Studio →" on every surface including the
 * desktop Studio itself.
 *
 * REPLACE, NEVER DELETE. Suppressing a self-advertisement leaves a hole; a
 * hole in a rail reads as unfinished software just like the bug did. Each
 * surface gets content it actually wants in that slot:
 *  - web           → the desktop acquisition CTA (correct here, and only here)
 *  - desktop       → version · update status · last ledger anchor
 *  - ide-extension → "Reveal in Studio →" if the desktop app is installed,
 *                    otherwise the acquisition CTA that offers to install it
 */
function railSurfaceSlot(input) {
    const ctx = input.surfaceContext;
    const surface = surfaceOf(input);
    if (surface === "desktop") {
        // The user HAS the app. What they want here is the state of the app they
        // are looking at. Every value is real or honestly absent — the ADR-022
        // no-fabricated-metrics invariant applies to this slot too.
        const update = UPDATE_STATUS_COPY[ctx?.updateStatus ?? "unknown"];
        const anchor = ctx?.lastAnchorAt ?? NO_ANCHOR_COPY;
        // The CTA is still REQUESTED here and the guard is what refuses it. That
        // is deliberate: a guard the production path routes around is decorative,
        // and a decorative guard is one refactor away from being deleted as dead
        // code. Routing through it means deleting the guard changes the rendered
        // desktop DOM — so the DOM regression tests, not just the source lint,
        // fail the build. It contributes the empty string here, by design.
        return `${acquisitionCta(ACQUISITION_CTA_IDS.DESKTOP_STUDIO, surface, STUDIO_DOWNLOAD_URL, "Get the desktop Studio →")}<div style="${RAIL_ROW_STYLE}"><span>Version</span><span class="mono">${esc(input.toolVersion)}</span></div>
    <div style="${RAIL_ROW_STYLE}"><span>Updates</span><span class="mono" data-update-status="${esc(ctx?.updateStatus ?? "unknown")}">${esc(update)}</span></div>
    <div style="${RAIL_ROW_STYLE}"><span>Last anchor</span><span class="mono">${esc(anchor)}</span></div>`;
    }
    if (surface === "ide-extension") {
        // "Reveal in Studio →" is NAVIGATION into an app the user already has —
        // deliberately NOT in ACQUISITION_CTA_IDS and so deliberately not guarded.
        return ctx?.desktopDetected === true
            ? `<a class="btn btn-ghost" data-cta-id="cta-reveal-in-studio" data-cta-kind="navigation" data-surface="${surface}" style="${RAIL_LINK_STYLE}" href="${STUDIO_REVEAL_DEEPLINK}?root=${encodeURIComponent(esc(input.workspaceRoot))}">Reveal in Studio →</a>`
            : acquisitionCta(ACQUISITION_CTA_IDS.DESKTOP_STUDIO_FROM_IDE, surface, STUDIO_DOWNLOAD_URL, "Open Governance Studio →");
    }
    return acquisitionCta(ACQUISITION_CTA_IDS.DESKTOP_STUDIO, surface, STUDIO_DOWNLOAD_URL, "Get the desktop Studio →");
}
function sidebar(input, active) {
    const nav = (id, label) => `<button class="navitem" data-screen="${id}" aria-current="${id === active}">${SHIELD}${label}</button>`;
    return `<div style="width:216px;flex:none;display:flex;flex-direction:column;border-right:1px solid var(--color-divider);background:color-mix(in srgb,var(--color-surface) 45%,var(--color-bg));padding:16px 0 14px">
  <div style="display:flex;align-items:center;gap:9px;padding:0 16px 14px"><span style="display:flex;width:22px">${DEEPSWEEP_LOGO_SVG}</span><div><div style="font-family:var(--font-heading);font-weight:500;font-size:14px;line-height:1.1">DeepSweep</div><div style="font-size:10px;letter-spacing:.06em;color:var(--color-neutral-600)">GOVERNANCE STUDIO</div></div></div>
  <div style="padding:0 16px 6px;font-size:10px;letter-spacing:.1em;color:var(--color-neutral-600)">WORKSPACE</div>
  ${input.serve
        ? `<div style="margin:0 12px 16px;display:flex;flex-direction:column;gap:6px"><input id="ws-input" class="mono" value="${esc(input.workspaceRoot)}" style="width:100%;padding:7px 10px;border-radius:var(--radius-md);border:1px solid var(--color-divider);background:var(--color-surface);color:var(--color-text);font-size:11px" aria-label="Workspace folder"><button class="btn btn-secondary" id="ws-select" style="font-size:12px">Review this workspace</button><span id="ws-status" class="mono" style="font-size:10.5px;color:var(--color-neutral-500)"></span></div>`
        : `<div style="margin:0 12px 16px;padding:7px 10px;border-radius:var(--radius-md);border:1px solid var(--color-divider);background:var(--color-surface)"><span class="mono" style="font-size:11.5px">${esc(input.workspace)}</span></div>`}
  <div style="display:flex;flex-direction:column;gap:2px;padding:0 8px">${nav("review", "Review")}${nav("authorize", "Authorize")}${nav("audit", "Audit")}</div>
  <div style="margin-top:auto;padding:14px 16px 0;display:flex;flex-direction:column;gap:8px;border-top:1px solid var(--color-divider)">
    <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--color-neutral-500)"><span>Policy</span><span class="mono">${esc(input.layersLoaded.join("+") || "none")} · ${esc(input.mode)}</span></div>
    <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--color-neutral-500)"><span>Ledger</span><span class="mono" style="color:${input.chainVerified ? "#8fc7a2" : "#e28f88"}">${input.chainVerified ? "[PASS]" : "[FAIL]"}</span></div>
    <!-- UNTOUCHED (TEAM-ADR-030 rule 3): DeepSweep GOVERNS Cursor, it does
         not compete with it. This deeplink is correct on every surface and is
         deliberately not an acquisition CTA. -->
    <a class="btn btn-ghost" style="font-size:12px;justify-content:flex-start;padding:2px 0" href="cursor://file/${esc(input.workspaceRoot)}">Open in Cursor →</a>
    ${railSurfaceSlot(input)}
  </div>
</div>`;
}
function reviewScreen(input) {
    const { report } = input;
    const capRows = report.capabilities
        .map((c) => {
        const gap = report.boundaryGaps.find((g) => g.relatedCapabilityIds?.includes(c.id ?? ""));
        const sev = gap?.severity ?? "info";
        const t = SEV_TOKEN[sev] ?? SEV_TOKEN["info"];
        return `<tr><td class="mono" style="font-size:12px;color:${t.color}">${t.token}</td><td>${esc(c.summary)}</td><td><span class="tag" style="background:color-mix(in srgb,${t.color} 13%,transparent);color:${t.color}">${esc(sev)}</span></td><td style="color:var(--color-neutral-400)" class="mono" >${esc(c.source)}</td><td style="color:var(--color-neutral-300)">${esc(gap?.recommendation ?? "No open gap for this capability")}</td></tr>`;
    })
        .join("");
    const firstTrust = input.trust[0];
    const posture = firstTrust
        ? `<div class="card elev-sm" style="align-items:center;text-align:center;padding:18px 14px;gap:8px"><div class="card-kicker">Posture (claimed tier)</div><div style="width:88px;height:88px;border-radius:50%;border:1.5px solid var(--color-accent);display:grid;place-items:center"><span style="font-family:var(--font-heading);font-weight:500;font-size:30px">${firstTrust.trustScore.postureScore}</span></div><div class="card-meta" style="justify-content:center;text-align:center">${esc(qualifiedPostureLine(firstTrust.trustScore))}</div></div>`
        : `<div class="card elev-sm" style="padding:18px 14px"><div class="card-kicker">Posture</div><div class="card-meta">No attributed agents in this workspace yet.</div></div>`;
    const agents = input.identity
        .map((r) => `<span style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:var(--radius-md);border:1px solid var(--color-divider)" class="mono"><span style="font-size:11.5px">${esc(r.agentType)}</span><span style="color:var(--color-neutral-600);font-size:11px">${esc(r.agentId.slice(0, 12))}…</span></span>`)
        .join(" ");
    return `<section class="screen active" id="screen-review" style="flex:1;min-width:0;padding:26px 30px;flex-direction:column;gap:18px;overflow:auto">
  <div style="display:flex;align-items:flex-start;gap:16px"><div><h4>Agent Environment Review</h4><div style="font-size:12.5px;color:var(--color-neutral-500)">Generated ${esc(input.generatedAt)} · read-only, offline · Studio v${esc(input.toolVersion)}</div></div>
  <div style="margin-left:auto;display:flex;gap:8px"><button class="btn btn-ghost" id="export-json">Export JSON</button>${input.serve
        ? `<button class="btn btn-primary" id="rerun-live">Re-run review</button>`
        : // TEAM-ADR-027: a static artifact re-runs by opening this workspace in
            // the Governance Studio — never by pasting a terminal command.
            `<button class="btn btn-primary" data-copy="workspace-path">Copy workspace path</button><span id="workspace-path" hidden>${esc(input.workspaceRoot)}</span>`}</div></div>
  <div style="display:grid;grid-template-columns:1.3fr 1fr 1fr 1.3fr;gap:12px">
    <div class="card"><div class="card-kicker">Boundary gaps</div><div style="font-size:24px;font-weight:500;color:${report.totals.critical > 0 ? "#e28f88" : "#8fc7a2"}">${report.totals.boundaryGaps}</div><div class="card-meta">${report.totals.critical} critical · ${report.totals.high} high</div></div>
    <div class="card"><div class="card-kicker">Capabilities</div><div style="font-size:24px;font-weight:500">${report.totals.capabilities}</div><div class="card-meta">across ${input.identity.length} agent(s)</div></div>
    <div class="card"><div class="card-kicker">Findings</div><div style="font-size:24px;font-weight:500">${input.findings.length}</div><div class="card-meta">drift + lifecycle</div></div>
    <div class="card"><div class="card-kicker">Warnings</div><div style="font-size:24px;font-weight:500">${report.warnings.length}</div><div class="card-meta">incl. unreadable configs</div></div>
  </div>
  <div style="display:flex;gap:10px;align-items:center"><span style="font-size:10px;letter-spacing:.1em;color:var(--color-neutral-600)">AGENTS FOUND</span>${agents || '<span style="font-size:12px;color:var(--color-neutral-500)">none yet — open this workspace with a coding agent and re-run</span>'}</div>
  <div style="flex:1;min-height:0;display:flex;gap:18px;align-items:flex-start">
    <div style="flex:1;min-width:0"><table class="table"><thead><tr><th style="width:64px">Status</th><th>Capability</th><th style="width:84px">Severity</th><th style="width:170px">Source</th><th style="width:250px">Suggested control</th></tr></thead><tbody>${capRows || '<tr><td colspan="5" style="color:var(--color-neutral-500)">No agent capabilities detected in this workspace.</td></tr>'}</tbody></table></div>
    <div style="width:252px;flex:none;display:flex;flex-direction:column;gap:12px">${posture}
      <div class="card" style="gap:6px"><div class="card-kicker">Next step</div><div style="font-size:12.5px;color:var(--color-neutral-300);line-height:1.5">Turn this review into policy — build the draft on the Authorize screen, then save it as .deepsweep/policy.json.</div><button class="navitem btn-block" data-screen="authorize" style="color:var(--color-accent);border:1px solid var(--color-accent);justify-content:center">Build policy draft →</button></div>
      <div class="card" style="gap:4px"><div class="card-kicker">Assurance</div><div style="font-size:11px;color:var(--color-neutral-500);line-height:1.5">${esc(POSTURE_ASSURANCE_NOTE)}</div></div>
    </div>
  </div></section>`;
}
function authorizeScreen(input) {
    const gapRows = input.report.boundaryGaps
        .map((g, i) => {
        const t = SEV_TOKEN[g.severity] ?? SEV_TOKEN["info"];
        const effect = g.severity === "critical" ? "deny" : "require-approval";
        const suggestion = {
            effect,
            name: `studio-${i + 1}`,
            rationale: g.recommendation,
            principal: "*",
            action: "*",
            resource: "*",
        };
        return `<tr><td><div style="font-size:12.5px">${esc(g.summary)}</div><div style="font-size:11px;color:var(--color-neutral-600)">${g.relatedCapabilities.length} related capabilit${g.relatedCapabilities.length === 1 ? "y" : "ies"}</div></td><td class="mono" style="font-size:11px;color:${t.color}">${t.token} ${esc(g.severity)}</td><td><span class="tag ${effect === "deny" ? "" : "tag-outline"}" style="${effect === "deny" ? "background:rgba(226,143,136,.13);color:#e28f88;border:1px solid rgba(226,143,136,.35)" : ""}">${effect === "deny" ? "Deny" : "Approval"}</span></td><td><button class="btn btn-ghost" style="font-size:12px" data-suggest="${esc(JSON.stringify(suggestion))}">Add to draft →</button></td></tr>`;
    })
        .join("");
    return `<section class="screen" id="screen-authorize" style="flex:1;min-width:0;padding:26px 30px;flex-direction:column;gap:16px;overflow:auto">
  <div style="display:flex;align-items:flex-start;gap:16px"><div><h4>Authorization policy</h4><div style="font-size:12.5px;color:var(--color-neutral-500)">Layers loaded: ${esc(input.layersLoaded.join(" + ") || "none")} · mode ${esc(input.mode)} · docs/policy-format.md has the full grammar</div></div>
  <div style="margin-left:auto;display:flex;gap:8px"><button class="btn btn-primary" data-copy="policy-draft">Copy policy.json draft (<span id="draft-count">0</span> rules)</button></div></div>
  <div style="display:flex;align-items:center;gap:12px;padding:11px 16px;border-radius:var(--radius-md);background:var(--color-accent-900);border:1px solid var(--color-accent-800)"><span style="color:var(--color-accent-300)">${SHIELD}</span><div style="font-size:12.5px;color:#e7e5fe"><strong style="font-weight:600">Deny wins.</strong> The draft starts at require-approval for anything unmatched — lower layers can only tighten, never loosen.</div><span class="tag tag-accent" style="margin-left:auto">${esc(input.mode)} mode</span></div>
  <div style="flex:1;min-height:0;display:flex;gap:18px;align-items:flex-start">
    <div style="flex:1;min-width:0"><table class="table"><thead><tr><th>Open gap (from this review)</th><th style="width:120px">Severity</th><th style="width:110px">Suggested rule</th><th style="width:130px"></th></tr></thead><tbody>${gapRows || '<tr><td colspan="4" style="color:var(--color-neutral-500)">No open boundary gaps — nothing to tighten. Well-governed workspace.</td></tr>'}</tbody></table>
    <div style="display:flex;align-items:center;gap:18px;font-size:11.5px;color:var(--color-neutral-500);margin-top:10px"><span><span class="tag" style="background:rgba(143,199,162,.12);color:#8fc7a2;border:1px solid rgba(143,199,162,.3);padding:1px 8px">Allow</span> runs without asking</span><span><span class="tag tag-outline" style="padding:1px 8px">Approval</span> pauses for a human</span><span><span class="tag" style="background:rgba(226,143,136,.13);color:#e28f88;border:1px solid rgba(226,143,136,.35);padding:1px 8px">Deny</span> refused, explained, ledgered</span></div></div>
    <div style="width:340px;flex:none;display:flex;flex-direction:column;gap:10px"><div class="card elev-sm" style="gap:8px"><div class="card-kicker">Draft policy.json (ADR-021 format)</div><pre id="policy-draft" class="mono" style="margin:0;font-size:11px;line-height:1.5;white-space:pre-wrap;max-height:380px;overflow:auto;background:var(--color-bg);border-radius:var(--radius-sm);padding:10px"></pre><div style="font-size:11px;color:var(--color-neutral-500)">Save as <span class="mono">.deepsweep/policy.json</span>, then ask for decisions with <span class="mono">deepsweep authorize</span>. Start in observe mode; enforce when the ledger looks right.</div>${input.serve
        ? `<button class="btn btn-primary btn-block" id="apply-draft">Apply draft as policy.json</button><span id="apply-status" class="mono" style="font-size:10.5px;color:var(--color-neutral-500)"></span>`
        : ""}</div></div>
  </div></section>`;
}
function auditScreen(input) {
    const entries = input.ledger ?? [];
    const rows = [...entries]
        .reverse()
        .slice(0, 50)
        .map((e) => {
        const outcome = typeof e.payload["outcome"] === "string" ? String(e.payload["outcome"]) : "";
        const badge = outcome === "deny"
            ? '<span class="tag" style="background:rgba(226,143,136,.13);color:#e28f88">DENY</span>'
            : outcome === "allow"
                ? '<span class="tag" style="background:rgba(143,199,162,.12);color:#8fc7a2">ALLOW</span>'
                : outcome !== ""
                    ? `<span class="tag tag-accent">${esc(outcome.toUpperCase())}</span>`
                    : '<span class="tag tag-neutral">RUN</span>';
        const rule = typeof e.payload["rule"] === "string" ? String(e.payload["rule"]) : "—";
        return `<tr data-entry-kind="${esc(e.kind)}"><td class="mono" style="font-size:11.5px;color:var(--color-neutral-500)">#${e.seq}</td><td class="mono" style="font-size:11.5px;color:var(--color-neutral-500)">${esc(e.occurredAt)}</td><td class="mono" style="font-size:12px">${esc(e.kind)}</td><td>${badge}</td><td class="mono" style="font-size:11.5px;color:var(--color-neutral-500)">${esc(rule)}</td><td class="mono" style="font-size:10.5px;color:var(--color-neutral-600)">${esc(e.entryHash.slice(0, 8))}…</td></tr>`;
    })
        .join("");
    const decisions = entries.filter((e) => e.kind === "policy.decision").length;
    return `<section class="screen" id="screen-audit" style="flex:1;min-width:0;padding:26px 30px;flex-direction:column;gap:16px;overflow:auto">
  <div style="display:flex;align-items:flex-start;gap:16px"><div><h4>Audit ledger</h4><div style="font-size:12.5px;color:var(--color-neutral-500)">${entries.length} entries · hash-chained locally · on-disk chain <span class="mono" style="color:${input.chainVerified ? "#8fc7a2" : "#e28f88"}">${input.chainVerified ? "[PASS]" : "[FAIL]"}</span> · privacy: decision tuples are stored as hashes, never values</div></div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:8px"><span id="verify-result" class="mono" style="font-size:11.5px;color:var(--color-neutral-500)"></span><button class="btn btn-ghost" id="verify-chain">Verify embedded snapshot in-browser</button></div></div>
  <div style="display:flex;align-items:center;gap:12px"><span class="seg"><button class="seg-opt" data-audit-filter="all" aria-pressed="true">All</button><button class="seg-opt" data-audit-filter="review.run" aria-pressed="false">Reviews</button><button class="seg-opt" data-audit-filter="policy.decision" aria-pressed="false">Decisions</button></span><span class="tag tag-neutral">${decisions} decisions recorded</span><span style="margin-left:auto;font-size:11.5px;color:var(--color-neutral-600)">Showing newest ${Math.min(entries.length, 50)} of ${entries.length}</span></div>
  <div style="flex:1;min-height:0"><table class="table" style="font-size:13px"><thead><tr><th style="width:56px">Entry</th><th style="width:200px">Recorded</th><th style="width:150px">Kind</th><th style="width:110px">Outcome</th><th>Rule</th><th style="width:110px">Hash</th></tr></thead><tbody>${rows || `<tr><td colspan="6" style="color:${input.ledger === undefined ? "#e28f88" : "var(--color-neutral-500)"}">${input.ledger === undefined ? "[FAIL] Ledger on disk is malformed — appends are refused so the damage stays verifiable against your latest anchor." : "No entries yet — run a review or an authorize decision to start the chain."}</td></tr>`}</tbody></table></div></section>`;
}
function plansStrip() {
    // Decluttered (founder directive 2026-08-01): the 4-tile pricing grid is
    // gone. One subtle line; the ONLY pricing affordance is a plain external
    // link — the offline report must never depend on a hosted route to render.
    return `<div style="display:flex;gap:8px;justify-content:center;align-items:baseline;padding:10px 16px;border-top:1px solid var(--color-divider);font-size:11.5px;color:var(--color-neutral-500)">Free · you're here · <a href="${STUDIO_DOCS_URL}" target="_blank" rel="noopener noreferrer">See plans →</a></div>`;
}
function marqueeStrip() {
    // Soft right-to-left marquee of the agentic-IDE marks (vendored, static,
    // script-free). Track duplicated once for a seamless loop; pauses under
    // prefers-reduced-motion. Third-party marks: neutral partner treatment.
    const marks = AGENTIC_IDE_MARKS.map((m) => `<span class="mark">${m.svg}<span class="mark-label">${esc(m.label)}</span></span>`).join("");
    return `<div class="ease-in" style="animation-delay:.15s;padding:10px 0;border-top:1px solid var(--color-divider)">
  <div style="padding:0 16px 8px;font-size:10px;letter-spacing:.1em;color:var(--color-neutral-600)">ONE REVIEW GOVERNS EVERY AGENTIC IDE</div>
  <div class="marquee"><div class="marquee-track">${marks}${marks}</div></div>
</div>`;
}
function bigTechRow() {
    // Incumbent platforms: further down, subtle, static (no marquee) — they
    // ease in with the shell like every section.
    const marks = BIG_TECH_MARKS.map((m) => `<span class="mark">${m.svg}</span>`).join("");
    return `<div class="ease-in bigtech" style="animation-delay:.3s;display:flex;align-items:center;gap:26px;justify-content:center;padding:10px 16px 14px">
  <span style="font-size:10px;letter-spacing:.08em;color:var(--color-neutral-700)">RUNS WHEREVER YOUR STACK RUNS</span>${marks}
</div>`;
}
/** The one sanctioned render call for the Studio artifact (S1.9). */
export function renderStudio(input) {
    // Data island: the DEEP sanitizing walk (per-field caps, choke-point
    // strip set) then script-context escaping ONLY (esc()'s per-field 512
    // cap would truncate the JSON wholesale — caught in review; the island
    // is one big string, so field-level capping happens INSIDE the walk).
    const dataIsland = JSON.stringify(sanitizeJsonValue({
        report: input.report,
        ledger: input.ledger ?? [],
        serve: input.serve !== undefined,
    })).replace(/</g, "\\u003c");
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;${input.serve ? " connect-src 'self';" : ""}">
<title>DeepSweep Governance Studio — ${esc(input.workspace)}</title>
<style>${TOKENS_CSS}</style>
</head>
<body>
<div style="min-height:100vh;display:flex;flex-direction:column">
<div style="height:44px;flex:none;display:flex;align-items:center;padding:0 16px;position:relative;border-bottom:1px solid var(--color-divider)">
  <div style="display:flex;gap:8px"><span style="width:12px;height:12px;border-radius:50%;background:#ff5f57"></span><span style="width:12px;height:12px;border-radius:50%;background:#febc2e"></span><span style="width:12px;height:12px;border-radius:50%;background:#28c840"></span></div>
  <div style="position:absolute;left:280px;right:280px;text-align:center;font-size:13px;color:var(--color-neutral-500);pointer-events:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">DeepSweep Governance Studio — ${esc(input.workspace)}</div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:6px;font-size:11px;color:var(--color-neutral-500)">${SHIELD}Local-first · no code upload · this file works offline</div>
</div>
<div style="flex:1;display:flex;min-height:0" class="ease-in">
${sidebar(input, "review")}
${reviewScreen(input)}
${authorizeScreen(input)}
${auditScreen(input)}
</div>
${marqueeStrip()}
${plansStrip()}
${bigTechRow()}
</div>
<script type="application/json" id="studio-data">${dataIsland}</script>
<script>${STUDIO_JS}</script>
</body>
</html>`;
}
