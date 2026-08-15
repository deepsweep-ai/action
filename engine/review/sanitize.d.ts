/**
 * S1.9 — the SINGLE sanitization choke point for every rendered surface.
 *
 * Every place a workspace-derived string reaches a terminal, file, or stream
 * (text report, watch header/status lines, JSONL drift events, error
 * messages, future md/html artifacts) sanitizes HERE and nowhere else.
 * Rationale (sprint-02 retro, kb/team-norms.md norm 9): the same P1
 * injection bug class shipped twice because fixes were applied per surface —
 * this module fixes the CLASS. Per-surface length caps are parameters of
 * this one implementation, never separate implementations.
 *
 * Strip set (shared by all surfaces): C0 controls (U+0000–U+001F), DEL
 * (U+007F), C1 controls (U+0080–U+009F) — no ANSI/ESC/CSI sequences can
 * reach a terminal to erase or forge report lines — plus Unicode bidi
 * controls (U+202A–U+202E, U+2066–U+2069) against trojan-source visual
 * reordering. Workspace content is data, never terminal instructions.
 *
 * BINDING (architect ruling, sprint-03 ADR gate): the event surface's
 * sanitized output bytes are ADR-004 contract — same 512-char cap, same
 * strip set, same ellipsis truncation as the pre-S1.9 implementation in
 * events.ts. eventIds are content-derived (SHA-256 over sanitized fields),
 * so ONE changed output byte is a breaking schema rev. A byte-exact
 * regression test (tests/sanitize.test.ts, "ADR-004 BINDING") guards this.
 *
 * By-construction enforcement choice (S1.9 AC3): a static GUARD TEST
 * (tests/sanitize.test.ts, extending the existing src/-scope-guard walk in
 * tests/fixtures.test.ts) rather than a branded/opaque string type. A brand
 * on the sanitizer's return type cannot stop `${raw}` template-literal
 * interpolation — TypeScript widens the brand away at the exact point that
 * matters — so the type would compile-check nothing and only LOOK safe.
 * The guard test is boring and actually binding: (a) this strip set may be
 * defined only in this file (no shadow implementations — how the bug class
 * shipped twice), and (b) any src/ module that writes to stdout/stderr must
 * import this module or a sanctioned render module. A new surface that
 * bypasses the choke point fails the suite.
 */
/** Max characters any single interpolated field may occupy in human renders. */
export declare const MAX_RENDERED_FIELD_LENGTH = 200;
/** Max characters per JSONL event field (ADR-004 contract — see above). */
export declare const MAX_EVENT_FIELD_LENGTH = 512;
/**
 * Human-render surfaces (text report, watch header/status, error messages):
 * strip set + 200-char cap, ellipsis-marked truncation.
 */
export declare function sanitizeField(value: string): string;
/**
 * Human-render variant for drift-finding explanations (QA defect D2,
 * generalized by S1.12 to every finding/warning kind whose actionable
 * remediation lives at the END of its copy — pin.drift "re-pin via
 * --update-baseline", identity.regenerated "re-review before continuing to
 * trust attribution…", the pin warnings, the trust decomposition's
 * honest-limit ending). Tail truncation destroyed exactly the part the user
 * needs. Middle-truncates instead: same strip set, same total budget (200 +
 * one ellipsis), but the ellipsis replaces the middle so both the lead-in
 * and the remediation ending survive.
 *
 * HUMAN RENDER ONLY (architect guardrail, sprint-03 ADR gate): the event
 * surface's tail truncation is ADR-004 contract (sanitizeEventField) and is
 * not affected by this variant. sanitizeField semantics for existing callers
 * are unchanged.
 */
export declare function sanitizeFieldKeepEnding(value: string): string;
/**
 * Event surface (JSONL drift events, ADR-004): strip set + 512-char cap,
 * ellipsis-marked truncation — the entity hash stays the authoritative
 * reference for truncated content. Output bytes are contract (see BINDING
 * note above); behavior is byte-identical to the pre-S1.9 events.ts
 * implementation.
 */
export declare function sanitizeEventField(value: string): string;
/**
 * Machine-render surface (the `--json` report dump) — QA defect D3: the raw
 * ReviewReport object reached stdout unsanitized; JSON.stringify escapes C0
 * but passes C1 (e.g. U+009B CSI) and bidi controls through RAW, and `jq -r`
 * / CI log viewers execute them.
 *
 * Deep-sanitizes every string leaf (and key) of a JSON-serializable plain
 * value with the EVENT-surface parameters. Cap decision: machine-readable
 * surfaces share MAX_EVENT_FIELD_LENGTH (512) — same budget consumers already
 * accept for ADR-004 drift events, and content hashes remain the
 * authoritative reference for truncated content; the 200 cap stays
 * human-render only. Idempotent by construction (strip and ellipsis-cap are
 * both fixed points), so ADR-004 event objects pass through byte-unchanged —
 * regression-tested, and the CLI additionally keeps the drift array OUTSIDE
 * this walk (see renderJsonReport) so event bytes are untouched by
 * construction as well.
 *
 * Contract: plain JSON-serializable data only (string/number/boolean/null/
 * array/object) — exactly what our report surfaces are.
 */
export declare function sanitizeJsonValue<T>(value: T): T;
