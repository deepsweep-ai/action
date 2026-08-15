/**
 * Resolve the process exit code for a one-shot run under the active flags.
 * Deterministic. Under the default threshold a `--json` run reproduces the
 * pre-ADR-012 behavior exactly; a text-mode run now gates criticals too —
 * that asymmetry was a fail-open CI path, not a contract worth preserving.
 */
export function resolveExitCode(input, flags) {
    let code = 0;
    const raise = (c) => {
        if (c > code)
            code = c;
    };
    if (flags.failOnDrift) {
        // Trust-anchor divergence (exit 5): the pins were silently reset against
        // the current — possibly poisoned — snapshot, or the anchor is missing
        // where the pipeline asserted one. Keyed on disposition (reason), never
        // on the warning severity of the baseline.regenerated finding.
        if (input.baselineDisposition.status === "regenerated")
            raise(5);
        if (flags.requireBaseline && input.baselineDisposition.status === "created")
            raise(5);
        for (const f of input.findings) {
            // Kind-keyed gating (ADR-006): severity is presentation, not policy.
            if (f.kind === "baseline.tampered")
                raise(5);
            if (f.kind === "pin.drift" || f.kind === "pin.conflict")
                raise(4);
        }
    }
    // Severity-threshold gating (ADR-012): format-independent, deny-nothing
    // only by explicit `--fail-on=none`. Unknown/forged threshold values are
    // impossible here — the CLI refuses them as usage errors (exit 1) before
    // this function runs; the typed union documents the closed vocabulary.
    if (flags.failOn === "critical" && input.criticalGaps > 0)
        raise(2);
    if (flags.failOn === "high" && input.criticalGaps + input.highGaps > 0)
        raise(2);
    return code;
}
