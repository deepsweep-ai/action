"""Turn DeepSweep CLI output into GitHub Action outputs, a job summary, a PR comment, and repaired SARIF."""

import argparse
import json
import os
import sys

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0", "info": "0.0"}
COMMENT_MARKER = "<!-- deepsweep-validation -->"
MAX_ROWS = 15


def severity(finding):
    return str(finding.get("severity", "")).lower()


def md_cell(text):
    return " ".join(str(text or "").replace("|", "\\|").replace("`", "'").split())


def meaning(finding):
    if finding.get("plain_english"):
        return md_cell(finding["plain_english"])
    # message can echo repository content, so keep it in a code span where links and mentions don't render
    return f"`{md_cell(finding.get('message') or finding.get('pattern_id'))}`"


def breaches(findings, fail_on):
    if fail_on == "none":
        return []
    threshold = SEVERITY_RANK[fail_on]
    return [f for f in findings if SEVERITY_RANK.get(severity(f), 0) >= threshold]


def status_label(findings, failing):
    if failing:
        return "[FAIL]"
    if findings:
        return "[WARN]"
    return "[PASS]"


def build_markdown(results, findings, failing, fail_on):
    counts = {s: sum(1 for f in findings if severity(f) == s) for s in ("critical", "high", "medium", "low")}
    lines = [
        COMMENT_MARKER,
        "## DeepSweep Security Validation",
        "",
        f"{status_label(findings, failing)} **Score: {results.get('score', 0)}/100 (Grade: {results.get('grade', '-')})**",
        "",
    ]

    if not findings:
        lines.append("No items to review. Your AI assistant configurations look good.")
    else:
        summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
        lines.append(f"### {len(findings)} item(s) to review ({summary})")
        lines.append("")
        if failing:
            lines.append(f"This check fails on `{fail_on}` severity or above.")
        elif fail_on == "none":
            lines.append("Report-only mode: this check does not fail on findings.")
        else:
            lines.append(f"Nothing at or above `{fail_on}` severity, so this check passes.")
        lines += [
            "",
            "| Severity | Location | What it means | How to address |",
            "|----------|----------|---------------|----------------|",
        ]
        ordered = sorted(findings, key=lambda f: -SEVERITY_RANK.get(severity(f), 0))
        for f in ordered[:MAX_ROWS]:
            location = f"`{md_cell(f.get('file'))}:{f.get('line', 1)}`"
            fix = md_cell(f.get("remediation"))
            lines.append(f"| {severity(f).upper()} | {location} | {meaning(f)} | {fix} |")
        if len(findings) > MAX_ROWS:
            lines.append("")
            lines.append(f"...and {len(findings) - MAX_ROWS} more. See the Security tab for full details.")

        prompts = [md_cell(f.get("fix_prompt")) for f in ordered if f.get("fix_prompt")]
        if prompts:
            lines += [
                "",
                "<details><summary>Address these with your AI assistant (copy and paste)</summary>",
                "",
                "```text",
                "Address these DeepSweep items in this repository:",
                *[f"{i}. {p}" for i, p in enumerate(dict.fromkeys(prompts), 1)],
                "```",
                "",
                "</details>",
            ]

    lines += ["", "---", "*Validated by [DeepSweep](https://deepsweep.ai). You don't need to understand the code to secure it.*"]
    return "\n".join(lines) + "\n"


def repair_sarif(path, findings):
    """Add security-severity (drives severity in GitHub code scanning) and dedupe rule ids."""
    with open(path) as fh:
        doc = json.load(fh)

    by_rule = {}
    for f in findings:
        rule_id = f.get("pattern_id")
        if rule_id and SEVERITY_RANK.get(severity(f), 0) >= SEVERITY_RANK.get(severity(by_rule.get(rule_id, {})), -1):
            by_rule[rule_id] = f

    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {}
        for rule in driver.get("rules", []):
            rules.setdefault(rule["id"], rule)
        for rule_id, rule in rules.items():
            f = by_rule.get(rule_id)
            if not f:
                continue
            props = rule.setdefault("properties", {})
            props["security-severity"] = SECURITY_SEVERITY.get(severity(f), "5.0")
            props.setdefault("tags", ["security"])
            if f.get("plain_english"):
                rule["fullDescription"] = {"text": f["plain_english"]}
            if f.get("remediation"):
                rule["help"] = {"text": f"How to address: {f['remediation']}"}
        driver["rules"] = list(rules.values())

    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)


def write_outputs(values):
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--sarif")
    parser.add_argument("--fail-on", default="high")
    parser.add_argument("--comment-file", required=True)
    args = parser.parse_args()

    fail_on = args.fail_on.strip().lower()
    if fail_on not in ("critical", "high", "medium", "low", "none"):
        print(f"::error::Invalid fail-on value '{args.fail_on}'. Use critical, high, medium, low, or none.")
        return 2

    with open(args.results) as fh:
        results = json.load(fh)
    findings = results.get("findings", [])
    failing = breaches(findings, fail_on)

    body = build_markdown(results, findings, bool(failing), fail_on)
    with open(args.comment_file, "w") as fh:
        fh.write(body)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(body)

    if args.sarif and os.path.exists(args.sarif):
        repair_sarif(args.sarif, findings)

    write_outputs({
        "score": results.get("score", 0),
        "grade": results.get("grade", "F"),
        "findings-count": len(findings),
        "critical-count": sum(1 for f in findings if severity(f) == "critical"),
        "failed": "true" if failing else "false",
    })

    for f in sorted(findings, key=lambda f: -SEVERITY_RANK.get(severity(f), 0)):
        level = "error" if f in failing else "warning"
        msg = md_cell(f.get("plain_english") or f.get("message") or f.get("pattern_id"))
        if f.get("remediation"):
            msg += f" How to address: {md_cell(f['remediation'])}"
        print(f"::{level} file={f.get('file')},line={f.get('line', 1)},title=DeepSweep {severity(f).upper()}::{msg}")

    if failing:
        print(f"[FAIL] {len(failing)} item(s) to review at or above '{fail_on}' severity")
    elif findings and fail_on == "none":
        print(f"[WARN] {len(findings)} item(s) to review (report-only mode)")
    elif findings:
        print(f"[WARN] {len(findings)} item(s) to review, none at or above '{fail_on}' severity")
    else:
        print("[PASS] No items to review")
    return 0


if __name__ == "__main__":
    sys.exit(main())
