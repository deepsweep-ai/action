"""
SARIF 2.1.0 output formatter for GitHub Security integration.

Usage:
    deepsweep validate . --format sarif > results.sarif
"""

import json
from typing import List, Dict, Any
from datetime import datetime, timezone
from ..core.types import ValidationResult, Finding


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def generate_sarif(result: ValidationResult) -> Dict[str, Any]:
    """
    Generate SARIF 2.1.0 compliant output.

    Args:
        result: ValidationResult from the validator

    Returns:
        SARIF document as dictionary
    """

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DeepSweep",
                        "version": result.version,
                        "informationUri": "https://deepsweep.ai",
                        "rules": _generate_rules(result.findings),
                    }
                },
                "results": _generate_results(result.findings),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def _generate_rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Generate SARIF rule definitions from findings."""

    # Dedupe rules by pattern_id
    seen_rules = {}

    for finding in findings:
        if finding.pattern_id in seen_rules:
            continue

        rule = {
            "id": finding.pattern_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.description
            },
            "helpUri": f"https://docs.deepsweep.ai/patterns/{finding.pattern_id}",
            "properties": {
                "security-severity": _severity_to_score(finding.severity),
            }
        }

        # Add CVE references if present
        if finding.cve_ids:
            rule["properties"]["tags"] = finding.cve_ids

        seen_rules[finding.pattern_id] = rule

    return list(seen_rules.values())


def _generate_results(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Generate SARIF results from findings."""

    results = []

    for finding in findings:
        result = {
            "ruleId": finding.pattern_id,
            "level": _severity_to_level(finding.severity),
            "message": {
                "text": finding.plain_english or finding.description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": finding.column or 1,
                        }
                    }
                }
            ],
        }

        # Add fix suggestion if available
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {
                        "text": f"How to address: {finding.remediation}"
                    }
                }
            ]

        results.append(result)

    return results


def _severity_to_level(severity: str) -> str:
    """Map DeepSweep severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "warning")


def _severity_to_score(severity: str) -> str:
    """Map DeepSweep severity to SARIF security-severity score."""
    # SARIF uses 0.0-10.0 scale
    mapping = {
        "critical": "9.0",
        "high": "7.0",
        "medium": "4.0",
        "low": "2.0",
        "info": "1.0",
    }
    return mapping.get(severity.lower(), "5.0")


def format_sarif(result: ValidationResult) -> str:
    """
    Format validation result as SARIF JSON string.

    Args:
        result: ValidationResult from the validator

    Returns:
        SARIF JSON string
    """
    sarif_doc = generate_sarif(result)
    return json.dumps(sarif_doc, indent=2)
