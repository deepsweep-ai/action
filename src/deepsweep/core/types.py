"""Core types for DeepSweep validation results."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """A single validation finding."""

    pattern_id: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    column: Optional[int] = None
    plain_english: Optional[str] = None
    remediation: Optional[str] = None
    cve_ids: Optional[List[str]] = None


@dataclass
class ValidationResult:
    """Complete validation result."""

    version: str
    score: int
    grade: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def findings_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)
