"""Data models for KL-DeepScan."""
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Lower rank = more severe; used for sorting findings.
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # one of SEVERITIES
    url: str
    evidence: str
    description: str
    remediation: str
    cwe: str = ""
