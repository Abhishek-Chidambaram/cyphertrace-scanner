# vuln_scanner/models.py
from dataclasses import dataclass, field
from packaging.version import Version # Keep this for type hinting and potential use
from typing import Optional, Union    # Import Union

@dataclass(frozen=True)
class Package:
    name: str
    # Allow version to be a parsed Version object or a raw string if parsing fails
    version: Union[Version, str] 
    ecosystem: Optional[str] = None

@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    description: str
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    configurations: str | None = None # Store raw JSON string

    @property
    def severity(self) -> str:
        if self.cvss_v3_score is None:
            return "UNKNOWN"
        elif self.cvss_v3_score >= 9.0:
            return "CRITICAL"
        elif self.cvss_v3_score >= 7.0:
            return "HIGH"
        elif self.cvss_v3_score >= 4.0:
            return "MEDIUM"
        elif self.cvss_v3_score > 0.0:
            return "LOW"
        else: # Score is 0.0
            return "NONE"

@dataclass
class ScanResult:
    package: Package 
    vulnerability: Vulnerability