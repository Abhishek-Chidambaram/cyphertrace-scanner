# vuln_scanner/models.py
from dataclasses import dataclass, field
from packaging.version import Version
# Remove SpecifierSet import for now
# from packaging.specifiers import SpecifierSet

@dataclass(frozen=True)
class Package:
    name: str
    version: Version
    ecosystem: str | None = None # Ecosystem is optional

@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    description: str
    # Store score as float, handle missing scores
    cvss_v3_score: float | None = None
    # Store vector string, handle missing
    cvss_v3_vector: str | None = None
    # Store raw affected configurations (e.g., CPEs) as JSON string for now
    configurations: str | None = None # Store raw JSON string

    # Add a property for severity based on CVSS v3 score
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
        else: # Score is 0.0 or None
            return "NONE" # Or UNKNOWN if None


@dataclass
class ScanResult:
     package: Package # Keep this as is
     vulnerability: Vulnerability # Keep this as is