from pydantic import BaseModel, Field

from analyzers.types import AnalysisResult, Finding
from collectors.types import CollectorResult


class ReportData(BaseModel):
    collector_results: list[CollectorResult] = Field(default_factory=list)
    analysis_results: list[AnalysisResult] = Field(default_factory=list)
    mitre_summary: dict = Field(default_factory=dict)
    case_id: str = ""
    examiner: str = ""
    system_info: dict = Field(default_factory=dict)

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for result in self.analysis_results:
            findings.extend(result.findings)
        return findings

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for finding in self.all_findings:
            grouped[finding.severity.value].append(finding)
        return grouped

    @property
    def risk_score(self) -> int:
        weights = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 1}
        score = 0
        for finding in self.all_findings:
            score += weights.get(finding.severity.value, 0)
        return min(score, 100)
