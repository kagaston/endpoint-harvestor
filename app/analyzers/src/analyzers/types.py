from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str = ""
    url: str = ""


class Finding(BaseModel):
    title: str
    description: str
    severity: Severity
    source: str
    analyzer: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    timestamp: str = ""


class TimelineEntry(BaseModel):
    timestamp: str
    source: str
    event_type: str
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    analyzer_name: str
    findings: list[Finding] = Field(default_factory=list)
    timeline_entries: list[TimelineEntry] = Field(default_factory=list)
    summary: str = ""
    duration_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)
