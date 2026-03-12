import csv
import json

import pytest

from analyzers.types import (
    AnalysisResult,
    Finding,
    MitreTechnique,
    Severity,
    TimelineEntry,
)
from collectors.types import Artifact, ArtifactType, CollectorResult
from reporters import REPORTER_REGISTRY, get_reporter, list_reporters
from reporters.console_report import ConsoleReporter
from reporters.csv_report import CSVReporter
from reporters.html_report import HTMLReporter
from reporters.json_report import JSONReporter
from reporters.types import ReportData


def _make_report_data() -> ReportData:
    collector_result = CollectorResult(
        collector_name="system_info",
        platform="Darwin",
        timestamp="2025-01-01T00:00:00Z",
        artifacts=[
            Artifact(
                artifact_type=ArtifactType.SYSTEM_INFO,
                data={"hostname": "test-host", "os": "Darwin"},
            ),
        ],
    )

    finding = Finding(
        title="Test Finding",
        description="A test finding",
        severity=Severity.HIGH,
        source="test",
        analyzer="anomaly_detector",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T1059",
                name="Command Interpreter",
                tactic="Execution",
            ),
        ],
    )

    timeline_entry = TimelineEntry(
        timestamp="2025-01-01T00:00:00Z",
        source="test",
        event_type="process",
        description="Test process",
    )

    analysis_result = AnalysisResult(
        analyzer_name="anomaly_detector",
        findings=[finding],
        timeline_entries=[timeline_entry],
    )

    return ReportData(
        collector_results=[collector_result],
        analysis_results=[analysis_result],
        mitre_summary={
            "technique_count": 1,
            "techniques": {
                "T1059": {
                    "technique": {
                        "technique_id": "T1059",
                        "name": "Command Interpreter",
                        "tactic": "Execution",
                        "url": "",
                    },
                    "finding_count": 1,
                    "max_severity": "high",
                },
            },
            "tactics": {"Execution": ["T1059"]},
            "overall_severity": "high",
            "navigator_layer": {},
        },
        case_id="TEST-001",
        examiner="Test Examiner",
        system_info={"hostname": "test-host", "os": "Darwin"},
    )


class TestReporterRegistry:
    def test_all_reporters_registered(self):
        assert len(REPORTER_REGISTRY) == 4

    def test_expected_reporter_names(self):
        for name in ("console", "html", "json", "csv"):
            assert name in REPORTER_REGISTRY

    def test_get_reporter_returns_correct_types(self):
        assert isinstance(get_reporter("console"), ConsoleReporter)
        assert isinstance(get_reporter("html"), HTMLReporter)
        assert isinstance(get_reporter("json"), JSONReporter)
        assert isinstance(get_reporter("csv"), CSVReporter)

    def test_get_reporter_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown reporter"):
            get_reporter("nonexistent")

    def test_list_reporters(self):
        names = list_reporters()
        assert set(names) == {"console", "html", "json", "csv"}


class TestReportData:
    @pytest.fixture()
    def data(self):
        return _make_report_data()

    def test_risk_score_is_positive(self, data):
        assert data.risk_score > 0

    def test_risk_score_high_finding_weight(self, data):
        assert data.risk_score == 20

    def test_findings_by_severity_groups_correctly(self, data):
        grouped = data.findings_by_severity
        assert len(grouped["high"]) == 1
        assert len(grouped["critical"]) == 0
        assert len(grouped["medium"]) == 0
        assert len(grouped["low"]) == 0
        assert len(grouped["info"]) == 0

    def test_all_findings_returns_all(self, data):
        findings = data.all_findings
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"

    def test_risk_score_capped_at_100(self):
        findings = [
            Finding(
                title=f"Finding {i}",
                description="desc",
                severity=Severity.CRITICAL,
                source="test",
                analyzer="test",
            )
            for i in range(10)
        ]
        analysis = AnalysisResult(analyzer_name="test", findings=findings)
        data = ReportData(analysis_results=[analysis])
        assert data.risk_score == 100


class TestJSONReporter:
    def test_generates_report_json(self, tmp_path):
        reporter = JSONReporter()
        data = _make_report_data()
        result_path = reporter.generate(data, tmp_path)

        assert result_path.name == "report.json"
        assert result_path.exists()

    def test_report_has_expected_keys(self, tmp_path):
        reporter = JSONReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        with open(tmp_path / "report.json") as f:
            report = json.load(f)

        expected_keys = {
            "meta", "system_info", "risk_score",
            "findings_summary", "findings", "mitre_attack",
            "collectors", "analysis",
        }
        assert expected_keys <= set(report.keys())

    def test_report_meta_contains_case_id(self, tmp_path):
        reporter = JSONReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        with open(tmp_path / "report.json") as f:
            report = json.load(f)

        assert report["meta"]["case_id"] == "TEST-001"
        assert report["meta"]["examiner"] == "Test Examiner"

    def test_report_risk_score_matches(self, tmp_path):
        reporter = JSONReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        with open(tmp_path / "report.json") as f:
            report = json.load(f)

        assert report["risk_score"] == data.risk_score


class TestCSVReporter:
    def test_generates_timeline_and_findings_csv(self, tmp_path):
        reporter = CSVReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        assert (tmp_path / "timeline.csv").exists()
        assert (tmp_path / "findings.csv").exists()

    def test_timeline_csv_has_header_and_data(self, tmp_path):
        reporter = CSVReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        with open(tmp_path / "timeline.csv") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = list(reader)

        assert "timestamp" in header
        assert "description" in header
        assert len(rows) == 1

    def test_findings_csv_has_header_and_data(self, tmp_path):
        reporter = CSVReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        with open(tmp_path / "findings.csv") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = list(reader)

        assert "severity" in header
        assert "title" in header
        assert len(rows) == 1


class TestHTMLReporter:
    def test_generates_report_html(self, tmp_path):
        reporter = HTMLReporter()
        data = _make_report_data()
        result_path = reporter.generate(data, tmp_path)

        assert result_path.name == "report.html"
        assert result_path.exists()

    def test_html_contains_expected_strings(self, tmp_path):
        reporter = HTMLReporter()
        data = _make_report_data()
        reporter.generate(data, tmp_path)

        html = (tmp_path / "report.html").read_text()
        assert "IntrusionInspector" in html
        assert "test-host" in html
        assert "TEST-001" in html


class TestConsoleReporter:
    def test_generate_does_not_crash(self, tmp_path):
        reporter = ConsoleReporter()
        data = _make_report_data()
        result = reporter.generate(data, tmp_path)
        assert result == tmp_path
