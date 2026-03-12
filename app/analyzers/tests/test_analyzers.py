import pytest
import yaml
from pathlib import Path

from analyzers import (
    ANALYZER_REGISTRY,
    AnalysisResult,
    Finding,
    MitreTechnique,
    Severity,
    TimelineEntry,
    get_analyzer,
    list_analyzers,
)
from analyzers.anomaly_detector import AnomalyDetector
from analyzers.ioc_scanner import IOCScanner
from analyzers.mitre_attack import MitreAttackMapper
from analyzers.timeline import TimelineGenerator
from collectors.types import Artifact, ArtifactType, CollectorResult


EXPECTED_ANALYZER_NAMES = [
    "ioc_scanner",
    "yara_scanner",
    "sigma_scanner",
    "anomaly_detector",
    "timeline",
    "mitre_attack",
]


def _make_collector_result(
    collector_name: str = "fake",
    platform: str = "Darwin",
    artifacts: list[Artifact] | None = None,
) -> CollectorResult:
    return CollectorResult(
        collector_name=collector_name,
        platform=platform,
        timestamp="2025-06-15T12:00:00Z",
        artifacts=artifacts or [],
    )


class TestAnalyzerRegistry:
    def test_all_analyzers_registered(self):
        assert len(ANALYZER_REGISTRY) == 6

    def test_registry_contains_expected_names(self):
        for name in EXPECTED_ANALYZER_NAMES:
            assert name in ANALYZER_REGISTRY, f"Analyzer {name!r} missing from registry"

    def test_get_analyzer_returns_instance(self):
        analyzer = get_analyzer("anomaly_detector")
        assert isinstance(analyzer, AnomalyDetector)

    def test_get_analyzer_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown analyzer"):
            get_analyzer("nonexistent")

    def test_list_analyzers_returns_all_names(self):
        names = list_analyzers()
        assert len(names) == 6
        assert set(names) == set(EXPECTED_ANALYZER_NAMES)


class TestAnomalyDetector:
    @pytest.fixture()
    def detector(self):
        return AnomalyDetector()

    def test_suspicious_parent_child_produces_finding(self, detector):
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={
                "pid": 4444,
                "name": "cmd.exe",
                "parent_name": "winword.exe",
                "exe": "C:\\Windows\\System32\\cmd.exe",
                "cmdline": "cmd.exe /c whoami",
            },
        )
        result = _make_collector_result(
            collector_name="processes",
            platform="Windows",
            artifacts=[artifact],
        )
        analysis = detector.analyze([result])

        assert isinstance(analysis, AnalysisResult)
        assert analysis.analyzer_name == "anomaly_detector"
        parent_child_findings = [
            f for f in analysis.findings if "Parent-Child" in f.title
        ]
        assert len(parent_child_findings) >= 1
        finding = parent_child_findings[0]
        assert finding.severity == Severity.HIGH
        assert len(finding.mitre_techniques) >= 1

    def test_temp_execution_produces_finding(self, detector):
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={
                "pid": 5555,
                "name": "malware.exe",
                "exe": "/tmp/malware.exe",
                "cmdline": "/tmp/malware.exe",
            },
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = detector.analyze([result])

        temp_findings = [f for f in analysis.findings if "temp directory" in f.title]
        assert len(temp_findings) >= 1

    def test_no_findings_for_benign_process(self, detector):
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={
                "pid": 1,
                "name": "init",
                "exe": "/sbin/init",
                "cmdline": "/sbin/init",
            },
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = detector.analyze([result])
        assert len(analysis.findings) == 0


class TestTimelineGenerator:
    @pytest.fixture()
    def generator(self):
        return TimelineGenerator()

    def test_produces_timeline_entries(self, generator):
        artifacts = [
            Artifact(
                artifact_type=ArtifactType.PROCESS,
                source="processes",
                timestamp=f"2025-06-15T12:0{i}:00Z",
                data={"pid": i, "name": f"proc_{i}", "cmdline": ""},
            )
            for i in range(3)
        ]
        result = _make_collector_result(artifacts=artifacts)
        analysis = generator.analyze([result])

        assert isinstance(analysis, AnalysisResult)
        assert analysis.analyzer_name == "timeline"
        assert len(analysis.timeline_entries) == 3

    def test_entries_sorted_by_timestamp(self, generator):
        artifacts = [
            Artifact(
                artifact_type=ArtifactType.PROCESS,
                source="processes",
                timestamp="2025-06-15T12:03:00Z",
                data={"pid": 3, "name": "late", "cmdline": ""},
            ),
            Artifact(
                artifact_type=ArtifactType.PROCESS,
                source="processes",
                timestamp="2025-06-15T12:01:00Z",
                data={"pid": 1, "name": "early", "cmdline": ""},
            ),
            Artifact(
                artifact_type=ArtifactType.PROCESS,
                source="processes",
                timestamp="2025-06-15T12:02:00Z",
                data={"pid": 2, "name": "mid", "cmdline": ""},
            ),
        ]
        result = _make_collector_result(artifacts=artifacts)
        analysis = generator.analyze([result])

        timestamps = [e.timestamp for e in analysis.timeline_entries]
        assert timestamps == sorted(timestamps)

    def test_empty_input_produces_empty_timeline(self, generator):
        result = _make_collector_result(artifacts=[])
        analysis = generator.analyze([result])
        assert len(analysis.timeline_entries) == 0


class TestIOCScanner:
    @pytest.fixture()
    def ioc_file(self, tmp_path):
        ioc_data = {
            "iocs": [
                {
                    "type": "process_name",
                    "value": "evil_miner",
                    "description": "Known cryptominer process",
                    "severity": "high",
                    "mitre_technique": "T1496",
                    "mitre_name": "Resource Hijacking",
                },
                {
                    "type": "ip",
                    "value": "10.66.66.66",
                    "description": "Known C2 server",
                    "severity": "critical",
                },
            ],
        }
        ioc_path = tmp_path / "test_iocs.yaml"
        ioc_path.write_text(yaml.dump(ioc_data))
        return ioc_path

    def test_detects_matching_process_name(self, ioc_file):
        scanner = IOCScanner(ioc_paths=[str(ioc_file)])

        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={"pid": 999, "name": "evil_miner", "exe": "/opt/evil_miner"},
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = scanner.analyze([result])

        assert len(analysis.findings) >= 1
        match = analysis.findings[0]
        assert "evil_miner" in match.title
        assert match.severity == Severity.HIGH

    def test_detects_matching_ip(self, ioc_file):
        scanner = IOCScanner(ioc_paths=[str(ioc_file)])

        artifact = Artifact(
            artifact_type=ArtifactType.NETWORK_CONNECTION,
            source="network",
            timestamp="2025-06-15T12:00:00Z",
            data={"remote_address": "10.66.66.66", "remote_port": 443},
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = scanner.analyze([result])

        assert len(analysis.findings) >= 1
        assert analysis.findings[0].severity == Severity.CRITICAL

    def test_no_match_returns_zero_findings(self, ioc_file):
        scanner = IOCScanner(ioc_paths=[str(ioc_file)])

        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={"pid": 1, "name": "python3", "exe": "/usr/bin/python3"},
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = scanner.analyze([result])
        assert len(analysis.findings) == 0

    def test_no_iocs_loaded_skips_scan(self):
        scanner = IOCScanner(ioc_paths=[])
        result = _make_collector_result(artifacts=[])
        analysis = scanner.analyze([result])
        assert "No IOC definitions loaded" in analysis.summary

    def test_ioc_directory_loading(self, tmp_path):
        ioc_data = {
            "iocs": [
                {"type": "process_name", "value": "dirtest", "severity": "low"},
            ],
        }
        (tmp_path / "ioc1.yaml").write_text(yaml.dump(ioc_data))

        scanner = IOCScanner(ioc_paths=[str(tmp_path)])
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="processes",
            timestamp="2025-06-15T12:00:00Z",
            data={"name": "dirtest"},
        )
        result = _make_collector_result(artifacts=[artifact])
        analysis = scanner.analyze([result])
        assert len(analysis.findings) >= 1


class TestMitreAttackMapper:
    @pytest.fixture()
    def mapper(self):
        return MitreAttackMapper()

    def test_analyze_returns_empty_result(self, mapper):
        result = _make_collector_result()
        analysis = mapper.analyze([result])
        assert isinstance(analysis, AnalysisResult)
        assert analysis.analyzer_name == "mitre_attack"

    def test_aggregate_produces_expected_keys(self, mapper):
        findings_with_mitre = [
            Finding(
                title="Test finding 1",
                description="desc",
                severity=Severity.HIGH,
                source="processes",
                analyzer="anomaly_detector",
                mitre_techniques=[
                    MitreTechnique(
                        technique_id="T1055",
                        name="Process Injection",
                        tactic="defense-evasion",
                    ),
                ],
            ),
            Finding(
                title="Test finding 2",
                description="desc",
                severity=Severity.MEDIUM,
                source="persistence",
                analyzer="anomaly_detector",
                mitre_techniques=[
                    MitreTechnique(
                        technique_id="T1053",
                        name="Scheduled Task/Job",
                        tactic="persistence",
                    ),
                ],
            ),
        ]
        analysis_result = AnalysisResult(
            analyzer_name="anomaly_detector",
            findings=findings_with_mitre,
        )
        summary = mapper.aggregate([analysis_result])

        assert "technique_count" in summary
        assert summary["technique_count"] == 2
        assert "tactics" in summary
        assert "navigator_layer" in summary

    def test_aggregate_navigator_layer_structure(self, mapper):
        finding = Finding(
            title="Test",
            description="desc",
            severity=Severity.CRITICAL,
            source="test",
            analyzer="test",
            mitre_techniques=[
                MitreTechnique(technique_id="T1218", name="System Binary Proxy Execution"),
            ],
        )
        analysis_result = AnalysisResult(
            analyzer_name="test",
            findings=[finding],
        )
        summary = mapper.aggregate([analysis_result])
        layer = summary["navigator_layer"]

        assert layer["domain"] == "enterprise-attack"
        assert isinstance(layer["techniques"], list)
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["techniqueID"] == "T1218"

    def test_aggregate_empty_input(self, mapper):
        summary = mapper.aggregate([])
        assert summary["technique_count"] == 0
        assert summary["techniques"] == {}
        assert summary["tactics"] == {}


class TestAnalyzerTypes:
    def test_severity_enum_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_finding_model_creation(self):
        finding = Finding(
            title="Test Finding",
            description="A test finding",
            severity=Severity.HIGH,
            source="test_collector",
            analyzer="test_analyzer",
            evidence={"key": "value"},
            mitre_techniques=[
                MitreTechnique(technique_id="T1055", name="Process Injection"),
            ],
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert len(finding.mitre_techniques) == 1

    def test_finding_model_defaults(self):
        finding = Finding(
            title="Minimal",
            description="desc",
            severity=Severity.INFO,
            source="s",
            analyzer="a",
        )
        assert finding.evidence == {}
        assert finding.mitre_techniques == []
        assert finding.timestamp == ""

    def test_analysis_result_model_creation(self):
        result = AnalysisResult(
            analyzer_name="test",
            findings=[
                Finding(
                    title="f",
                    description="d",
                    severity=Severity.LOW,
                    source="s",
                    analyzer="a",
                ),
            ],
            summary="One finding",
            duration_ms=10.0,
        )
        assert result.analyzer_name == "test"
        assert len(result.findings) == 1
        assert result.summary == "One finding"

    def test_analysis_result_defaults(self):
        result = AnalysisResult(analyzer_name="x")
        assert result.findings == []
        assert result.timeline_entries == []
        assert result.summary == ""
        assert result.duration_ms == 0.0
        assert result.errors == []
