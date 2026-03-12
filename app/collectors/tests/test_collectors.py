import pytest

from collectors import (
    COLLECTOR_REGISTRY,
    Artifact,
    ArtifactType,
    Collector,
    CollectorResult,
    get_collector,
    list_collectors,
)
from collectors.network import NetworkCollector
from collectors.processes import ProcessCollector
from collectors.system_info import SystemInfoCollector
from collectors.types import CollectorResult, ArtifactType


EXPECTED_COLLECTOR_NAMES = [
    "system_info",
    "processes",
    "network",
    "users",
    "persistence",
    "filesystem",
    "logs",
    "browser",
    "shell_history",
    "usb_devices",
    "installed_software",
    "kernel_modules",
    "firewall",
    "environment",
    "clipboard",
    "certificates",
]


class TestCollectorRegistry:
    def test_all_collectors_registered(self):
        assert len(COLLECTOR_REGISTRY) == 16

    def test_registry_contains_expected_names(self):
        for name in EXPECTED_COLLECTOR_NAMES:
            assert name in COLLECTOR_REGISTRY, f"Collector {name!r} missing from registry"

    def test_get_collector_returns_correct_type(self):
        collector = get_collector("system_info")
        assert isinstance(collector, SystemInfoCollector)

    def test_get_collector_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown collector"):
            get_collector("does_not_exist")

    def test_list_collectors_returns_all_names(self):
        names = list_collectors()
        assert len(names) == 16
        assert set(names) == set(EXPECTED_COLLECTOR_NAMES)


class TestCollectorProtocol:
    @pytest.fixture(params=list(COLLECTOR_REGISTRY.keys()))
    def collector_instance(self, request):
        return get_collector(request.param)

    def test_has_name(self, collector_instance):
        assert isinstance(collector_instance.name, str)
        assert len(collector_instance.name) > 0

    def test_has_display_name(self, collector_instance):
        assert isinstance(collector_instance.display_name, str)
        assert len(collector_instance.display_name) > 0

    def test_has_supported_platforms(self, collector_instance):
        platforms = collector_instance.supported_platforms
        assert isinstance(platforms, list)
        assert len(platforms) > 0
        for p in platforms:
            assert p in ("Windows", "Linux", "Darwin")


class TestSystemInfoCollector:
    @pytest.fixture()
    def result(self):
        collector = SystemInfoCollector()
        return collector.collect()

    def test_returns_collector_result(self, result):
        assert isinstance(result, CollectorResult)

    def test_collector_name(self, result):
        assert result.collector_name == "system_info"

    def test_has_artifacts(self, result):
        assert len(result.artifacts) >= 1

    def test_artifact_type_is_system_info(self, result):
        system_info_artifacts = [
            a for a in result.artifacts if a.artifact_type == ArtifactType.SYSTEM_INFO
        ]
        assert len(system_info_artifacts) >= 1

    def test_duration_positive(self, result):
        assert result.duration_ms > 0


class TestProcessCollector:
    @pytest.fixture()
    def result(self):
        collector = ProcessCollector()
        return collector.collect()

    def test_returns_collector_result(self, result):
        assert isinstance(result, CollectorResult)

    def test_has_at_least_one_process(self, result):
        process_artifacts = [
            a for a in result.artifacts if a.artifact_type == ArtifactType.PROCESS
        ]
        assert len(process_artifacts) >= 1

    def test_process_artifact_has_expected_fields(self, result):
        process_artifacts = [
            a for a in result.artifacts if a.artifact_type == ArtifactType.PROCESS
        ]
        sample = process_artifacts[0]
        assert "pid" in sample.data
        assert "name" in sample.data


class TestNetworkCollector:
    @pytest.fixture()
    def result(self):
        collector = NetworkCollector()
        return collector.collect()

    def test_returns_collector_result(self, result):
        assert isinstance(result, CollectorResult)

    def test_has_some_artifacts(self, result):
        assert len(result.artifacts) >= 0


class TestCollectorTypes:
    def test_artifact_type_has_expected_values(self):
        assert ArtifactType.SYSTEM_INFO.value == "system_info"
        assert ArtifactType.PROCESS.value == "process"
        assert ArtifactType.NETWORK_CONNECTION.value == "network_connection"
        assert ArtifactType.BROWSER_HISTORY.value == "browser_history"
        assert ArtifactType.FIREWALL_RULE.value == "firewall_rule"
        assert ArtifactType.CERTIFICATE.value == "certificate"

    def test_artifact_model_creation(self):
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            source="test",
            timestamp="2025-01-01T00:00:00Z",
            data={"pid": 1234, "name": "pytest"},
        )
        assert artifact.artifact_type == ArtifactType.PROCESS
        assert artifact.source == "test"
        assert artifact.data["pid"] == 1234

    def test_artifact_model_defaults(self):
        artifact = Artifact(artifact_type=ArtifactType.SYSTEM_INFO)
        assert artifact.source == ""
        assert artifact.timestamp == ""
        assert artifact.data == {}

    def test_collector_result_model_creation(self):
        result = CollectorResult(
            collector_name="test_collector",
            platform="Darwin",
            timestamp="2025-01-01T00:00:00Z",
            artifacts=[
                Artifact(artifact_type=ArtifactType.PROCESS, data={"pid": 1}),
            ],
            duration_ms=42.5,
        )
        assert result.collector_name == "test_collector"
        assert result.platform == "Darwin"
        assert len(result.artifacts) == 1
        assert result.duration_ms == 42.5

    def test_collector_result_defaults(self):
        result = CollectorResult(
            collector_name="x",
            platform="Linux",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert result.artifacts == []
        assert result.errors == []
        assert result.duration_ms == 0.0
