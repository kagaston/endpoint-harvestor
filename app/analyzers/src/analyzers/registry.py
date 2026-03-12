from analyzers.ioc_scanner import IOCScanner
from analyzers.yara_scanner import YARAScanner
from analyzers.sigma_scanner import SigmaScanner
from analyzers.anomaly_detector import AnomalyDetector
from analyzers.timeline import TimelineGenerator
from analyzers.mitre_attack import MitreAttackMapper
from analyzers.protocol import Analyzer


ANALYZER_REGISTRY: dict[str, type] = {
    "ioc_scanner": IOCScanner,
    "yara_scanner": YARAScanner,
    "sigma_scanner": SigmaScanner,
    "anomaly_detector": AnomalyDetector,
    "timeline": TimelineGenerator,
    "mitre_attack": MitreAttackMapper,
}


def get_analyzer(name: str, **kwargs) -> Analyzer:
    cls = ANALYZER_REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"Unknown analyzer: {name!r}. Available: {list(ANALYZER_REGISTRY)}")
    return cls(**kwargs)


def list_analyzers() -> list[str]:
    return list(ANALYZER_REGISTRY.keys())
