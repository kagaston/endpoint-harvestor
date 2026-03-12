import json
import time
from pathlib import Path

from analyzers.anomaly_detector import AnomalyDetector
from analyzers.ioc_scanner import IOCScanner
from analyzers.mitre_attack import MitreAttackMapper
from analyzers.sigma_scanner import SigmaScanner
from analyzers.timeline import TimelineGenerator
from analyzers.types import AnalysisResult
from analyzers.yara_scanner import YARAScanner
from collectors.registry import get_collector, COLLECTOR_REGISTRY
from collectors.types import CollectorResult, ArtifactType
from engine.platform_detect import get_platform, filter_by_platform
from engine.profile_loader import CollectionProfile, load_profile
from errors import CollectorError, handle_error
from evidence.integrity import EvidenceIntegrity
from evidence.secure_output import create_secure_package
from logger import get_logger
from reporters.registry import get_reporter
from reporters.types import ReportData
from utils.privileges import require_admin

log = get_logger("engine.orchestrator")


class Orchestrator:
    def __init__(
        self,
        output_dir: str | Path,
        profile: str | CollectionProfile = "standard",
        case_id: str = "",
        examiner: str = "",
    ):
        self.output_dir = Path(output_dir)
        self.case_id = case_id
        self.examiner = examiner

        if isinstance(profile, str):
            self.profile = load_profile(profile)
        else:
            self.profile = profile

        self.collector_results: list[CollectorResult] = []
        self.analysis_results: list[AnalysisResult] = []
        self.mitre_summary: dict = {}
        self.evidence = EvidenceIntegrity(self.output_dir, case_id=case_id, examiner=examiner)

    def collect(self) -> list[CollectorResult]:
        require_admin("artifact collection")
        self.evidence.start_collection()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        current_platform = get_platform()
        log.info("Starting collection with profile: %s on %s", self.profile.name, current_platform)

        for collector_name in self.profile.collectors:
            if collector_name not in COLLECTOR_REGISTRY:
                log.warning("Unknown collector in profile: %s — skipping", collector_name)
                continue

            cls = COLLECTOR_REGISTRY[collector_name]
            test_instance = cls.__new__(cls)
            if hasattr(test_instance, "supported_platforms"):
                try:
                    platforms = test_instance.supported_platforms
                    if current_platform not in platforms:
                        log.debug("Skipping %s — not supported on %s", collector_name, current_platform)
                        continue
                except Exception:
                    pass

            kwargs = {}
            if collector_name in ("processes",) and self.profile.hash_files:
                kwargs["hash_executables"] = True
            elif collector_name in ("filesystem",):
                kwargs["hash_files"] = self.profile.hash_files
            elif collector_name in ("logs",):
                pass
            elif collector_name in ("browser",):
                pass

            log.info("Running collector: %s", collector_name)
            self.evidence.log_event("collector_start", collector_name)

            try:
                collector = get_collector(collector_name, **kwargs)
                result = collector.collect()
                self.collector_results.append(result)
                self.evidence.log_event(
                    "collector_complete", collector_name,
                    f"{len(result.artifacts)} artifacts, {len(result.errors)} errors, {result.duration_ms:.0f}ms",
                )
                log.info(
                    "Collector %s: %d artifacts, %d errors (%.0fms)",
                    collector_name, len(result.artifacts), len(result.errors), result.duration_ms,
                )
            except Exception as e:
                handle_error(e, context=f"collector:{collector_name}")
                self.evidence.log_event("collector_error", collector_name, str(e), success=False)

        self._save_collector_results()
        return self.collector_results

    def analyze(
        self,
        ioc_paths: list[str] | None = None,
        yara_paths: list[str] | None = None,
        sigma_paths: list[str] | None = None,
    ) -> list[AnalysisResult]:
        log.info("Starting analysis phase")

        analyzers_to_run = [
            ("anomaly_detector", AnomalyDetector()),
            ("timeline", TimelineGenerator()),
        ]

        if ioc_paths:
            analyzers_to_run.append(("ioc_scanner", IOCScanner(ioc_paths=ioc_paths)))
        if yara_paths and self.profile.yara_scan:
            analyzers_to_run.append(("yara_scanner", YARAScanner(rule_paths=yara_paths)))
        if sigma_paths:
            analyzers_to_run.append(("sigma_scanner", SigmaScanner(rule_paths=sigma_paths)))

        for name, analyzer in analyzers_to_run:
            log.info("Running analyzer: %s", name)
            self.evidence.log_event("analyzer_start", name)
            try:
                result = analyzer.analyze(self.collector_results)
                self.analysis_results.append(result)
                self.evidence.log_event(
                    "analyzer_complete", name,
                    f"{len(result.findings)} findings, {len(result.timeline_entries)} timeline entries",
                )
                log.info(
                    "Analyzer %s: %d findings (%.0fms)",
                    name, len(result.findings), result.duration_ms,
                )
            except Exception as e:
                handle_error(e, context=f"analyzer:{name}")
                self.evidence.log_event("analyzer_error", name, str(e), success=False)

        mapper = MitreAttackMapper()
        self.mitre_summary = mapper.aggregate(self.analysis_results)
        log.info("MITRE ATT&CK mapping: %d techniques detected", self.mitre_summary.get("technique_count", 0))

        self._save_analysis_results()
        return self.analysis_results

    def report(self, formats: list[str] | None = None) -> list[Path]:
        formats = formats or ["console", "html", "json", "csv"]
        report_data = self._build_report_data()
        output_paths = []

        for fmt in formats:
            log.info("Generating %s report", fmt)
            self.evidence.log_event("report_start", fmt)
            try:
                reporter = get_reporter(fmt)
                path = reporter.generate(report_data, self.output_dir)
                output_paths.append(path)
                self.evidence.log_event("report_complete", fmt, str(path))
            except Exception as e:
                handle_error(e, context=f"reporter:{fmt}")
                self.evidence.log_event("report_error", fmt, str(e), success=False)

        return output_paths

    def triage(
        self,
        ioc_paths: list[str] | None = None,
        yara_paths: list[str] | None = None,
        sigma_paths: list[str] | None = None,
        report_formats: list[str] | None = None,
        secure_output: bool = False,
        password: str = "",
    ) -> Path:
        log.info("Starting full triage pipeline")
        start = time.time()

        self.collect()
        self.analyze(ioc_paths=ioc_paths, yara_paths=yara_paths, sigma_paths=sigma_paths)
        self.report(formats=report_formats)

        total_artifacts = sum(len(r.artifacts) for r in self.collector_results)
        self.evidence.register_directory(self.output_dir)
        self.evidence.finalize(total_artifacts=total_artifacts)

        elapsed = time.time() - start
        log.info("Triage complete in %.1fs — %d artifacts, %d findings", elapsed, total_artifacts, len(self._build_report_data().all_findings))

        if secure_output:
            pkg_path = create_secure_package(self.output_dir, password=password)
            log.info("Secure evidence package: %s", pkg_path)
            return pkg_path

        return self.output_dir

    def _build_report_data(self) -> ReportData:
        sys_info = {}
        for result in self.collector_results:
            if result.collector_name == "system_info" and result.artifacts:
                sys_info = result.artifacts[0].data
                break

        return ReportData(
            collector_results=self.collector_results,
            analysis_results=self.analysis_results,
            mitre_summary=self.mitre_summary,
            case_id=self.case_id,
            examiner=self.examiner,
            system_info=sys_info,
        )

    def _save_collector_results(self) -> None:
        data_dir = self.output_dir / "raw"
        data_dir.mkdir(parents=True, exist_ok=True)
        for result in self.collector_results:
            path = data_dir / f"{result.collector_name}.json"
            with open(path, "w") as f:
                json.dump(result.model_dump(), f, indent=2, default=str)

    def _save_analysis_results(self) -> None:
        data_dir = self.output_dir / "analysis"
        data_dir.mkdir(parents=True, exist_ok=True)
        for result in self.analysis_results:
            path = data_dir / f"{result.analyzer_name}.json"
            with open(path, "w") as f:
                json.dump(result.model_dump(), f, indent=2, default=str)

        if self.mitre_summary:
            path = data_dir / "mitre_attack_summary.json"
            with open(path, "w") as f:
                json.dump(self.mitre_summary, f, indent=2, default=str)
