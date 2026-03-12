import time
from pathlib import Path

from analyzers.types import AnalysisResult, Finding, MitreTechnique, Severity
from collectors.types import ArtifactType, CollectorResult
from logger import get_logger

log = get_logger("analyzers.yara_scanner")

try:
    import yara

    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    log.warning("yara-python is not installed — YARA scanning will be unavailable")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"

_SCANNABLE_TYPES = {ArtifactType.FILE_ENTRY, ArtifactType.LOG_ENTRY}


class YARAScanner:
    def __init__(self, rule_paths: list[str] | None = None) -> None:
        self._rule_paths = rule_paths or []
        self._available = _YARA_AVAILABLE
        self._rules: list = []
        if self._available:
            self._compile_rules()

    @property
    def name(self) -> str:
        return "yara_scanner"

    @property
    def display_name(self) -> str:
        return "YARA Scanner"

    def _compile_rules(self) -> None:
        for path_str in self._rule_paths:
            path = Path(path_str)
            files: list[Path] = []
            if path.is_dir():
                files = list(path.glob("*.yar")) + list(path.glob("*.yara"))
            elif path.is_file() and path.suffix in (".yar", ".yara"):
                files = [path]

            for rule_file in files:
                try:
                    compiled = yara.compile(filepath=str(rule_file))
                    self._rules.append(compiled)
                    log.info("Compiled YARA rule file: %s", rule_file)
                except yara.Error as exc:
                    log.warning("Failed to compile YARA rule %s: %s", rule_file, exc)

        log.info("Compiled %d YARA rule file(s)", len(self._rules))

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        start = time.time()

        if not self._available:
            return AnalysisResult(
                analyzer_name=self.name,
                summary="YARA scanning unavailable — yara-python is not installed.",
                duration_ms=(time.time() - start) * 1000,
            )

        if not self._rules:
            return AnalysisResult(
                analyzer_name=self.name,
                summary="No YARA rules loaded — skipping scan.",
                duration_ms=(time.time() - start) * 1000,
            )

        findings: list[Finding] = []
        errors: list[str] = []

        for collector_result in results:
            for artifact in collector_result.artifacts:
                if artifact.artifact_type not in _SCANNABLE_TYPES:
                    continue
                try:
                    self._scan_artifact(artifact, collector_result.collector_name, findings)
                except Exception as exc:
                    msg = f"Error scanning artifact from {collector_result.collector_name}: {exc}"
                    log.warning(msg)
                    errors.append(msg)

        duration_ms = (time.time() - start) * 1000
        summary = (
            f"Scanned artifacts with {len(self._rules)} YARA rule file(s) "
            f"— {len(findings)} match(es) found."
        )
        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            summary=summary,
            duration_ms=duration_ms,
            errors=errors,
        )

    def _scan_artifact(
        self, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        data = artifact.data
        file_path = data.get("path", "") or data.get("file_path", "")

        if file_path:
            resolved = Path(file_path)
            if resolved.is_file():
                self._scan_file(resolved, artifact, collector_name, findings)
                return

        raw_content = data.get("content", "") or data.get("raw", "")
        if raw_content:
            content_bytes = raw_content.encode("utf-8", errors="replace") if isinstance(raw_content, str) else raw_content
            self._scan_data(content_bytes, artifact, collector_name, findings, source_label=file_path or artifact.source)

    def _scan_file(
        self, path: Path, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        for rules in self._rules:
            try:
                matches = rules.match(filepath=str(path))
            except yara.Error as exc:
                log.warning("YARA scan error on %s: %s", path, exc)
                continue
            for match in matches:
                findings.append(self._build_finding(match, str(path), artifact, collector_name))

    def _scan_data(
        self,
        data: bytes,
        artifact,
        collector_name: str,
        findings: list[Finding],
        source_label: str = "",
    ) -> None:
        for rules in self._rules:
            try:
                matches = rules.match(data=data)
            except yara.Error as exc:
                log.warning("YARA scan error on data blob: %s", exc)
                continue
            for match in matches:
                findings.append(self._build_finding(match, source_label, artifact, collector_name))

    @staticmethod
    def _build_finding(
        match, source_label: str, artifact, collector_name: str
    ) -> Finding:
        meta = match.meta if hasattr(match, "meta") else {}

        severity_str = meta.get("severity", "medium").lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        matched_strings: list[str] = []
        if hasattr(match, "strings"):
            for s in match.strings:
                instances = s.instances if hasattr(s, "instances") else []
                for inst in instances:
                    matched_strings.append(str(inst))

        mitre_techniques: list[MitreTechnique] = []
        mitre_id = meta.get("mitre_attack", "")
        if mitre_id:
            mitre_techniques.append(MitreTechnique(
                technique_id=mitre_id,
                name=meta.get("mitre_name", mitre_id),
                url=f"{_MITRE_BASE_URL}{mitre_id.replace('.', '/')}/",
            ))

        return Finding(
            title=f"YARA Match: {match.rule}",
            description=meta.get("description", f"YARA rule '{match.rule}' matched."),
            severity=severity,
            source=collector_name,
            analyzer="yara_scanner",
            evidence={
                "rule": match.rule,
                "tags": list(match.tags) if hasattr(match, "tags") else [],
                "meta": dict(meta),
                "matched_strings": matched_strings,
                "file_path": source_label,
            },
            mitre_techniques=mitre_techniques,
            timestamp=artifact.timestamp,
        )
