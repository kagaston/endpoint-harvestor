import time
from pathlib import Path
from urllib.parse import urlparse

import yaml

from analyzers.types import AnalysisResult, Finding, MitreTechnique, Severity
from collectors.types import ArtifactType, CollectorResult
from logger import get_logger

log = get_logger("analyzers.ioc_scanner")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_HASH_TYPES = {"hash_md5", "hash_sha1", "hash_sha256"}

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


class IOCScanner:
    def __init__(self, ioc_paths: list[str] | None = None) -> None:
        self._ioc_paths = ioc_paths or []
        self._iocs: list[dict] = []
        self._load_iocs()

    @property
    def name(self) -> str:
        return "ioc_scanner"

    @property
    def display_name(self) -> str:
        return "IOC Scanner"

    def _load_iocs(self) -> None:
        for path_str in self._ioc_paths:
            path = Path(path_str)
            files = list(path.glob("*.yaml")) + list(path.glob("*.yml")) if path.is_dir() else [path]
            for f in files:
                if not f.is_file():
                    continue
                try:
                    with open(f, "r") as fh:
                        doc = yaml.safe_load(fh)
                    if doc and "iocs" in doc:
                        self._iocs.extend(doc["iocs"])
                except Exception as exc:
                    log.warning("Failed to load IOC file %s: %s", f, exc)

        log.info("Loaded %d IOC definitions", len(self._iocs))

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        if not self._iocs:
            return AnalysisResult(
                analyzer_name=self.name,
                summary="No IOC definitions loaded — skipping scan.",
                duration_ms=(time.time() - start) * 1000,
            )

        for collector_result in results:
            for artifact in collector_result.artifacts:
                try:
                    self._check_artifact(artifact, collector_result.collector_name, findings)
                except Exception as exc:
                    msg = f"Error scanning artifact from {collector_result.collector_name}: {exc}"
                    log.warning(msg)
                    errors.append(msg)

        duration_ms = (time.time() - start) * 1000
        summary = f"Scanned artifacts against {len(self._iocs)} IOCs — {len(findings)} match(es) found."
        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            summary=summary,
            duration_ms=duration_ms,
            errors=errors,
        )

    def _check_artifact(
        self, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        data = artifact.data
        for ioc in self._iocs:
            ioc_type: str = ioc.get("type", "")
            ioc_value: str = str(ioc.get("value", ""))
            if not ioc_type or not ioc_value:
                continue

            matched = False
            match_context = ""

            if ioc_type in _HASH_TYPES:
                hash_algo = ioc_type.replace("hash_", "")
                artifact_hash = data.get(hash_algo, "") or data.get(ioc_type, "")
                if artifact_hash and artifact_hash.lower() == ioc_value.lower():
                    matched = True
                    match_context = f"{hash_algo} hash match"

            elif ioc_type == "ip":
                matched, match_context = self._match_ip(data, artifact.artifact_type, ioc_value)

            elif ioc_type == "domain":
                matched, match_context = self._match_domain(data, artifact.artifact_type, ioc_value)

            elif ioc_type == "filepath":
                for key in ("path", "exe", "filepath", "file_path"):
                    val = data.get(key, "")
                    if val and ioc_value in val:
                        matched = True
                        match_context = f"file path match on field '{key}'"
                        break

            elif ioc_type == "process_name":
                for key in ("name", "process_name"):
                    val = data.get(key, "")
                    if val and val.lower() == ioc_value.lower():
                        matched = True
                        match_context = f"process name match on field '{key}'"
                        break

            elif ioc_type == "registry_key":
                for key in ("key", "registry_key", "path"):
                    val = data.get(key, "")
                    if val and ioc_value.lower() in val.lower():
                        matched = True
                        match_context = f"registry key match on field '{key}'"
                        break

            if matched:
                findings.append(self._build_finding(ioc, artifact, collector_name, match_context))

    def _match_ip(self, data: dict, artifact_type, ioc_value: str) -> tuple[bool, str]:
        if artifact_type == ArtifactType.NETWORK_CONNECTION:
            raddr = data.get("remote_address", "")
            if raddr and ioc_value in raddr:
                return True, f"remote address '{raddr}'"
        if artifact_type == ArtifactType.DNS_ENTRY:
            for key in ("value", "record_name"):
                val = data.get(key, "")
                if val and ioc_value in val:
                    return True, f"DNS entry field '{key}'"
        return False, ""

    def _match_domain(self, data: dict, artifact_type, ioc_value: str) -> tuple[bool, str]:
        if artifact_type == ArtifactType.BROWSER_HISTORY:
            url = data.get("url", "")
            if url:
                try:
                    host = urlparse(url).hostname or ""
                except Exception:
                    host = ""
                if host and (host == ioc_value or host.endswith(f".{ioc_value}")):
                    return True, f"browser history domain '{host}'"
        if artifact_type == ArtifactType.DNS_ENTRY:
            for key in ("record_name", "value", "domain"):
                val = data.get(key, "")
                if val and (val == ioc_value or val.endswith(f".{ioc_value}")):
                    return True, f"DNS entry field '{key}'"
        return False, ""

    @staticmethod
    def _build_finding(
        ioc: dict, artifact, collector_name: str, match_context: str
    ) -> Finding:
        severity = _SEVERITY_MAP.get(ioc.get("severity", "medium"), Severity.MEDIUM)

        mitre_techniques: list[MitreTechnique] = []
        technique_id = ioc.get("mitre_technique", "")
        if technique_id:
            mitre_techniques.append(MitreTechnique(
                technique_id=technique_id,
                name=ioc.get("mitre_name", technique_id),
                url=f"{_MITRE_BASE_URL}{technique_id.replace('.', '/')}/",
            ))

        return Finding(
            title=f"IOC Match: {ioc.get('type', 'unknown')} — {ioc.get('value', '')}",
            description=ioc.get("description", "Matched a known indicator of compromise."),
            severity=severity,
            source=collector_name,
            analyzer="ioc_scanner",
            evidence={
                "ioc_type": ioc.get("type", ""),
                "ioc_value": ioc.get("value", ""),
                "match_context": match_context,
                "artifact_source": artifact.source,
                "artifact_data": dict(artifact.data),
            },
            mitre_techniques=mitre_techniques,
            timestamp=artifact.timestamp,
        )
