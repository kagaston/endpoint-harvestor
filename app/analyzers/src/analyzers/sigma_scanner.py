import re
import time
from pathlib import Path

import yaml

from analyzers.types import AnalysisResult, Finding, MitreTechnique, Severity
from collectors.types import ArtifactType, CollectorResult
from logger import get_logger

log = get_logger("analyzers.sigma_scanner")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"

_MITRE_TAG_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

_MATCHABLE_TYPES = {ArtifactType.LOG_ENTRY, ArtifactType.PROCESS}


class SigmaScanner:
    def __init__(self, rule_paths: list[str] | None = None) -> None:
        self._rule_paths = rule_paths or []
        self._rules: list[dict] = []
        self._load_rules()

    @property
    def name(self) -> str:
        return "sigma_scanner"

    @property
    def display_name(self) -> str:
        return "Sigma Scanner"

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        for path_str in self._rule_paths:
            path = Path(path_str)
            files: list[Path] = (
                list(path.glob("*.yaml")) + list(path.glob("*.yml"))
                if path.is_dir()
                else [path]
            )
            for f in files:
                if not f.is_file():
                    continue
                try:
                    with open(f, "r") as fh:
                        doc = yaml.safe_load(fh)
                    if doc and "detection" in doc:
                        self._rules.append(doc)
                except Exception as exc:
                    log.warning("Failed to load Sigma rule %s: %s", f, exc)

        log.info("Loaded %d Sigma rule(s)", len(self._rules))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        start = time.time()

        if not self._rules:
            return AnalysisResult(
                analyzer_name=self.name,
                summary="No Sigma rules loaded — skipping scan.",
                duration_ms=(time.time() - start) * 1000,
            )

        findings: list[Finding] = []
        errors: list[str] = []

        for collector_result in results:
            for artifact in collector_result.artifacts:
                if artifact.artifact_type not in _MATCHABLE_TYPES:
                    continue
                for rule in self._rules:
                    try:
                        if self._matches_rule(rule, artifact):
                            findings.append(
                                self._build_finding(rule, artifact, collector_result.collector_name)
                            )
                    except Exception as exc:
                        msg = (
                            f"Error evaluating Sigma rule '{rule.get('title', '?')}' "
                            f"against artifact from {collector_result.collector_name}: {exc}"
                        )
                        log.warning(msg)
                        errors.append(msg)

        duration_ms = (time.time() - start) * 1000
        summary = (
            f"Evaluated {len(self._rules)} Sigma rule(s) "
            f"— {len(findings)} match(es) found."
        )
        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            summary=summary,
            duration_ms=duration_ms,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Detection matching
    # ------------------------------------------------------------------

    def _matches_rule(self, rule: dict, artifact) -> bool:
        detection = rule.get("detection", {})
        condition: str = detection.get("condition", "selection")

        selections: dict[str, dict] = {
            k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)
        }

        if not selections:
            return False

        tokens = condition.strip().split()

        if len(tokens) == 1:
            sel = selections.get(tokens[0])
            return self._match_selection(sel, artifact) if sel else False

        if len(tokens) == 3 and tokens[1] in ("and", "or"):
            left = selections.get(tokens[0])
            right = selections.get(tokens[2])
            left_match = self._match_selection(left, artifact) if left else False
            right_match = self._match_selection(right, artifact) if right else False
            if tokens[1] == "and":
                return left_match and right_match
            return left_match or right_match

        # Fallback: require all named selections to match
        return all(
            self._match_selection(sel, artifact) for sel in selections.values()
        )

    def _match_selection(self, selection: dict | None, artifact) -> bool:
        if not selection:
            return False

        data = self._artifact_fields(artifact)

        for field_expr, expected_values in selection.items():
            if not self._field_matches(field_expr, expected_values, data):
                return False
        return True

    @staticmethod
    def _artifact_fields(artifact) -> dict[str, str]:
        data = artifact.data
        fields: dict[str, str] = {}
        if artifact.artifact_type == ArtifactType.LOG_ENTRY:
            fields["content"] = str(data.get("content", ""))
            fields["CommandLine"] = str(data.get("content", ""))
        elif artifact.artifact_type == ArtifactType.PROCESS:
            fields["name"] = str(data.get("name", ""))
            fields["CommandLine"] = str(
                data.get("cmdline", data.get("CommandLine", ""))
            )
            fields["Image"] = str(data.get("exe", data.get("Image", "")))
            fields["ParentImage"] = str(
                data.get("parent_exe", data.get("ParentImage", ""))
            )
        for k, v in data.items():
            fields.setdefault(k, str(v))
        return fields

    @staticmethod
    def _field_matches(field_expr: str, expected, data: dict[str, str]) -> bool:
        parts = field_expr.split("|")
        field_name = parts[0]
        modifier = parts[1] if len(parts) > 1 else ""

        field_value = data.get(field_name, "")
        if not field_value:
            return False

        if not isinstance(expected, list):
            expected = [expected]

        compare_value = field_value.lower()

        for exp in expected:
            exp_str = str(exp).lower()
            matched = False

            if modifier == "contains":
                matched = exp_str in compare_value
            elif modifier == "endswith":
                matched = compare_value.endswith(exp_str)
            elif modifier == "startswith":
                matched = compare_value.startswith(exp_str)
            elif modifier == "re":
                try:
                    matched = bool(re.search(str(exp), field_value, re.IGNORECASE))
                except re.error:
                    matched = False
            else:
                matched = compare_value == exp_str

            if matched:
                return True

        return False

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_mitre(rule: dict) -> list[MitreTechnique]:
        techniques: list[MitreTechnique] = []
        seen: set[str] = set()
        for tag in rule.get("tags", []):
            m = _MITRE_TAG_RE.match(tag)
            if m:
                tid = f"T{m.group(1).upper()}"
                if tid not in seen:
                    seen.add(tid)
                    techniques.append(
                        MitreTechnique(
                            technique_id=tid,
                            name=rule.get("title", tid),
                            tactic="",
                            url=f"{_MITRE_BASE_URL}{tid.replace('.', '/')}/",
                        )
                    )
        return techniques

    @staticmethod
    def _build_finding(rule: dict, artifact, collector_name: str) -> Finding:
        level = rule.get("level", "medium").lower()
        severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)

        return Finding(
            title=f"Sigma Match: {rule.get('title', 'Unnamed Rule')}",
            description=rule.get("description", "Sigma rule matched."),
            severity=severity,
            source=collector_name,
            analyzer="sigma_scanner",
            evidence={
                "rule_title": rule.get("title", ""),
                "rule_level": rule.get("level", ""),
                "rule_status": rule.get("status", ""),
                "matched_artifact_type": artifact.artifact_type.value,
                "artifact_source": artifact.source,
                "artifact_data": dict(artifact.data),
            },
            mitre_techniques=SigmaScanner._extract_mitre(rule),
            timestamp=artifact.timestamp,
        )
