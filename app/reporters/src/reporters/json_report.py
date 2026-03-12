import json
from pathlib import Path

from reporters.types import ReportData
from logger import get_logger

log = get_logger("reporters.json")


class JSONReporter:
    @property
    def name(self) -> str:
        return "json"

    @property
    def display_name(self) -> str:
        return "JSON Report"

    def generate(self, data: ReportData, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "meta": {
                "tool": "IntrusionInspector",
                "version": "0.1.0",
                "case_id": data.case_id,
                "examiner": data.examiner,
            },
            "system_info": data.system_info,
            "risk_score": data.risk_score,
            "findings_summary": {
                sev: len(findings) for sev, findings in data.findings_by_severity.items()
            },
            "findings": [f.model_dump() for f in data.all_findings],
            "mitre_attack": data.mitre_summary,
            "collectors": [r.model_dump() for r in data.collector_results],
            "analysis": [r.model_dump() for r in data.analysis_results],
        }

        report_path = output_dir / "report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        log.info("JSON report written to %s", report_path)

        if data.mitre_summary.get("navigator_layer"):
            layer_path = output_dir / "attack_navigator_layer.json"
            with open(layer_path, "w") as f:
                json.dump(data.mitre_summary["navigator_layer"], f, indent=2)
            log.info("ATT&CK Navigator layer written to %s", layer_path)

        return report_path
