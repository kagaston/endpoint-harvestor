import csv
from pathlib import Path

from analyzers.types import AnalysisResult
from reporters.types import ReportData
from logger import get_logger

log = get_logger("reporters.csv")


class CSVReporter:
    @property
    def name(self) -> str:
        return "csv"

    @property
    def display_name(self) -> str:
        return "CSV Timeline Report"

    def generate(self, data: ReportData, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        timeline_path = output_dir / "timeline.csv"

        timeline_entries = []
        for result in data.analysis_results:
            timeline_entries.extend(result.timeline_entries)

        timeline_entries.sort(key=lambda e: e.timestamp or "")

        with open(timeline_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "source", "event_type", "description",
                "mitre_techniques", "data",
            ])
            for entry in timeline_entries:
                mitre = "; ".join(t.technique_id for t in entry.mitre_techniques)
                data_str = str(entry.data)[:500] if entry.data else ""
                writer.writerow([
                    entry.timestamp,
                    entry.source,
                    entry.event_type,
                    entry.description,
                    mitre,
                    data_str,
                ])

        log.info("CSV timeline written to %s (%d entries)", timeline_path, len(timeline_entries))

        findings_path = output_dir / "findings.csv"
        with open(findings_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "severity", "title", "description", "source",
                "analyzer", "mitre_techniques", "timestamp",
            ])
            for finding in sorted(data.all_findings, key=lambda f: f.severity.value):
                mitre = "; ".join(t.technique_id for t in finding.mitre_techniques)
                writer.writerow([
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.source,
                    finding.analyzer,
                    mitre,
                    finding.timestamp,
                ])

        log.info("CSV findings written to %s", findings_path)
        return timeline_path
