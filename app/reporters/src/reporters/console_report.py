from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from reporters.types import ReportData
from logger import get_logger

log = get_logger("reporters.console")

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class ConsoleReporter:
    def __init__(self, console: Console | None = None):
        self.console = console or Console(stderr=True)

    @property
    def name(self) -> str:
        return "console"

    @property
    def display_name(self) -> str:
        return "Console Report"

    def generate(self, data: ReportData, output_dir: Path) -> Path:
        self._print_header(data)
        self._print_risk_score(data)
        self._print_findings_summary(data)
        self._print_findings_detail(data)
        self._print_system_info(data)
        self._print_mitre_summary(data)
        self._print_collection_summary(data)
        return output_dir

    def _print_header(self, data: ReportData) -> None:
        header = Text("IntrusionInspector — DFIR Triage Report", style="bold white")
        meta_lines = []
        if data.case_id:
            meta_lines.append(f"Case ID: {data.case_id}")
        if data.examiner:
            meta_lines.append(f"Examiner: {data.examiner}")
        if data.system_info:
            meta_lines.append(f"Host: {data.system_info.get('hostname', 'unknown')}")
            meta_lines.append(f"OS: {data.system_info.get('os', 'unknown')}")
        subtitle = "\n".join(meta_lines) if meta_lines else ""
        self.console.print(Panel(header, subtitle=subtitle, border_style="blue"))

    def _print_risk_score(self, data: ReportData) -> None:
        score = data.risk_score
        if score >= 70:
            style = "bold red"
            label = "CRITICAL"
        elif score >= 40:
            style = "red"
            label = "HIGH"
        elif score >= 20:
            style = "yellow"
            label = "MEDIUM"
        elif score >= 5:
            style = "cyan"
            label = "LOW"
        else:
            style = "green"
            label = "CLEAN"
        self.console.print(f"\nRisk Score: [{style}]{score}/100 ({label})[/]")

    def _print_findings_summary(self, data: ReportData) -> None:
        by_sev = data.findings_by_severity
        table = Table(title="\nFindings Summary", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_sev[sev])
            style = SEVERITY_COLORS[sev]
            table.add_row(Text(sev.upper(), style=style), str(count))
        self.console.print(table)

    def _print_findings_detail(self, data: ReportData) -> None:
        findings = data.all_findings
        if not findings:
            self.console.print("\n[green]No findings detected.[/]")
            return

        self.console.print("\n[bold]Detailed Findings[/]")
        for i, finding in enumerate(sorted(findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)), 1):
            style = SEVERITY_COLORS.get(finding.severity.value, "")
            mitre = ", ".join(t.technique_id for t in finding.mitre_techniques)
            mitre_str = f" [{mitre}]" if mitre else ""

            self.console.print(
                f"\n  [{style}]{i}. [{finding.severity.value.upper()}]{mitre_str}[/] {finding.title}"
            )
            self.console.print(f"     {finding.description}", style="dim")
            if finding.source:
                self.console.print(f"     Source: {finding.source}", style="dim")

    def _print_system_info(self, data: ReportData) -> None:
        if not data.system_info:
            return
        table = Table(title="\nSystem Overview", show_header=False)
        table.add_column("Field", style="bold")
        table.add_column("Value")
        for key, value in data.system_info.items():
            if isinstance(value, (list, dict)):
                continue
            table.add_row(key, str(value))
        self.console.print(table)

    def _print_mitre_summary(self, data: ReportData) -> None:
        if not data.mitre_summary or not data.mitre_summary.get("techniques"):
            return
        self.console.print("\n[bold]MITRE ATT&CK Coverage[/]")
        tree = Tree("[bold]Tactics[/]")
        for tactic, technique_ids in data.mitre_summary.get("tactics", {}).items():
            branch = tree.add(f"[bold]{tactic}[/]")
            for tid in technique_ids:
                tech_info = data.mitre_summary["techniques"].get(tid, {})
                tech_data = tech_info.get("technique", {})
                sev = tech_info.get("max_severity", "info")
                style = SEVERITY_COLORS.get(sev, "")
                branch.add(f"[{style}]{tid}: {tech_data.get('name', tid)}[/] ({tech_info.get('finding_count', 0)} findings)")
        self.console.print(tree)

    def _print_collection_summary(self, data: ReportData) -> None:
        table = Table(title="\nCollection Summary", show_header=True)
        table.add_column("Collector")
        table.add_column("Artifacts", justify="right")
        table.add_column("Errors", justify="right")
        table.add_column("Duration", justify="right")
        for result in data.collector_results:
            err_style = "red" if result.errors else ""
            table.add_row(
                result.collector_name,
                str(len(result.artifacts)),
                Text(str(len(result.errors)), style=err_style),
                f"{result.duration_ms:.0f}ms",
            )
        self.console.print(table)
