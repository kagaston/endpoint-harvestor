import sys
from pathlib import Path

import click
from rich.console import Console

from logger import setup_logging, get_logger
from settings import VERSION, DEFAULT_PROFILE


console = Console(stderr=True)
log = get_logger("cli")


@click.group()
@click.version_option(version=VERSION, prog_name="intrusion-inspector")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """intrusion-inspector — DFIR collection and triage for corporate endpoints."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose=verbose)


@main.command()
@click.option("--output", "-o", required=True, type=click.Path(), help="Output directory for collected artifacts")
@click.option("--profile", "-p", default=DEFAULT_PROFILE, help="Collection profile (quick/standard/full)")
@click.option("--case-id", default="", help="Case identifier for chain of custody")
@click.option("--examiner", default="", help="Examiner name for chain of custody")
@click.pass_context
def collect(ctx: click.Context, output: str, profile: str, case_id: str, examiner: str) -> None:
    """Collect forensic artifacts from the endpoint."""
    from engine.orchestrator import Orchestrator

    console.print(f"[bold blue]IntrusionInspector v{VERSION}[/] — Collecting artifacts")
    console.print(f"  Profile: [bold]{profile}[/]  Output: [bold]{output}[/]")

    try:
        orch = Orchestrator(output_dir=output, profile=profile, case_id=case_id, examiner=examiner)
        results = orch.collect()
        total = sum(len(r.artifacts) for r in results)
        console.print(f"\n[green]Collection complete:[/] {total} artifacts from {len(results)} collectors")
    except Exception as e:
        console.print(f"[red]Collection failed:[/] {e}")
        log.exception("Collection failed")
        sys.exit(1)


@main.command()
@click.option("--input", "-i", "input_dir", required=True, type=click.Path(exists=True), help="Directory with collected artifacts")
@click.option("--iocs", type=click.Path(exists=True), help="Path to IOC rules directory or file")
@click.option("--sigma", type=click.Path(exists=True), help="Path to Sigma rules directory or file")
@click.option("--yara", type=click.Path(exists=True), help="Path to YARA rules directory or file")
@click.pass_context
def analyze(ctx: click.Context, input_dir: str, iocs: str | None, sigma: str | None, yara: str | None) -> None:
    """Analyze previously collected artifacts."""
    import json
    from collectors.types import CollectorResult
    from engine.orchestrator import Orchestrator

    console.print(f"[bold blue]IntrusionInspector v{VERSION}[/] — Analyzing artifacts")

    raw_dir = Path(input_dir) / "raw"
    if not raw_dir.is_dir():
        console.print(f"[red]No raw data found in {input_dir}/raw/[/]")
        sys.exit(1)

    try:
        orch = Orchestrator(output_dir=input_dir, profile="standard")
        for json_file in sorted(raw_dir.glob("*.json")):
            with open(json_file) as f:
                data = json.load(f)
            orch.collector_results.append(CollectorResult(**data))

        ioc_paths = [iocs] if iocs else None
        sigma_paths = [sigma] if sigma else None
        yara_paths = [yara] if yara else None

        results = orch.analyze(ioc_paths=ioc_paths, sigma_paths=sigma_paths, yara_paths=yara_paths)
        total_findings = sum(len(r.findings) for r in results)
        console.print(f"\n[green]Analysis complete:[/] {total_findings} findings from {len(results)} analyzers")
    except Exception as e:
        console.print(f"[red]Analysis failed:[/] {e}")
        log.exception("Analysis failed")
        sys.exit(1)


@main.command()
@click.option("--input", "-i", "input_dir", required=True, type=click.Path(exists=True), help="Directory with analysis results")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "json", "csv", "console"]), default="html", help="Report format")
@click.pass_context
def report(ctx: click.Context, input_dir: str, fmt: str) -> None:
    """Generate reports from analysis results."""
    import json
    from analyzers.types import AnalysisResult
    from collectors.types import CollectorResult
    from reporters.registry import get_reporter
    from reporters.types import ReportData

    console.print(f"[bold blue]IntrusionInspector v{VERSION}[/] — Generating {fmt} report")

    try:
        report_data = _load_report_data(input_dir)
        reporter = get_reporter(fmt)
        output_path = reporter.generate(report_data, Path(input_dir))
        console.print(f"\n[green]Report generated:[/] {output_path}")
    except Exception as e:
        console.print(f"[red]Report generation failed:[/] {e}")
        log.exception("Report generation failed")
        sys.exit(1)


@main.command()
@click.option("--output", "-o", required=True, type=click.Path(), help="Output directory")
@click.option("--profile", "-p", default=DEFAULT_PROFILE, help="Collection profile (quick/standard/full)")
@click.option("--case-id", default="", help="Case identifier")
@click.option("--examiner", default="", help="Examiner name")
@click.option("--iocs", type=click.Path(exists=True), help="IOC rules path")
@click.option("--sigma", type=click.Path(exists=True), help="Sigma rules path")
@click.option("--yara", type=click.Path(exists=True), help="YARA rules path")
@click.option("--secure-output", is_flag=True, help="Create encrypted evidence package")
@click.option("--password", default="", help="Password for encrypted package (prompted if omitted with --secure-output)")
@click.option("--format", "-f", "formats", multiple=True, type=click.Choice(["html", "json", "csv", "console"]), help="Report formats (can specify multiple)")
@click.pass_context
def triage(
    ctx: click.Context,
    output: str,
    profile: str,
    case_id: str,
    examiner: str,
    iocs: str | None,
    sigma: str | None,
    yara: str | None,
    secure_output: bool,
    password: str,
    formats: tuple[str, ...],
) -> None:
    """Full triage: collect + analyze + report in one pass."""
    from engine.orchestrator import Orchestrator

    console.print(f"[bold blue]IntrusionInspector v{VERSION}[/] — Full Triage")
    console.print(f"  Profile: [bold]{profile}[/]  Output: [bold]{output}[/]")

    if secure_output and not password:
        password = click.prompt("Evidence package password", hide_input=True, confirmation_prompt=True)

    try:
        orch = Orchestrator(output_dir=output, profile=profile, case_id=case_id, examiner=examiner)
        result_path = orch.triage(
            ioc_paths=[iocs] if iocs else None,
            yara_paths=[yara] if yara else None,
            sigma_paths=[sigma] if sigma else None,
            report_formats=list(formats) if formats else None,
            secure_output=secure_output,
            password=password,
        )
        console.print(f"\n[bold green]Triage complete![/] Output: {result_path}")
    except Exception as e:
        console.print(f"[red]Triage failed:[/] {e}")
        log.exception("Triage failed")
        sys.exit(1)


@main.command()
@click.option("--input", "-i", "input_dir", required=True, type=click.Path(exists=True), help="Directory to verify")
@click.pass_context
def verify(ctx: click.Context, input_dir: str) -> None:
    """Verify evidence integrity against the collection manifest."""
    from evidence.integrity import EvidenceIntegrity

    console.print(f"[bold blue]IntrusionInspector v{VERSION}[/] — Verifying evidence integrity")

    valid, errors = EvidenceIntegrity.verify(Path(input_dir))

    if valid:
        console.print("[bold green]VERIFIED:[/] All files match the manifest checksums")
    else:
        console.print(f"[bold red]INTEGRITY FAILURE:[/] {len(errors)} issue(s) detected")
        for error in errors:
            console.print(f"  [red]•[/] {error}")
        sys.exit(1)


def _load_report_data(input_dir: str) -> "ReportData":
    import json
    from analyzers.types import AnalysisResult
    from collectors.types import CollectorResult
    from reporters.types import ReportData

    base = Path(input_dir)
    collector_results = []
    analysis_results = []
    mitre_summary = {}

    raw_dir = base / "raw"
    if raw_dir.is_dir():
        for json_file in sorted(raw_dir.glob("*.json")):
            with open(json_file) as f:
                collector_results.append(CollectorResult(**json.load(f)))

    analysis_dir = base / "analysis"
    if analysis_dir.is_dir():
        for json_file in sorted(analysis_dir.glob("*.json")):
            if json_file.name == "mitre_attack_summary.json":
                with open(json_file) as f:
                    mitre_summary = json.load(f)
            else:
                with open(json_file) as f:
                    analysis_results.append(AnalysisResult(**json.load(f)))

    coc_path = base / "chain_of_custody.json"
    case_id = ""
    examiner_name = ""
    if coc_path.is_file():
        with open(coc_path) as f:
            coc = json.load(f)
            case_id = coc.get("case_id", "")
            examiner_name = coc.get("examiner", "")

    sys_info = {}
    for r in collector_results:
        if r.collector_name == "system_info" and r.artifacts:
            sys_info = r.artifacts[0].data
            break

    return ReportData(
        collector_results=collector_results,
        analysis_results=analysis_results,
        mitre_summary=mitre_summary,
        case_id=case_id,
        examiner=examiner_name,
        system_info=sys_info,
    )
