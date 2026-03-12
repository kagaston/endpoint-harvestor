import time
from collections import defaultdict

from analyzers.types import AnalysisResult, Finding, MitreTechnique, Severity
from collectors.types import CollectorResult
from logger import get_logger

log = get_logger("analyzers.mitre_attack")

TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1014": {"name": "Rootkit", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution, Persistence, Privilege Escalation"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion, Privilege Escalation"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1115": {"name": "Clipboard Data", "tactic": "Collection"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1216": {"name": "System Script Proxy Execution", "tactic": "Defense Evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence, Privilege Escalation"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence, Privilege Escalation"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence, Privilege Escalation"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence, Privilege Escalation"},
    "T1547.006": {"name": "Kernel Modules and Extensions", "tactic": "Persistence, Privilege Escalation"},
    "T1553": {"name": "Subvert Trust Controls", "tactic": "Defense Evasion"},
    "T1553.004": {"name": "Install Root Certificate", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1562.004": {"name": "Disable or Modify System Firewall", "tactic": "Defense Evasion"},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence, Privilege Escalation, Defense Evasion"},
    "T1574.007": {"name": "Path Interception by PATH Environment Variable", "tactic": "Persistence, Privilege Escalation, Defense Evasion"},
}


def enrich_technique(technique_id: str) -> MitreTechnique:
    info = TECHNIQUE_DB.get(technique_id, {})
    return MitreTechnique(
        technique_id=technique_id,
        name=info.get("name", technique_id),
        tactic=info.get("tactic", ""),
        url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


class MitreAttackMapper:
    @property
    def name(self) -> str:
        return "mitre_attack"

    @property
    def display_name(self) -> str:
        return "MITRE ATT&CK Mapper"

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        return AnalysisResult(analyzer_name=self.name)

    def aggregate(self, analysis_results: list[AnalysisResult]) -> dict:
        technique_findings: dict[str, list[Finding]] = defaultdict(list)
        tactic_techniques: dict[str, list[str]] = defaultdict(list)
        all_techniques: dict[str, MitreTechnique] = {}

        for result in analysis_results:
            for finding in result.findings:
                for tech in finding.mitre_techniques:
                    tid = tech.technique_id
                    technique_findings[tid].append(finding)
                    enriched = enrich_technique(tid)
                    all_techniques[tid] = enriched
                    for tactic in enriched.tactic.split(", "):
                        if tactic and tid not in tactic_techniques[tactic]:
                            tactic_techniques[tactic].append(tid)

        max_severity = Severity.INFO
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for findings in technique_findings.values():
            for f in findings:
                if severity_order.index(f.severity) > severity_order.index(max_severity):
                    max_severity = f.severity

        return {
            "technique_count": len(all_techniques),
            "techniques": {
                tid: {
                    "technique": tech.model_dump(),
                    "finding_count": len(technique_findings[tid]),
                    "max_severity": max(
                        (f.severity for f in technique_findings[tid]),
                        key=lambda s: severity_order.index(s),
                    ).value,
                }
                for tid, tech in sorted(all_techniques.items())
            },
            "tactics": {
                tactic: sorted(tids) for tactic, tids in sorted(tactic_techniques.items())
            },
            "overall_severity": max_severity.value,
            "navigator_layer": self._build_navigator_layer(all_techniques, technique_findings, severity_order),
        }

    def _build_navigator_layer(
        self,
        techniques: dict[str, MitreTechnique],
        findings: dict[str, list[Finding]],
        severity_order: list[Severity],
    ) -> dict:
        score_map = {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}
        layer_techniques = []
        for tid, tech in techniques.items():
            max_sev = max(
                (f.severity for f in findings[tid]),
                key=lambda s: severity_order.index(s),
            )
            layer_techniques.append({
                "techniqueID": tid,
                "score": score_map.get(max_sev, 1),
                "comment": f"{len(findings[tid])} finding(s)",
                "enabled": True,
            })

        return {
            "name": "IntrusionInspector Findings",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Auto-generated ATT&CK layer from IntrusionInspector analysis",
            "techniques": layer_techniques,
            "gradient": {
                "colors": ["#ce0000", "#ff6600", "#ffcc00", "#66cc00", "#00cc00"],
                "minValue": 1,
                "maxValue": 5,
            },
        }
