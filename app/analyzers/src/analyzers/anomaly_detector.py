import re
import time

from analyzers.types import AnalysisResult, Finding, MitreTechnique, Severity
from collectors.types import ArtifactType, CollectorResult
from logger import get_logger
from settings import (
    LOLBINS_LINUX,
    LOLBINS_MACOS,
    LOLBINS_WINDOWS,
    SUSPICIOUS_ENV_VARS,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_PORTS,
)

log = get_logger("analyzers.anomaly_detector")

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_TEMP_DIR_PATTERNS = ("/tmp/", "/temp/", "\\temp\\", "\\appdata\\local\\temp\\", "/dev/shm/")

_PLATFORM_LOLBINS: dict[str, list[str]] = {
    "windows": LOLBINS_WINDOWS,
    "linux": LOLBINS_LINUX,
    "darwin": LOLBINS_MACOS,
    "macos": LOLBINS_MACOS,
}

_WRITABLE_DIR_FRAGMENTS = ("/tmp", "/home", "temp", "\\users\\", "\\appdata\\")

_SYSTEM_CERT_STORES = {"root", "ca", "authroot", "trustedpublisher", "system", "systemrootcerts"}

_SUSPICIOUS_MODULE_NAMES = {"rootkit", "keylog", "inject", "hook", "hide", "stealth", "sniff"}


def _mitre(technique_id: str, name: str, tactic: str = "") -> list[MitreTechnique]:
    return [
        MitreTechnique(
            technique_id=technique_id,
            name=name,
            tactic=tactic,
            url=f"{_MITRE_BASE_URL}{technique_id.replace('.', '/')}/",
        )
    ]


def _in_temp_dir(path: str) -> bool:
    lower = path.lower()
    return any(p in lower for p in _TEMP_DIR_PATTERNS)


def _in_user_dir(path: str) -> bool:
    lower = path.lower()
    return any(tok in lower for tok in ("\\users\\", "/home/", "\\appdata\\"))


class AnomalyDetector:
    def __init__(self) -> None:
        pass

    @property
    def name(self) -> str:
        return "anomaly_detector"

    @property
    def display_name(self) -> str:
        return "Anomaly Detector"

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        start = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        for collector_result in results:
            platform = collector_result.platform.lower()
            for artifact in collector_result.artifacts:
                try:
                    self._check_artifact(artifact, platform, collector_result.collector_name, findings)
                except Exception as exc:
                    msg = f"Error analysing artifact from {collector_result.collector_name}: {exc}"
                    log.warning(msg)
                    errors.append(msg)

        duration_ms = (time.time() - start) * 1000
        summary = f"Heuristic analysis complete — {len(findings)} anomal{'y' if len(findings) == 1 else 'ies'} detected."
        return AnalysisResult(
            analyzer_name=self.name,
            findings=findings,
            summary=summary,
            duration_ms=duration_ms,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _check_artifact(
        self, artifact, platform: str, collector_name: str, findings: list[Finding]
    ) -> None:
        t = artifact.artifact_type
        data = artifact.data

        if t == ArtifactType.PROCESS:
            self._check_lolbins(data, platform, artifact, collector_name, findings)
            self._check_parent_child(data, artifact, collector_name, findings)
            self._check_temp_execution(data, artifact, collector_name, findings)
            self._check_base64_cmdline(data, artifact, collector_name, findings)
        elif t == ArtifactType.SCHEDULED_TASK:
            self._check_suspicious_task(data, artifact, collector_name, findings)
        elif t == ArtifactType.NETWORK_CONNECTION:
            self._check_unusual_connection(data, artifact, collector_name, findings)
        elif t == ArtifactType.SERVICE:
            self._check_unusual_service(data, artifact, collector_name, findings)
        elif t == ArtifactType.ENVIRONMENT_VAR:
            self._check_path_hijack(data, artifact, collector_name, findings)
        elif t == ArtifactType.CERTIFICATE:
            self._check_rogue_cert(data, artifact, collector_name, findings)
        elif t == ArtifactType.KERNEL_MODULE:
            self._check_suspicious_module(data, artifact, collector_name, findings)
        elif t == ArtifactType.CLIPBOARD_CONTENT:
            self._check_clipboard_iocs(data, artifact, collector_name, findings)
        elif t == ArtifactType.FIREWALL_RULE:
            self._check_firewall_tampering(data, artifact, collector_name, findings)

    # ------------------------------------------------------------------
    # 1. LOLBins (T1218 / T1216)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_lolbins(
        data: dict, platform: str, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        proc_name = data.get("name", "")
        if not proc_name:
            return

        lolbins = _PLATFORM_LOLBINS.get(platform, [])
        if not lolbins:
            return

        if proc_name.lower() in (lb.lower() for lb in lolbins):
            findings.append(Finding(
                title=f"LOLBin Execution: {proc_name}",
                description=f"Living-off-the-land binary '{proc_name}' detected on {platform}.",
                severity=Severity.MEDIUM,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"process_name": proc_name, "platform": platform, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1218", "System Binary Proxy Execution", "defense-evasion"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 2. Unusual parent-child relationships (T1055 / T1036)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_parent_child(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        parent = data.get("parent_name", "")
        child = data.get("name", "")
        if not parent or not child:
            return

        suspicious_children = SUSPICIOUS_PARENT_CHILD.get(parent.lower())
        if suspicious_children is None:
            for key, vals in SUSPICIOUS_PARENT_CHILD.items():
                if key.lower() == parent.lower():
                    suspicious_children = vals
                    break

        if suspicious_children and child.lower() in (c.lower() for c in suspicious_children):
            findings.append(Finding(
                title=f"Suspicious Parent-Child: {parent} → {child}",
                description=f"Unexpected child process '{child}' spawned by '{parent}'.",
                severity=Severity.HIGH,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"parent": parent, "child": child, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1055", "Process Injection", "defense-evasion"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 3. Processes from temp directories (T1204)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_temp_execution(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        exe = data.get("exe", "") or data.get("path", "")
        if not exe:
            return

        if _in_temp_dir(exe):
            findings.append(Finding(
                title=f"Execution from temp directory: {exe}",
                description=f"Process running from temporary directory: '{exe}'.",
                severity=Severity.HIGH,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"exe_path": exe, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1204", "User Execution", "execution"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 4. Suspicious scheduled tasks (T1053)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_suspicious_task(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        action = str(data.get("action", "") or data.get("command", "") or data.get("path", ""))
        if not action:
            return

        lower = action.lower()
        suspicious = (
            _in_temp_dir(action)
            or _in_user_dir(action)
            or "-enc" in lower
            or "-encodedcommand" in lower
        )
        if suspicious:
            findings.append(Finding(
                title=f"Suspicious Scheduled Task: {data.get('name', 'unknown')}",
                description=f"Scheduled task with suspicious action: '{action}'.",
                severity=Severity.MEDIUM,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"task_name": data.get("name", ""), "action": action, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1053", "Scheduled Task/Job", "persistence"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 5. Unusual network connections (T1071)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_unusual_connection(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        remote_port = data.get("remote_port")
        if remote_port is None:
            return

        try:
            port = int(remote_port)
        except (ValueError, TypeError):
            return

        if port in SUSPICIOUS_PORTS:
            findings.append(Finding(
                title=f"Suspicious outbound connection on port {port}",
                description=f"Connection to {data.get('remote_address', '?')}:{port} uses a known-suspicious port.",
                severity=Severity.MEDIUM,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={
                    "remote_address": data.get("remote_address", ""),
                    "remote_port": port,
                    "pid": data.get("pid", ""),
                    "artifact_data": dict(data),
                },
                mitre_techniques=_mitre("T1071", "Application Layer Protocol", "command-and-control"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 6. Base64 / encoded command lines (T1027 / T1059)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_base64_cmdline(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        cmdline = str(data.get("cmdline", "") or data.get("CommandLine", ""))
        if not cmdline:
            return

        lower = cmdline.lower()
        has_enc_flag = "-enc " in lower or "-encodedcommand " in lower or lower.endswith("-enc") or lower.endswith("-encodedcommand")
        has_b64_blob = bool(_BASE64_RE.search(cmdline))

        if has_enc_flag or has_b64_blob:
            findings.append(Finding(
                title="Encoded/obfuscated command line detected",
                description=f"Process command line contains base64 or encoding indicators.",
                severity=Severity.HIGH,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"cmdline": cmdline, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1027", "Obfuscated Files or Information", "defense-evasion"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 7. Unusual services (T1543)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_unusual_service(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        binary = data.get("binary_path", "") or data.get("path", "") or data.get("exe", "")
        if not binary:
            return

        if _in_temp_dir(binary) or _in_user_dir(binary):
            findings.append(Finding(
                title=f"Suspicious service binary: {data.get('name', 'unknown')}",
                description=f"Service binary located in non-standard directory: '{binary}'.",
                severity=Severity.HIGH,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"service_name": data.get("name", ""), "binary_path": binary, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1543", "Create or Modify System Process", "persistence"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 8. PATH hijacking (T1574)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_path_hijack(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        var_name = data.get("name", "")
        if var_name.lower() not in ("path", "Path"):
            if var_name not in ("PATH", "Path"):
                return

        value = data.get("value", "")
        if not value:
            return

        lower_value = value.lower()
        if any(frag in lower_value for frag in _WRITABLE_DIR_FRAGMENTS):
            findings.append(Finding(
                title="PATH contains writable directory",
                description=f"The PATH environment variable includes directories writable by non-privileged users.",
                severity=Severity.MEDIUM,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"variable": var_name, "value": value, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1574", "Hijack Execution Flow", "persistence"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 9. Rogue certificates (T1553)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_rogue_cert(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        if not data.get("is_self_signed"):
            return

        store = str(data.get("store", "")).lower()
        if store in _SYSTEM_CERT_STORES:
            return

        findings.append(Finding(
            title=f"Self-signed certificate in non-system store: {data.get('subject', 'unknown')}",
            description=f"Self-signed certificate found in store '{data.get('store', '?')}'.",
            severity=Severity.MEDIUM,
            source=collector_name,
            analyzer="anomaly_detector",
            evidence={"subject": data.get("subject", ""), "store": data.get("store", ""), "artifact_data": dict(data)},
            mitre_techniques=_mitre("T1553", "Subvert Trust Controls", "defense-evasion"),
            timestamp=artifact.timestamp,
        ))

    # ------------------------------------------------------------------
    # 10. Suspicious kernel modules (T1547 / T1014)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_suspicious_module(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        is_signed = data.get("signed", True)
        module_name = str(data.get("name", "")).lower()

        has_suspicious_name = any(tok in module_name for tok in _SUSPICIOUS_MODULE_NAMES)
        is_unsigned = not is_signed

        if is_unsigned or has_suspicious_name:
            reasons: list[str] = []
            if is_unsigned:
                reasons.append("unsigned")
            if has_suspicious_name:
                reasons.append("suspicious name")

            findings.append(Finding(
                title=f"Suspicious kernel module: {data.get('name', 'unknown')}",
                description=f"Kernel module flagged ({', '.join(reasons)}): '{data.get('name', '')}'.",
                severity=Severity.HIGH,
                source=collector_name,
                analyzer="anomaly_detector",
                evidence={"module_name": data.get("name", ""), "reasons": reasons, "artifact_data": dict(data)},
                mitre_techniques=_mitre("T1547", "Boot or Logon Autostart Execution", "persistence"),
                timestamp=artifact.timestamp,
            ))

    # ------------------------------------------------------------------
    # 11. Clipboard IOCs (T1115)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_clipboard_iocs(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        has_urls = data.get("has_urls", False)
        has_base64 = data.get("has_base64", False)

        if not (has_urls or has_base64):
            return

        indicators: list[str] = []
        if has_urls:
            indicators.append("URLs")
        if has_base64:
            indicators.append("base64")

        findings.append(Finding(
            title="Clipboard contains potential IOCs",
            description=f"Clipboard content contains {' and '.join(indicators)}.",
            severity=Severity.LOW,
            source=collector_name,
            analyzer="anomaly_detector",
            evidence={"has_urls": has_urls, "has_base64": has_base64, "artifact_data": dict(data)},
            mitre_techniques=_mitre("T1115", "Clipboard Data", "collection"),
            timestamp=artifact.timestamp,
        ))

    # ------------------------------------------------------------------
    # 12. Firewall tampering (T1562)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_firewall_tampering(
        data: dict, artifact, collector_name: str, findings: list[Finding]
    ) -> None:
        enabled = data.get("enabled", True)
        action = str(data.get("action", "")).lower()

        is_disabled = enabled is False or str(enabled).lower() == "false"
        is_allow_all = action == "allow" and not data.get("remote_address") and not data.get("remote_port")

        if not (is_disabled or is_allow_all):
            return

        reason = "disabled rule" if is_disabled else "allow-all rule"
        findings.append(Finding(
            title=f"Firewall tampering detected: {reason}",
            description=f"Firewall rule '{data.get('name', 'unknown')}' flagged as {reason}.",
            severity=Severity.MEDIUM,
            source=collector_name,
            analyzer="anomaly_detector",
            evidence={"rule_name": data.get("name", ""), "reason": reason, "artifact_data": dict(data)},
            mitre_techniques=_mitre("T1562", "Impair Defenses", "defense-evasion"),
            timestamp=artifact.timestamp,
        ))
