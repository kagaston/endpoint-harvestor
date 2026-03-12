import time

from analyzers.types import AnalysisResult, TimelineEntry
from collectors.types import CollectorResult, ArtifactType
from logger import get_logger

log = get_logger("analyzers.timeline")

_EVENT_TYPE_MAP = {
    ArtifactType.SYSTEM_INFO: "system",
    ArtifactType.PROCESS: "process",
    ArtifactType.NETWORK_CONNECTION: "network",
    ArtifactType.DNS_ENTRY: "dns",
    ArtifactType.ARP_ENTRY: "arp",
    ArtifactType.USER_ACCOUNT: "user",
    ArtifactType.LOGIN_EVENT: "login",
    ArtifactType.SCHEDULED_TASK: "scheduled_task",
    ArtifactType.SERVICE: "service",
    ArtifactType.STARTUP_ITEM: "startup",
    ArtifactType.CRON_JOB: "cron",
    ArtifactType.FILE_ENTRY: "file",
    ArtifactType.LOG_ENTRY: "log",
    ArtifactType.BROWSER_HISTORY: "browser",
    ArtifactType.BROWSER_DOWNLOAD: "download",
    ArtifactType.SHELL_COMMAND: "shell",
    ArtifactType.USB_DEVICE: "usb",
    ArtifactType.INSTALLED_SOFTWARE: "software",
    ArtifactType.KERNEL_MODULE: "kernel",
    ArtifactType.FIREWALL_RULE: "firewall",
    ArtifactType.ENVIRONMENT_VAR: "environment",
    ArtifactType.CLIPBOARD_CONTENT: "clipboard",
    ArtifactType.CERTIFICATE: "certificate",
}


def _describe_artifact(artifact_type: ArtifactType, data: dict) -> str:
    match artifact_type:
        case ArtifactType.PROCESS:
            return f"Process: {data.get('name', '?')} (PID {data.get('pid', '?')}) — {data.get('cmdline', '')[:120]}"
        case ArtifactType.NETWORK_CONNECTION:
            return f"Connection: {data.get('local_address', '?')}:{data.get('local_port', '?')} → {data.get('remote_address', '?')}:{data.get('remote_port', '?')} [{data.get('status', '')}]"
        case ArtifactType.LOGIN_EVENT:
            return f"Login: {data.get('user', data.get('username', '?'))} from {data.get('host', data.get('terminal', '?'))}"
        case ArtifactType.FILE_ENTRY:
            return f"File: {data.get('path', data.get('name', '?'))} ({data.get('size', '?')} bytes)"
        case ArtifactType.LOG_ENTRY:
            content = data.get("content", "")
            return f"Log [{data.get('source', '?')}]: {content[:150]}"
        case ArtifactType.BROWSER_HISTORY:
            return f"Browser: {data.get('url', '?')} — {data.get('title', '')[:80]}"
        case ArtifactType.SHELL_COMMAND:
            return f"Shell [{data.get('shell', '?')}]: {data.get('command', '')[:120]}"
        case ArtifactType.SCHEDULED_TASK:
            return f"Task: {data.get('name', data.get('task_name', '?'))}"
        case ArtifactType.SERVICE:
            return f"Service: {data.get('name', data.get('service_name', '?'))} [{data.get('state', data.get('status', ''))}]"
        case ArtifactType.USB_DEVICE:
            return f"USB: {data.get('device_name', data.get('description', '?'))}"
        case ArtifactType.INSTALLED_SOFTWARE:
            return f"Software: {data.get('name', data.get('display_name', '?'))} {data.get('version', '')}"
        case ArtifactType.FIREWALL_RULE:
            return f"Firewall: {data.get('name', '?')} [{data.get('action', '')} {data.get('direction', '')}]"
        case _:
            name = data.get("name", data.get("subject", data.get("content", "")))
            return f"{artifact_type.value}: {str(name)[:100]}"


class TimelineGenerator:
    @property
    def name(self) -> str:
        return "timeline"

    @property
    def display_name(self) -> str:
        return "Timeline Generator"

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult:
        start = time.time()
        entries: list[TimelineEntry] = []
        errors: list[str] = []

        for result in results:
            for artifact in result.artifacts:
                try:
                    ts = artifact.timestamp or artifact.data.get("timestamp", artifact.data.get("create_time", ""))
                    if not ts:
                        ts = result.timestamp

                    entry = TimelineEntry(
                        timestamp=str(ts),
                        source=f"{result.collector_name}/{artifact.source}" if artifact.source else result.collector_name,
                        event_type=_EVENT_TYPE_MAP.get(artifact.artifact_type, artifact.artifact_type.value),
                        description=_describe_artifact(artifact.artifact_type, artifact.data),
                        data=artifact.data,
                    )
                    entries.append(entry)
                except Exception as e:
                    errors.append(f"Timeline entry error: {e}")

        entries.sort(key=lambda e: e.timestamp or "")

        elapsed = (time.time() - start) * 1000
        return AnalysisResult(
            analyzer_name=self.name,
            timeline_entries=entries,
            summary=f"Generated timeline with {len(entries)} entries from {len(results)} collectors",
            duration_ms=elapsed,
            errors=errors,
        )
