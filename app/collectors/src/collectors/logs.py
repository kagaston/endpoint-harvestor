import platform
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger

log = get_logger("collectors.logs")

MAX_LOG_BYTES = 50 * 1024  # 50 KB per log source


class LogCollector:
    def __init__(self, days: int = 7) -> None:
        self.days = days

    @property
    def name(self) -> str:
        return "logs"

    @property
    def display_name(self) -> str:
        return "System Logs"

    @property
    def supported_platforms(self) -> list[str]:
        return ["Windows", "Linux", "Darwin"]

    def collect(self) -> CollectorResult:
        start = time.time()
        system = platform.system()
        result = CollectorResult(
            collector_name=self.name,
            platform=system,
            timestamp=normalize_timestamp(time.time()),
        )

        try:
            if system == "Windows":
                self._collect_windows(result)
            elif system == "Linux":
                self._collect_linux(result)
            elif system == "Darwin":
                self._collect_darwin(result)
        except Exception as exc:
            log.error("Unexpected error during log collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        channels = ["System", "Security", "Application"]
        for channel in channels:
            try:
                stdout, stderr, rc = run_command(
                    ["wevtutil", "qe", channel, "/c:500", "/f:text"],
                    timeout=60,
                )
                if rc != 0:
                    result.errors.append(f"wevtutil {channel} (rc={rc}): {stderr}")
                    continue

                content = stdout[:MAX_LOG_BYTES]
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.LOG_ENTRY,
                    source=f"wevtutil:{channel}",
                    data={
                        "log_source": f"Windows Event Log - {channel}",
                        "content": content,
                        "truncated": len(stdout) > MAX_LOG_BYTES,
                    },
                ))
            except Exception as exc:
                log.warning("Failed to collect %s event log: %s", channel, exc)
                result.errors.append(f"Event log {channel}: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        log_files: list[tuple[str, list[str]]] = [
            ("syslog", ["/var/log/syslog", "/var/log/messages"]),
            ("auth", ["/var/log/auth.log", "/var/log/secure"]),
            ("kernel", ["/var/log/kern.log"]),
        ]

        for source_name, paths in log_files:
            for path in paths:
                if not Path(path).is_file():
                    continue
                try:
                    content = safe_read_file(path, max_bytes=MAX_LOG_BYTES)
                    if not content:
                        continue
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.LOG_ENTRY,
                        source=path,
                        data={
                            "log_source": source_name,
                            "content": content,
                            "truncated": len(content) >= MAX_LOG_BYTES,
                        },
                    ))
                    break  # first readable path wins for this source
                except Exception as exc:
                    log.warning("Failed to read %s: %s", path, exc)
                    result.errors.append(f"Log file {path}: {exc}")

        self._collect_journalctl(result)

    def _collect_journalctl(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                [
                    "journalctl",
                    f"--since={self.days} days ago",
                    "--no-pager",
                    "-q",
                ],
                timeout=60,
            )
            if rc != 0:
                return

            content = stdout[:MAX_LOG_BYTES]
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.LOG_ENTRY,
                source="journalctl",
                data={
                    "log_source": "systemd journal",
                    "content": content,
                    "truncated": len(stdout) > MAX_LOG_BYTES,
                    "days": self.days,
                },
            ))
        except Exception as exc:
            log.debug("journalctl not available: %s", exc)

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        mac_logs = ["/var/log/system.log", "/var/log/install.log"]
        for path in mac_logs:
            if not Path(path).is_file():
                continue
            try:
                content = safe_read_file(path, max_bytes=MAX_LOG_BYTES)
                if content:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.LOG_ENTRY,
                        source=path,
                        data={
                            "log_source": Path(path).name,
                            "content": content,
                            "truncated": len(content) >= MAX_LOG_BYTES,
                        },
                    ))
            except Exception as exc:
                log.warning("Failed to read %s: %s", path, exc)
                result.errors.append(f"Log file {path}: {exc}")

        self._collect_unified_log(result)

    def _collect_unified_log(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                [
                    "log", "show",
                    "--predicate", "eventType == logEvent",
                    f"--last", f"{self.days}d",
                    "--style", "compact",
                ],
                timeout=120,
            )
            if rc != 0:
                result.errors.append(f"log show (rc={rc}): {stderr}")
                return

            lines = stdout.splitlines()[:1000]
            content = "\n".join(lines)
            if len(content) > MAX_LOG_BYTES:
                content = content[:MAX_LOG_BYTES]

            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.LOG_ENTRY,
                source="log show",
                data={
                    "log_source": "macOS unified log",
                    "content": content,
                    "truncated": len(lines) >= 1000 or len(stdout) > MAX_LOG_BYTES,
                    "days": self.days,
                },
            ))
        except Exception as exc:
            log.warning("Failed to collect unified log: %s", exc)
            result.errors.append(f"Unified log: {exc}")
