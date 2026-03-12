import platform
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file, resolve_user_paths
from logger import get_logger

log = get_logger("collectors.shell_history")

UNIX_HISTORY_FILES: dict[str, str] = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".sh_history": "sh",
    ".local/share/fish/fish_history": "fish",
}

POWERSHELL_HISTORY_REL = (
    r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)


class ShellHistoryCollector:
    @property
    def name(self) -> str:
        return "shell_history"

    @property
    def display_name(self) -> str:
        return "Shell History"

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
            if system in ("Linux", "Darwin"):
                self._collect_unix_history(result)
            elif system == "Windows":
                self._collect_powershell_history(result)
                self._collect_cmd_history(result)
        except Exception as exc:
            log.error("Unexpected error during shell history collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _collect_unix_history(self, result: CollectorResult) -> None:
        for filename, shell in UNIX_HISTORY_FILES.items():
            try:
                paths = resolve_user_paths(filename)
                for hist_path in paths:
                    self._parse_history_file(result, hist_path, shell)
            except Exception as exc:
                log.warning("Failed to collect %s history: %s", shell, exc)
                result.errors.append(f"{shell} history: {exc}")

    def _parse_history_file(
        self, result: CollectorResult, path: Path, shell: str
    ) -> None:
        content = safe_read_file(path)
        if not content:
            return

        user = path.parts[2] if len(path.parts) > 2 else "unknown"

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.SHELL_COMMAND,
                source=str(path),
                data={
                    "command": line,
                    "user": user,
                    "shell": shell,
                    "line_number": line_number,
                },
            ))

    def _collect_powershell_history(self, result: CollectorResult) -> None:
        try:
            paths = resolve_user_paths(POWERSHELL_HISTORY_REL)
            for hist_path in paths:
                content = safe_read_file(hist_path)
                if not content:
                    continue

                user = hist_path.parts[2] if len(hist_path.parts) > 2 else "unknown"

                for line_number, raw_line in enumerate(
                    content.splitlines(), start=1
                ):
                    line = raw_line.strip()
                    if not line:
                        continue
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.SHELL_COMMAND,
                        source=str(hist_path),
                        data={
                            "command": line,
                            "user": user,
                            "shell": "powershell",
                            "line_number": line_number,
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to collect PowerShell history: %s", exc)
            result.errors.append(f"PowerShell history: {exc}")

    def _collect_cmd_history(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["doskey", "/history"], shell=True)
            if rc != 0 or not stdout.strip():
                return

            for line_number, raw_line in enumerate(
                stdout.splitlines(), start=1
            ):
                line = raw_line.strip()
                if not line:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.SHELL_COMMAND,
                    source="doskey /history",
                    data={
                        "command": line,
                        "shell": "cmd",
                        "line_number": line_number,
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect cmd.exe history: %s", exc)
            result.errors.append(f"cmd history: {exc}")
