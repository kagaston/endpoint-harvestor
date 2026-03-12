import os
import platform
import time

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger
from settings import SUSPICIOUS_ENV_VARS

log = get_logger("collectors.environment")


class EnvironmentCollector:
    @property
    def name(self) -> str:
        return "environment"

    @property
    def display_name(self) -> str:
        return "Environment Variables"

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
            self._collect_current_process_env(result)

            if system == "Windows":
                self._collect_windows(result)
            elif system == "Linux":
                self._collect_linux(result)
            elif system == "Darwin":
                self._collect_darwin(result)
        except Exception as exc:
            log.error("Unexpected error during environment collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _is_suspicious(self, var_name: str) -> bool:
        return var_name.upper() in {v.upper() for v in SUSPICIOUS_ENV_VARS}

    def _make_env_artifact(
        self, name: str, value: str, scope: str, source: str,
    ) -> Artifact:
        data: dict = {
            "name": name,
            "value": value,
            "scope": scope,
        }
        if self._is_suspicious(name):
            data["suspicious"] = True
        return Artifact(
            artifact_type=ArtifactType.ENVIRONMENT_VAR,
            source=source,
            data=data,
        )

    def _collect_current_process_env(self, result: CollectorResult) -> None:
        try:
            for name, value in os.environ.items():
                result.artifacts.append(
                    self._make_env_artifact(name, value, "current_process", "os.environ"),
                )
        except Exception as exc:
            log.warning("Failed to collect current process env: %s", exc)
            result.errors.append(f"Current process env: {exc}")

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        self._collect_windows_registry_env(
            result,
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "system",
        )
        self._collect_windows_registry_env(
            result,
            r"HKCU\Environment",
            "user",
        )

    def _collect_windows_registry_env(
        self, result: CollectorResult, key_path: str, scope: str,
    ) -> None:
        try:
            stdout, stderr, rc = run_command(["reg", "query", key_path])
            if rc != 0:
                log.debug("Registry query failed for %s (rc=%d): %s", key_path, rc, stderr)
                return

            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("HKEY_"):
                    continue
                parts = stripped.split(None, 2)
                if len(parts) >= 3:
                    var_name = parts[0]
                    var_value = parts[2]
                    result.artifacts.append(
                        self._make_env_artifact(
                            var_name, var_value, scope, f"reg query {key_path}",
                        ),
                    )
        except Exception as exc:
            log.warning("Failed to query registry env %s: %s", key_path, exc)
            result.errors.append(f"Registry env {key_path}: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        self._collect_proc_environ(result, 1, "system")
        self._collect_linux_user_environs(result)

    def _collect_proc_environ(
        self, result: CollectorResult, pid: int, scope: str,
    ) -> None:
        try:
            environ_path = f"/proc/{pid}/environ"
            content = safe_read_file(environ_path)
            if not content:
                return

            for entry in content.split("\x00"):
                if "=" not in entry:
                    continue
                var_name, _, var_value = entry.partition("=")
                result.artifacts.append(
                    self._make_env_artifact(var_name, var_value, scope, environ_path),
                )
        except Exception as exc:
            log.debug("Failed to read /proc/%d/environ: %s", pid, exc)

    def _collect_linux_user_environs(self, result: CollectorResult) -> None:
        try:
            passwd = safe_read_file("/etc/passwd")
            if not passwd:
                return

            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username = parts[0]
                uid = int(parts[2]) if parts[2].isdigit() else -1
                shell = parts[6]
                if uid < 1000 and uid != 0:
                    continue
                if "nologin" in shell or "false" in shell:
                    continue

                stdout, _, rc = run_command(["pgrep", "-u", username, "-o"])
                if rc != 0 or not stdout.strip():
                    continue

                pid_str = stdout.strip().splitlines()[0]
                if pid_str.isdigit():
                    self._collect_proc_environ(
                        result, int(pid_str), f"user:{username}",
                    )
        except Exception as exc:
            log.warning("Failed to collect user environs: %s", exc)
            result.errors.append(f"Linux user environs: {exc}")

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        key_vars = ["PATH", "HOME", "SHELL", "TMPDIR", "USER", "LOGNAME"]
        for var in key_vars:
            try:
                stdout, _, rc = run_command(["launchctl", "getenv", var])
                if rc != 0:
                    continue
                value = stdout.strip()
                if value:
                    result.artifacts.append(
                        self._make_env_artifact(var, value, "launchctl", "launchctl getenv"),
                    )
            except Exception as exc:
                log.debug("Failed to get launchctl env %s: %s", var, exc)
