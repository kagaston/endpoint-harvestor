import os
import platform
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger

log = get_logger("collectors.persistence")


class PersistenceCollector:
    @property
    def name(self) -> str:
        return "persistence"

    @property
    def display_name(self) -> str:
        return "Persistence Mechanisms"

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
            log.error("Unexpected error during persistence collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        self._collect_scheduled_tasks(result)
        self._collect_windows_services(result)
        self._collect_run_keys(result)

    def _collect_scheduled_tasks(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["schtasks", "/query", "/fo", "CSV", "/v"], timeout=60,
            )
            if rc != 0:
                result.errors.append(f"schtasks failed (rc={rc}): {stderr}")
                return

            lines = stdout.strip().splitlines()
            if len(lines) < 2:
                return

            headers = [h.strip('"') for h in lines[0].split(",")]
            for line in lines[1:]:
                fields = [f.strip('"') for f in line.split(",")]
                if len(fields) != len(headers):
                    continue
                entry = dict(zip(headers, fields))
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.SCHEDULED_TASK,
                    source="schtasks",
                    data=entry,
                ))
        except Exception as exc:
            log.warning("Failed to collect scheduled tasks: %s", exc)
            result.errors.append(f"Scheduled tasks: {exc}")

    def _collect_windows_services(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["sc", "query", "state=", "all"], timeout=60,
            )
            if rc != 0:
                result.errors.append(f"sc query failed (rc={rc}): {stderr}")
                return

            current: dict[str, str] = {}
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    if current:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.SERVICE,
                            source="sc query",
                            data=dict(current),
                        ))
                        current = {}
                    continue
                if ":" in stripped:
                    key, _, value = stripped.partition(":")
                    current[key.strip().lower().replace(" ", "_")] = value.strip()

            if current:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.SERVICE,
                    source="sc query",
                    data=dict(current),
                ))
        except Exception as exc:
            log.warning("Failed to collect Windows services: %s", exc)
            result.errors.append(f"Windows services: {exc}")

    def _collect_run_keys(self, result: CollectorResult) -> None:
        keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ]
        for key_path in keys:
            try:
                stdout, _, rc = run_command(["reg", "query", key_path])
                if rc != 0:
                    continue
                for line in stdout.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("HKEY_"):
                        continue
                    parts = stripped.split(None, 2)
                    if len(parts) >= 3:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.STARTUP_ITEM,
                            source=f"reg query {key_path}",
                            data={
                                "name": parts[0],
                                "type": parts[1],
                                "value": parts[2],
                                "registry_key": key_path,
                            },
                        ))
            except Exception as exc:
                log.warning("Failed to query run key %s: %s", key_path, exc)
                result.errors.append(f"Run key {key_path}: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        self._collect_system_crontabs(result)
        self._collect_user_crontabs(result)
        self._collect_systemd_services(result)
        self._collect_init_scripts(result)

    def _collect_system_crontabs(self, result: CollectorResult) -> None:
        try:
            content = safe_read_file("/etc/crontab")
            if content:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.CRON_JOB,
                            source="/etc/crontab",
                            data={"entry": stripped},
                        ))
        except Exception as exc:
            log.warning("Failed to read /etc/crontab: %s", exc)
            result.errors.append(f"/etc/crontab: {exc}")

        cron_d = Path("/etc/cron.d")
        if cron_d.is_dir():
            try:
                for cron_file in cron_d.iterdir():
                    if cron_file.is_file():
                        content = safe_read_file(str(cron_file))
                        for line in content.splitlines():
                            stripped = line.strip()
                            if stripped and not stripped.startswith("#"):
                                result.artifacts.append(Artifact(
                                    artifact_type=ArtifactType.CRON_JOB,
                                    source=str(cron_file),
                                    data={"entry": stripped},
                                ))
            except Exception as exc:
                log.warning("Failed to read /etc/cron.d: %s", exc)
                result.errors.append(f"/etc/cron.d: {exc}")

    def _collect_user_crontabs(self, result: CollectorResult) -> None:
        users: list[str] = []
        try:
            passwd = safe_read_file("/etc/passwd")
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    uid = int(parts[2]) if parts[2].isdigit() else -1
                    shell = parts[6]
                    if uid >= 1000 or uid == 0:
                        if "nologin" not in shell and "false" not in shell:
                            users.append(parts[0])
        except Exception as exc:
            log.warning("Failed to parse /etc/passwd: %s", exc)
            result.errors.append(f"/etc/passwd: {exc}")

        for user in users:
            try:
                stdout, _, rc = run_command(["crontab", "-l", "-u", user])
                if rc != 0:
                    continue
                for line in stdout.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.CRON_JOB,
                            source=f"crontab -l -u {user}",
                            data={"user": user, "entry": stripped},
                        ))
            except Exception as exc:
                log.debug("Failed to get crontab for user %s: %s", user, exc)

    def _collect_systemd_services(self, result: CollectorResult) -> None:
        service_dirs = [
            Path("/etc/systemd/system"),
            Path("/usr/lib/systemd/system"),
        ]
        for svc_dir in service_dirs:
            if not svc_dir.is_dir():
                continue
            try:
                for svc_file in svc_dir.glob("*.service"):
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.SERVICE,
                        source=str(svc_dir),
                        data={
                            "name": svc_file.name,
                            "path": str(svc_file),
                            "type": "systemd",
                        },
                    ))
            except Exception as exc:
                log.warning("Failed to list %s: %s", svc_dir, exc)
                result.errors.append(f"Systemd dir {svc_dir}: {exc}")

    def _collect_init_scripts(self, result: CollectorResult) -> None:
        init_dir = Path("/etc/init.d")
        if not init_dir.is_dir():
            return
        try:
            for script in init_dir.iterdir():
                if script.is_file():
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.STARTUP_ITEM,
                        source="/etc/init.d",
                        data={
                            "name": script.name,
                            "path": str(script),
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to list /etc/init.d: %s", exc)
            result.errors.append(f"/etc/init.d: {exc}")

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        self._collect_launch_daemons(result)
        self._collect_launch_agents(result)
        self._collect_darwin_cron(result)
        self._collect_login_items(result)

    def _collect_launch_daemons(self, result: CollectorResult) -> None:
        dirs = [
            Path("/Library/LaunchDaemons"),
            Path("/System/Library/LaunchDaemons"),
        ]
        for daemon_dir in dirs:
            if not daemon_dir.is_dir():
                continue
            try:
                for plist in daemon_dir.iterdir():
                    if plist.is_file():
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.SERVICE,
                            source=str(daemon_dir),
                            data={
                                "name": plist.name,
                                "path": str(plist),
                                "type": "launch_daemon",
                            },
                        ))
            except Exception as exc:
                log.warning("Failed to list %s: %s", daemon_dir, exc)
                result.errors.append(f"LaunchDaemons {daemon_dir}: {exc}")

    def _collect_launch_agents(self, result: CollectorResult) -> None:
        dirs = [
            Path("/Library/LaunchAgents"),
            Path.home() / "Library" / "LaunchAgents",
        ]
        for agent_dir in dirs:
            if not agent_dir.is_dir():
                continue
            try:
                for plist in agent_dir.iterdir():
                    if plist.is_file():
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.STARTUP_ITEM,
                            source=str(agent_dir),
                            data={
                                "name": plist.name,
                                "path": str(plist),
                                "type": "launch_agent",
                            },
                        ))
            except Exception as exc:
                log.warning("Failed to list %s: %s", agent_dir, exc)
                result.errors.append(f"LaunchAgents {agent_dir}: {exc}")

    def _collect_darwin_cron(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["crontab", "-l"])
            if rc != 0:
                return
            for line in stdout.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.CRON_JOB,
                        source="crontab -l",
                        data={"entry": stripped},
                    ))
        except Exception as exc:
            log.warning("Failed to collect macOS cron jobs: %s", exc)
            result.errors.append(f"macOS cron: {exc}")

    def _collect_login_items(self, result: CollectorResult) -> None:
        try:
            cmd = [
                "osascript", "-e",
                'tell application "System Events" to get the name of every login item',
            ]
            stdout, _, rc = run_command(cmd)
            if rc != 0:
                return
            items = [i.strip() for i in stdout.split(",") if i.strip()]
            for item in items:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.STARTUP_ITEM,
                    source="osascript (login items)",
                    data={"name": item, "type": "login_item"},
                ))
        except Exception as exc:
            log.warning("Failed to collect login items: %s", exc)
            result.errors.append(f"Login items: {exc}")
