import json
import platform
import time

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.installed_software")

WINDOWS_UNINSTALL_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]


class InstalledSoftwareCollector:
    @property
    def name(self) -> str:
        return "installed_software"

    @property
    def display_name(self) -> str:
        return "Installed Software"

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
                self._collect_windows_uninstall(result)
            elif system == "Linux":
                self._collect_linux_dpkg(result)
                self._collect_linux_rpm(result)
                self._collect_linux_snap(result)
                self._collect_linux_flatpak(result)
            elif system == "Darwin":
                self._collect_macos_profiler(result)
                self._collect_macos_brew(result)
        except Exception as exc:
            log.error("Unexpected error during software collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # -- Windows -----------------------------------------------------------

    def _collect_windows_uninstall(self, result: CollectorResult) -> None:
        for key in WINDOWS_UNINSTALL_KEYS:
            try:
                stdout, _, rc = run_command(
                    ["reg", "query", key, "/s"], timeout=60
                )
                if rc != 0 or not stdout.strip():
                    continue
                self._parse_windows_uninstall(result, stdout, key)
            except Exception as exc:
                log.warning("Failed to query %s: %s", key, exc)
                result.errors.append(f"Registry {key}: {exc}")

    def _parse_windows_uninstall(
        self, result: CollectorResult, output: str, source: str
    ) -> None:
        current: dict[str, str] = {}
        field_map = {
            "DisplayName": "name",
            "DisplayVersion": "version",
            "Publisher": "publisher",
            "InstallDate": "install_date",
            "InstallLocation": "install_location",
        }

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                if current.get("name"):
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                        source=source,
                        data=dict(current),
                    ))
                current = {}
                continue

            if stripped.startswith("HKEY_"):
                continue

            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                reg_name = parts[0]
                if reg_name in field_map:
                    current[field_map[reg_name]] = parts[2]

        if current.get("name"):
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                source=source,
                data=dict(current),
            ))

    # -- Linux: dpkg -------------------------------------------------------

    def _collect_linux_dpkg(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["dpkg", "-l"], timeout=60)
            if rc != 0 or not stdout.strip():
                return

            for line in stdout.splitlines():
                if not line.startswith("ii"):
                    continue
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="dpkg",
                    data={
                        "name": parts[1],
                        "version": parts[2],
                        "architecture": parts[3],
                        "description": parts[4].strip() if len(parts) > 4 else "",
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect dpkg packages: %s", exc)
            result.errors.append(f"dpkg: {exc}")

    # -- Linux: rpm --------------------------------------------------------

    def _collect_linux_rpm(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["rpm", "-qa", "--qf", r"%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}\n"],
                timeout=60,
            )
            if rc != 0 or not stdout.strip():
                return

            for line in stdout.splitlines():
                parts = line.strip().split("|")
                if len(parts) < 4:
                    continue
                install_ts = ""
                try:
                    install_ts = normalize_timestamp(int(parts[3]))
                except (ValueError, TypeError):
                    install_ts = parts[3]

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="rpm",
                    timestamp=install_ts,
                    data={
                        "name": parts[0],
                        "version": parts[1],
                        "release": parts[2],
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect rpm packages: %s", exc)
            result.errors.append(f"rpm: {exc}")

    # -- Linux: snap -------------------------------------------------------

    def _collect_linux_snap(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["snap", "list"])
            if rc != 0 or not stdout.strip():
                return

            lines = stdout.splitlines()
            if len(lines) < 2:
                return

            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="snap",
                    data={
                        "name": parts[0],
                        "version": parts[1],
                        "revision": parts[2],
                        "tracking": parts[3] if len(parts) > 3 else "",
                        "publisher": parts[4] if len(parts) > 4 else "",
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect snap packages: %s", exc)
            result.errors.append(f"snap: {exc}")

    # -- Linux: flatpak ----------------------------------------------------

    def _collect_linux_flatpak(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["flatpak", "list"])
            if rc != 0 or not stdout.strip():
                return

            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    parts = line.split()
                if not parts:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="flatpak",
                    data={
                        "name": parts[0].strip(),
                        "application_id": parts[1].strip() if len(parts) > 1 else "",
                        "version": parts[2].strip() if len(parts) > 2 else "",
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect flatpak packages: %s", exc)
            result.errors.append(f"flatpak: {exc}")

    # -- macOS -------------------------------------------------------------

    def _collect_macos_profiler(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                timeout=120,
            )
            if rc != 0 or not stdout.strip():
                return

            data = json.loads(stdout)
            apps = data.get("SPApplicationsDataType", [])
            for app in apps:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="system_profiler",
                    data={
                        "name": app.get("_name", ""),
                        "version": app.get("version", ""),
                        "path": app.get("path", ""),
                        "obtained_from": app.get("obtained_from", ""),
                        "last_modified": app.get("lastModified", ""),
                        "arch": app.get("arch_kind", ""),
                    },
                ))
        except json.JSONDecodeError as exc:
            log.warning("Failed to parse system_profiler JSON: %s", exc)
            result.errors.append(f"system_profiler JSON parse: {exc}")
        except Exception as exc:
            log.warning("Failed to collect macOS applications: %s", exc)
            result.errors.append(f"system_profiler apps: {exc}")

    def _collect_macos_brew(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["brew", "list", "--versions"])
            if rc != 0 or not stdout.strip():
                return

            for line in stdout.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.INSTALLED_SOFTWARE,
                    source="homebrew",
                    data={
                        "name": parts[0],
                        "version": " ".join(parts[1:]) if len(parts) > 1 else "",
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect Homebrew packages: %s", exc)
            result.errors.append(f"homebrew: {exc}")
