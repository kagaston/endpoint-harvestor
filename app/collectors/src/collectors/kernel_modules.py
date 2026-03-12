import csv
import io
import platform
import re
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger

log = get_logger("collectors.kernel_modules")


class KernelModuleCollector:
    @property
    def name(self) -> str:
        return "kernel_modules"

    @property
    def display_name(self) -> str:
        return "Kernel Modules"

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
                self._collect_windows_drivers(result)
            elif system == "Linux":
                self._collect_linux_proc_modules(result)
                self._collect_linux_module_params(result)
            elif system == "Darwin":
                self._collect_macos_kextstat(result)
        except Exception as exc:
            log.error("Unexpected error during kernel module collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # -- Windows -----------------------------------------------------------

    def _collect_windows_drivers(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["driverquery", "/v", "/fo", "csv"], timeout=60
            )
            if rc != 0 or not stdout.strip():
                return

            reader = csv.DictReader(io.StringIO(stdout))
            for row in reader:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.KERNEL_MODULE,
                    source="driverquery",
                    data={
                        "module_name": row.get("Module Name", "").strip(),
                        "display_name": row.get("Display Name", "").strip(),
                        "driver_type": row.get("Driver Type", "").strip(),
                        "state": row.get("State", "").strip(),
                        "start_mode": row.get("Start Mode", "").strip(),
                        "path": row.get("Path", "").strip(),
                        "link_date": row.get("Link Date", "").strip(),
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect Windows drivers: %s", exc)
            result.errors.append(f"driverquery: {exc}")

    # -- Linux -------------------------------------------------------------

    def _collect_linux_proc_modules(self, result: CollectorResult) -> None:
        try:
            content = safe_read_file("/proc/modules")
            if not content:
                self._collect_linux_lsmod_fallback(result)
                return

            for line in content.splitlines():
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                used_by = parts[3].strip(",").split(",") if parts[3] != "-" else []
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.KERNEL_MODULE,
                    source="/proc/modules",
                    data={
                        "module_name": parts[0],
                        "size": int(parts[1]) if parts[1].isdigit() else parts[1],
                        "use_count": int(parts[2]) if parts[2].isdigit() else parts[2],
                        "used_by": [m for m in used_by if m],
                        "state": parts[4] if len(parts) > 4 else "",
                        "offset": parts[5] if len(parts) > 5 else "",
                    },
                ))
        except Exception as exc:
            log.warning("Failed to read /proc/modules: %s", exc)
            result.errors.append(f"/proc/modules: {exc}")

    def _collect_linux_lsmod_fallback(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["lsmod"])
            if rc != 0 or not stdout.strip():
                return

            lines = stdout.splitlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                used_by = parts[3].strip(",").split(",") if len(parts) > 3 else []
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.KERNEL_MODULE,
                    source="lsmod",
                    data={
                        "module_name": parts[0],
                        "size": int(parts[1]) if parts[1].isdigit() else parts[1],
                        "use_count": int(parts[2]) if parts[2].isdigit() else parts[2],
                        "used_by": [m for m in used_by if m],
                    },
                ))
        except Exception as exc:
            log.warning("Failed to run lsmod: %s", exc)
            result.errors.append(f"lsmod: {exc}")

    def _collect_linux_module_params(self, result: CollectorResult) -> None:
        try:
            sysmod = Path("/sys/module")
            if not sysmod.is_dir():
                return

            for mod_dir in sysmod.iterdir():
                params_dir = mod_dir / "parameters"
                if not params_dir.is_dir():
                    continue

                params: dict[str, str] = {}
                try:
                    for param_file in params_dir.iterdir():
                        if param_file.is_file():
                            val = safe_read_file(param_file).strip()
                            if val:
                                params[param_file.name] = val
                except PermissionError:
                    continue

                if params:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.KERNEL_MODULE,
                        source="/sys/module/*/parameters",
                        data={
                            "module_name": mod_dir.name,
                            "parameters": params,
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to read module parameters: %s", exc)
            result.errors.append(f"module parameters: {exc}")

    # -- macOS -------------------------------------------------------------

    def _collect_macos_kextstat(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["kextstat"])
            if rc != 0 or not stdout.strip():
                return

            lines = stdout.splitlines()
            for line in lines[1:]:
                stripped = line.strip()
                if not stripped:
                    continue

                match = re.match(
                    r"\s*(\d+)\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
                    r"(0x[0-9a-fA-F]+)\s+(\S+)\s*\(([^)]+)\)",
                    line,
                )
                if match:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.KERNEL_MODULE,
                        source="kextstat",
                        data={
                            "index": int(match.group(1)),
                            "refs": int(match.group(2)),
                            "address": match.group(3),
                            "size": match.group(4),
                            "wired": match.group(5),
                            "bundle_id": match.group(6),
                            "version": match.group(7),
                        },
                    ))
                else:
                    parts = stripped.split()
                    if len(parts) >= 6:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.KERNEL_MODULE,
                            source="kextstat",
                            data={
                                "bundle_id": parts[5] if len(parts) > 5 else parts[-1],
                                "raw_line": stripped,
                            },
                        ))
        except Exception as exc:
            log.warning("Failed to collect macOS kext data: %s", exc)
            result.errors.append(f"kextstat: {exc}")
