import platform
import socket
import time

import psutil

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.system_info")


class SystemInfoCollector:
    @property
    def name(self) -> str:
        return "system_info"

    @property
    def display_name(self) -> str:
        return "System Information"

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
            self._collect_os_info(result, system)
            self._collect_cpu_memory(result)
            self._collect_uptime(result)
            self._collect_network_interfaces(result)
            self._collect_domain(result, system)
        except Exception as exc:
            log.error("Unexpected error during system info collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _collect_os_info(self, result: CollectorResult, system: str) -> None:
        try:
            uname = platform.uname()
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.SYSTEM_INFO,
                source="platform",
                data={
                    "category": "os",
                    "hostname": socket.gethostname(),
                    "fqdn": socket.getfqdn(),
                    "os_name": system,
                    "os_version": platform.version(),
                    "os_release": platform.release(),
                    "os_build": getattr(uname, "version", platform.version()),
                    "architecture": platform.machine(),
                    "kernel_version": uname.release,
                },
            ))
        except Exception as exc:
            log.warning("Failed to collect OS info: %s", exc)
            result.errors.append(f"OS info: {exc}")

    def _collect_cpu_memory(self, result: CollectorResult) -> None:
        try:
            mem = psutil.virtual_memory()
            cpu_freq = psutil.cpu_freq()
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.SYSTEM_INFO,
                source="psutil",
                data={
                    "category": "hardware",
                    "cpu_count_logical": psutil.cpu_count(logical=True),
                    "cpu_count_physical": psutil.cpu_count(logical=False),
                    "cpu_model": platform.processor() or "unknown",
                    "cpu_freq_mhz": cpu_freq.current if cpu_freq else None,
                    "ram_total_bytes": mem.total,
                    "ram_available_bytes": mem.available,
                    "ram_percent_used": mem.percent,
                },
            ))
        except Exception as exc:
            log.warning("Failed to collect CPU/memory info: %s", exc)
            result.errors.append(f"CPU/memory info: {exc}")

    def _collect_uptime(self, result: CollectorResult) -> None:
        try:
            boot_ts = psutil.boot_time()
            uptime_seconds = time.time() - boot_ts
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.SYSTEM_INFO,
                source="psutil",
                data={
                    "category": "uptime",
                    "boot_time": normalize_timestamp(boot_ts),
                    "uptime_seconds": round(uptime_seconds, 2),
                },
            ))
        except Exception as exc:
            log.warning("Failed to collect uptime: %s", exc)
            result.errors.append(f"Uptime: {exc}")

    def _collect_network_interfaces(self, result: CollectorResult) -> None:
        try:
            addrs = psutil.net_if_addrs()
            for iface_name, iface_addrs in addrs.items():
                iface_data: dict = {
                    "category": "network_interface",
                    "interface": iface_name,
                    "addresses": [],
                }
                for addr in iface_addrs:
                    entry: dict = {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    }
                    if addr.family == psutil.AF_LINK:
                        entry["type"] = "mac"
                    iface_data["addresses"].append(entry)

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.SYSTEM_INFO,
                    source="psutil",
                    data=iface_data,
                ))
        except Exception as exc:
            log.warning("Failed to collect network interfaces: %s", exc)
            result.errors.append(f"Network interfaces: {exc}")

    def _collect_domain(self, result: CollectorResult, system: str) -> None:
        try:
            domain = "unknown"
            source_detail = ""

            if system == "Windows":
                stdout, _, rc = run_command(
                    ["wmic", "computersystem", "get", "domain"],
                )
                if rc == 0:
                    lines = [l.strip() for l in stdout.splitlines() if l.strip()]
                    domain = lines[-1] if len(lines) > 1 else "unknown"
                    source_detail = "wmic"
            elif system == "Linux":
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2 and parts[0] in ("domain", "search"):
                                domain = parts[1]
                                source_detail = "/etc/resolv.conf"
                                break
                except (FileNotFoundError, PermissionError):
                    pass
            elif system == "Darwin":
                stdout, _, rc = run_command(["dsconfigad", "-show"])
                if rc == 0 and stdout.strip():
                    for line in stdout.splitlines():
                        if "Active Directory Domain" in line:
                            domain = line.split("=")[-1].strip()
                            source_detail = "dsconfigad"
                            break
                if domain == "unknown":
                    domain = "not bound"
                    source_detail = "dsconfigad"

            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.SYSTEM_INFO,
                source=source_detail or system,
                data={
                    "category": "domain",
                    "domain": domain,
                },
            ))
        except Exception as exc:
            log.warning("Failed to collect domain info: %s", exc)
            result.errors.append(f"Domain info: {exc}")
