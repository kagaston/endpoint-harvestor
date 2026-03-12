import platform
import time

import psutil

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.network")


class NetworkCollector:
    @property
    def name(self) -> str:
        return "network"

    @property
    def display_name(self) -> str:
        return "Network State"

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
            self._collect_connections(result)
            self._collect_dns(result, system)
            self._collect_arp(result)
        except Exception as exc:
            log.error("Unexpected error during network collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _collect_connections(self, result: CollectorResult) -> None:
        try:
            for conn in psutil.net_connections(kind="all"):
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                laddr = ""
                if conn.laddr:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn.laddr, "ip") else str(conn.laddr)

                raddr = ""
                if conn.raddr:
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn.raddr, "ip") else str(conn.raddr)

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.NETWORK_CONNECTION,
                    source="psutil",
                    data={
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "local_address": laddr,
                        "remote_address": raddr,
                        "status": conn.status if hasattr(conn, "status") else "",
                        "pid": conn.pid,
                        "process_name": proc_name,
                    },
                ))
        except (psutil.AccessDenied, PermissionError) as exc:
            log.warning("Insufficient permissions for net_connections: %s", exc)
            result.errors.append(f"Connections (access denied): {exc}")
        except Exception as exc:
            log.warning("Failed to collect connections: %s", exc)
            result.errors.append(f"Connections: {exc}")

    def _collect_dns(self, result: CollectorResult, system: str) -> None:
        try:
            if system == "Windows":
                self._collect_dns_windows(result)
            elif system == "Linux":
                self._collect_dns_linux(result)
            elif system == "Darwin":
                self._collect_dns_darwin(result)
        except Exception as exc:
            log.warning("Failed to collect DNS info: %s", exc)
            result.errors.append(f"DNS: {exc}")

    def _collect_dns_windows(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command(["ipconfig", "/displaydns"])
        if rc != 0:
            return

        current_entry: dict = {}
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("-"):
                if current_entry.get("record_name"):
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.DNS_ENTRY,
                        source="ipconfig /displaydns",
                        data=dict(current_entry),
                    ))
                    current_entry = {}
                continue
            if "Record Name" in stripped:
                current_entry["record_name"] = stripped.split(":", 1)[-1].strip()
            elif "Record Type" in stripped:
                current_entry["record_type"] = stripped.split(":", 1)[-1].strip()
            elif "Time To Live" in stripped:
                current_entry["ttl"] = stripped.split(":", 1)[-1].strip()
            elif "Data Length" in stripped:
                current_entry["data_length"] = stripped.split(":", 1)[-1].strip()
            elif "A (Host) Record" in stripped or "Section" in stripped:
                current_entry["section"] = stripped.split(":", 1)[-1].strip()
            elif stripped.startswith("AAAA") or stripped.startswith("CNAME"):
                current_entry["value"] = stripped
            else:
                current_entry.setdefault("value", stripped)

        if current_entry.get("record_name"):
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.DNS_ENTRY,
                source="ipconfig /displaydns",
                data=dict(current_entry),
            ))

    def _collect_dns_linux(self, result: CollectorResult) -> None:
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split()
                    if len(parts) >= 2:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.DNS_ENTRY,
                            source="/etc/resolv.conf",
                            data={"directive": parts[0], "value": " ".join(parts[1:])},
                        ))
        except (FileNotFoundError, PermissionError):
            pass

        stdout, _, rc = run_command(["systemd-resolve", "--statistics"])
        if rc == 0 and stdout.strip():
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.DNS_ENTRY,
                source="systemd-resolve --statistics",
                data={"raw": stdout.strip()},
            ))

    def _collect_dns_darwin(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command(["scutil", "--dns"])
        if rc != 0:
            return

        current_resolver: dict = {}
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("resolver"):
                if current_resolver:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.DNS_ENTRY,
                        source="scutil --dns",
                        data=dict(current_resolver),
                    ))
                current_resolver = {"resolver": stripped}
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                current_resolver[key.strip().lower().replace(" ", "_")] = val.strip()

        if current_resolver:
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.DNS_ENTRY,
                source="scutil --dns",
                data=dict(current_resolver),
            ))

    def _collect_arp(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["arp", "-a"])
            if rc != 0:
                return

            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith("address"):
                    continue

                parts = stripped.split()
                if len(parts) < 2:
                    continue

                hostname = ""
                ip = ""
                mac = ""

                if "(" in stripped and ")" in stripped:
                    hostname = parts[0] if not parts[0].startswith("(") else ""
                    ip_start = stripped.index("(") + 1
                    ip_end = stripped.index(")")
                    ip = stripped[ip_start:ip_end]
                    at_idx = None
                    for i, p in enumerate(parts):
                        if p == "at":
                            at_idx = i
                            break
                    if at_idx and at_idx + 1 < len(parts):
                        mac = parts[at_idx + 1]
                else:
                    ip = parts[0] if len(parts) > 0 else ""
                    mac = parts[1] if len(parts) > 1 else ""

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.ARP_ENTRY,
                    source="arp -a",
                    data={
                        "hostname": hostname,
                        "ip_address": ip,
                        "mac_address": mac,
                        "raw": stripped,
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect ARP table: %s", exc)
            result.errors.append(f"ARP table: {exc}")
