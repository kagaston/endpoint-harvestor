import platform
import time

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger

log = get_logger("collectors.firewall")


class FirewallCollector:
    @property
    def name(self) -> str:
        return "firewall"

    @property
    def display_name(self) -> str:
        return "Firewall Rules"

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
            log.error("Unexpected error during firewall collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        self._collect_windows_profile_status(result)
        self._collect_windows_rules(result, "in")
        self._collect_windows_rules(result, "out")

    def _collect_windows_profile_status(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["netsh", "advfirewall", "show", "allprofiles"],
            )
            if rc != 0:
                result.errors.append(f"Firewall profile status failed (rc={rc}): {stderr}")
                return

            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.FIREWALL_RULE,
                source="netsh advfirewall show allprofiles",
                data={"type": "profile_status", "raw": stdout.strip()},
            ))
        except Exception as exc:
            log.warning("Failed to collect firewall profile status: %s", exc)
            result.errors.append(f"Firewall profile status: {exc}")

    def _collect_windows_rules(self, result: CollectorResult, direction: str) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all", f"dir={direction}"],
                timeout=60,
            )
            if rc != 0:
                result.errors.append(
                    f"Firewall rules dir={direction} failed (rc={rc}): {stderr}",
                )
                return

            current: dict[str, str] = {}
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("-"):
                    if current:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.FIREWALL_RULE,
                            source=f"netsh advfirewall firewall (dir={direction})",
                            data=dict(current),
                        ))
                        current = {}
                    continue
                if ":" in stripped:
                    key, _, value = stripped.partition(":")
                    normalised_key = key.strip().lower().replace(" ", "_")
                    current[normalised_key] = value.strip()

            if current:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source=f"netsh advfirewall firewall (dir={direction})",
                    data=dict(current),
                ))
        except Exception as exc:
            log.warning("Failed to collect firewall rules (dir=%s): %s", direction, exc)
            result.errors.append(f"Firewall rules dir={direction}: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        self._collect_iptables(result)
        self._collect_nftables(result)
        self._collect_ufw(result)

    def _collect_iptables(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(["iptables", "-L", "-n", "-v"])
            if rc != 0:
                log.debug("iptables not available or no permission (rc=%d): %s", rc, stderr)
                return

            current_chain = ""
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("Chain "):
                    current_chain = stripped.split()[1] if len(stripped.split()) > 1 else stripped
                    continue
                if stripped.lower().startswith("pkts") or stripped.lower().startswith("num"):
                    continue

                parts = stripped.split()
                if len(parts) >= 7:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.FIREWALL_RULE,
                        source="iptables",
                        data={
                            "chain": current_chain,
                            "target": parts[2] if len(parts) > 2 else "",
                            "protocol": parts[3] if len(parts) > 3 else "",
                            "source": parts[7] if len(parts) > 7 else "",
                            "destination": parts[8] if len(parts) > 8 else "",
                            "raw": stripped,
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to collect iptables rules: %s", exc)
            result.errors.append(f"iptables: {exc}")

    def _collect_nftables(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(["nft", "list", "ruleset"])
            if rc != 0:
                log.debug("nftables not available (rc=%d): %s", rc, stderr)
                return

            current_chain = ""
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped in ("{", "}"):
                    continue
                if stripped.startswith("chain "):
                    current_chain = stripped.split()[1] if len(stripped.split()) > 1 else stripped
                    continue
                if stripped.startswith("table ") or stripped.startswith("type "):
                    continue

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source="nftables",
                    data={
                        "chain": current_chain,
                        "rule": stripped,
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect nftables rules: %s", exc)
            result.errors.append(f"nftables: {exc}")

    def _collect_ufw(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(["ufw", "status", "verbose"])
            if rc != 0:
                log.debug("ufw not available (rc=%d): %s", rc, stderr)
                return

            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("Status:") or stripped.startswith("--"):
                    continue

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source="ufw",
                    data={"rule": stripped},
                ))
        except Exception as exc:
            log.warning("Failed to collect ufw rules: %s", exc)
            result.errors.append(f"ufw: {exc}")

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        self._collect_pf_rules(result)
        self._collect_application_firewall(result)

    def _collect_pf_rules(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(["pfctl", "-sr"])
            if rc != 0:
                log.debug("pfctl not available or no permission (rc=%d): %s", rc, stderr)
                result.errors.append(f"pfctl (rc={rc}): {stderr}")
                return

            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source="pfctl -sr",
                    data={"rule": stripped},
                ))
        except Exception as exc:
            log.warning("Failed to collect pf rules: %s", exc)
            result.errors.append(f"pfctl: {exc}")

    def _collect_application_firewall(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            )
            if rc == 0 and stdout.strip():
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source="socketfilterfw --getglobalstate",
                    data={"type": "global_state", "state": stdout.strip()},
                ))
        except Exception as exc:
            log.warning("Failed to get application firewall state: %s", exc)
            result.errors.append(f"socketfilterfw global state: {exc}")

        try:
            stdout, stderr, rc = run_command(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"],
            )
            if rc != 0:
                return

            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.FIREWALL_RULE,
                    source="socketfilterfw --listapps",
                    data={"type": "app_rule", "entry": stripped},
                ))
        except Exception as exc:
            log.warning("Failed to list application firewall apps: %s", exc)
            result.errors.append(f"socketfilterfw list apps: {exc}")
