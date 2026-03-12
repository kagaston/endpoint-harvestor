import platform
import subprocess
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.certificates")

_MAX_CERTS = 200


class CertificateCollector:
    @property
    def name(self) -> str:
        return "certificates"

    @property
    def display_name(self) -> str:
        return "Certificate Store"

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
            log.error("Unexpected error during certificate collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        stores = [
            ("Root", "Trusted Root CAs"),
            ("CA", "Intermediate CAs"),
            ("My", "Personal"),
        ]
        for store_name, description in stores:
            self._collect_certutil_store(result, store_name, description)

    def _collect_certutil_store(
        self, result: CollectorResult, store_name: str, description: str,
    ) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["certutil", "-store", store_name], timeout=60,
            )
            if rc != 0:
                result.errors.append(
                    f"certutil -store {store_name} failed (rc={rc}): {stderr}",
                )
                return

            current: dict[str, str] = {}
            for line in stdout.splitlines():
                stripped = line.strip()

                if stripped.startswith("==============="):
                    if current.get("subject") or current.get("serial"):
                        current["store_name"] = store_name
                        current["store_description"] = description
                        current["is_self_signed"] = str(
                            current.get("subject", "") == current.get("issuer", ""),
                        )
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.CERTIFICATE,
                            source=f"certutil -store {store_name}",
                            data=dict(current),
                        ))
                    current = {}
                    continue

                if ":" in stripped:
                    key, _, value = stripped.partition(":")
                    key_lower = key.strip().lower()
                    val = value.strip()

                    if "subject" in key_lower:
                        current["subject"] = val
                    elif "issuer" in key_lower:
                        current["issuer"] = val
                    elif "serial" in key_lower:
                        current["serial_number"] = val
                    elif "thumb" in key_lower or "hash" in key_lower:
                        current["thumbprint"] = val
                    elif "notbefore" in key_lower or "not before" in key_lower:
                        current["not_before"] = val
                    elif "notafter" in key_lower or "not after" in key_lower:
                        current["not_after"] = val

            if current.get("subject") or current.get("serial"):
                current["store_name"] = store_name
                current["store_description"] = description
                current["is_self_signed"] = str(
                    current.get("subject", "") == current.get("issuer", ""),
                )
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.CERTIFICATE,
                    source=f"certutil -store {store_name}",
                    data=dict(current),
                ))
        except Exception as exc:
            log.warning("Failed to collect cert store %s: %s", store_name, exc)
            result.errors.append(f"certutil store {store_name}: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        cert_dirs = [
            Path("/etc/ssl/certs"),
            Path("/usr/local/share/ca-certificates"),
        ]
        count = 0
        for cert_dir in cert_dirs:
            if not cert_dir.is_dir():
                continue
            try:
                for cert_file in cert_dir.iterdir():
                    if count >= _MAX_CERTS:
                        log.debug("Reached cert cap (%d), stopping", _MAX_CERTS)
                        return
                    if not cert_file.is_file():
                        continue
                    if cert_file.suffix not in (".pem", ".crt"):
                        continue
                    self._parse_openssl_cert(result, cert_file, str(cert_dir))
                    count += 1
            except PermissionError:
                result.errors.append(f"Permission denied: {cert_dir}")
            except Exception as exc:
                log.warning("Failed to list %s: %s", cert_dir, exc)
                result.errors.append(f"Cert dir {cert_dir}: {exc}")

    def _parse_openssl_cert(
        self, result: CollectorResult, cert_path: Path, store_name: str,
    ) -> None:
        try:
            stdout, stderr, rc = run_command([
                "openssl", "x509", "-in", str(cert_path), "-noout",
                "-subject", "-issuer", "-serial", "-dates", "-fingerprint",
            ])
            if rc != 0:
                log.debug("openssl failed for %s (rc=%d): %s", cert_path, rc, stderr)
                return

            data: dict[str, str] = {"store_name": store_name, "file": str(cert_path)}
            for line in stdout.splitlines():
                stripped = line.strip()
                if "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key_lower = key.strip().lower()

                if key_lower == "subject":
                    data["subject"] = value.strip()
                elif key_lower == "issuer":
                    data["issuer"] = value.strip()
                elif key_lower.startswith("serial"):
                    data["serial_number"] = value.strip()
                elif "fingerprint" in key_lower:
                    data["thumbprint"] = value.strip()
                elif key_lower == "notbefore":
                    data["not_before"] = value.strip()
                elif key_lower == "notafter":
                    data["not_after"] = value.strip()

            data["is_self_signed"] = str(
                data.get("subject", "") == data.get("issuer", ""),
            )
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.CERTIFICATE,
                source=f"openssl x509 ({store_name})",
                data=data,
            ))
        except Exception as exc:
            log.debug("Failed to parse cert %s: %s", cert_path, exc)

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        keychains = [
            ("/Library/Keychains/System.keychain", "System"),
            (
                str(Path.home() / "Library" / "Keychains" / "login.keychain-db"),
                "Login",
            ),
        ]
        for keychain_path, store_name in keychains:
            self._collect_darwin_keychain(result, keychain_path, store_name)

    def _collect_darwin_keychain(
        self, result: CollectorResult, keychain_path: str, store_name: str,
    ) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["security", "find-certificate", "-a", "-p", keychain_path],
                timeout=60,
            )
            if rc != 0:
                log.debug(
                    "security find-certificate failed for %s (rc=%d): %s",
                    keychain_path, rc, stderr,
                )
                result.errors.append(
                    f"Keychain {keychain_path} (rc={rc}): {stderr}",
                )
                return

            pem_blocks: list[str] = []
            current_block: list[str] = []
            in_block = False

            for line in stdout.splitlines():
                if "BEGIN CERTIFICATE" in line:
                    in_block = True
                    current_block = [line]
                elif "END CERTIFICATE" in line:
                    current_block.append(line)
                    pem_blocks.append("\n".join(current_block))
                    current_block = []
                    in_block = False
                elif in_block:
                    current_block.append(line)

            count = 0
            for pem in pem_blocks:
                if count >= _MAX_CERTS:
                    log.debug("Reached cert cap (%d) for %s", _MAX_CERTS, keychain_path)
                    break

                cert_data = self._parse_pem_with_openssl(pem, keychain_path, store_name)
                if cert_data:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.CERTIFICATE,
                        source=f"security find-certificate ({store_name})",
                        data=cert_data,
                    ))
                    count += 1
        except Exception as exc:
            log.warning("Failed to collect keychain %s: %s", keychain_path, exc)
            result.errors.append(f"Keychain {keychain_path}: {exc}")

    def _parse_pem_with_openssl(
        self, pem_text: str, keychain_path: str, store_name: str,
    ) -> dict[str, str] | None:
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-noout",
                 "-subject", "-issuer", "-serial", "-dates", "-fingerprint"],
                input=pem_text,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                return None

            data: dict[str, str] = {
                "store_name": store_name,
                "keychain": keychain_path,
            }
            for line in proc.stdout.splitlines():
                stripped = line.strip()
                if "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key_lower = key.strip().lower()

                if key_lower == "subject":
                    data["subject"] = value.strip()
                elif key_lower == "issuer":
                    data["issuer"] = value.strip()
                elif key_lower.startswith("serial"):
                    data["serial_number"] = value.strip()
                elif "fingerprint" in key_lower:
                    data["thumbprint"] = value.strip()
                elif key_lower == "notbefore":
                    data["not_before"] = value.strip()
                elif key_lower == "notafter":
                    data["not_after"] = value.strip()

            data["is_self_signed"] = str(
                data.get("subject", "") == data.get("issuer", ""),
            )
            return data
        except Exception as exc:
            log.debug("Failed to parse PEM block: %s", exc)
            return None
