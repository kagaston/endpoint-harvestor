import base64
import platform
import re
import time

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.clipboard")

_MAX_CLIPBOARD_BYTES = 10 * 1024  # 10 KB

_IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


class ClipboardCollector:
    @property
    def name(self) -> str:
        return "clipboard"

    @property
    def display_name(self) -> str:
        return "Clipboard Contents"

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
            log.error("Unexpected error during clipboard collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _build_clipboard_artifact(self, content: str, source: str) -> Artifact:
        truncated = content[:_MAX_CLIPBOARD_BYTES]
        has_urls = bool(_URL_PATTERN.search(truncated))
        has_ips = bool(_IP_PATTERN.search(truncated))
        has_base64 = self._looks_like_base64(truncated)

        iocs: list[str] = []
        if has_ips:
            iocs.extend(_IP_PATTERN.findall(truncated))
        if has_urls:
            iocs.extend(_URL_PATTERN.findall(truncated))

        return Artifact(
            artifact_type=ArtifactType.CLIPBOARD_CONTENT,
            source=source,
            data={
                "content": truncated,
                "content_length": len(content),
                "truncated": len(content) > _MAX_CLIPBOARD_BYTES,
                "has_urls": has_urls,
                "has_ips": has_ips,
                "has_base64": has_base64,
                "iocs": iocs if iocs else [],
            },
        )

    @staticmethod
    def _looks_like_base64(text: str) -> bool:
        candidates = _BASE64_PATTERN.findall(text)
        for candidate in candidates:
            try:
                decoded = base64.b64decode(candidate, validate=True)
                if len(decoded) > 8:
                    return True
            except Exception:
                continue
        return False

    # ── Windows ──────────────────────────────────────────────────────────

    def _collect_windows(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(
                ["powershell", "-Command", "Get-Clipboard"],
            )
            if rc != 0:
                result.errors.append(f"Get-Clipboard failed (rc={rc}): {stderr}")
                return
            if stdout.strip():
                result.artifacts.append(
                    self._build_clipboard_artifact(stdout, "powershell Get-Clipboard"),
                )
        except Exception as exc:
            log.warning("Failed to collect Windows clipboard: %s", exc)
            result.errors.append(f"Windows clipboard: {exc}")

    # ── Linux ────────────────────────────────────────────────────────────

    def _collect_linux(self, result: CollectorResult) -> None:
        commands = [
            (["xclip", "-selection", "clipboard", "-o"], "xclip"),
            (["xsel", "--clipboard", "--output"], "xsel"),
            (["wl-paste"], "wl-paste"),
        ]
        for cmd, source in commands:
            try:
                stdout, _, rc = run_command(cmd, timeout=5)
                if rc == 0 and stdout.strip():
                    result.artifacts.append(
                        self._build_clipboard_artifact(stdout, source),
                    )
                    return
            except Exception:
                continue

        log.debug("No clipboard tool available on Linux")
        result.errors.append(
            "No clipboard tool available (tried xclip, xsel, wl-paste)",
        )

    # ── macOS ────────────────────────────────────────────────────────────

    def _collect_darwin(self, result: CollectorResult) -> None:
        try:
            stdout, stderr, rc = run_command(["pbpaste"])
            if rc != 0:
                result.errors.append(f"pbpaste failed (rc={rc}): {stderr}")
                return
            if stdout.strip():
                result.artifacts.append(
                    self._build_clipboard_artifact(stdout, "pbpaste"),
                )
        except Exception as exc:
            log.warning("Failed to collect macOS clipboard: %s", exc)
            result.errors.append(f"macOS clipboard: {exc}")
