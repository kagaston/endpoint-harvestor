import platform
import re
import time

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from logger import get_logger

log = get_logger("collectors.usb_devices")


class USBDeviceCollector:
    @property
    def name(self) -> str:
        return "usb_devices"

    @property
    def display_name(self) -> str:
        return "USB Devices"

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
                self._collect_windows_usb(result)
                self._collect_windows_usbstor(result)
                self._collect_windows_setupapi(result)
            elif system == "Linux":
                self._collect_linux_syslog(result)
                self._collect_linux_lsusb(result)
                self._collect_linux_sysfs(result)
            elif system == "Darwin":
                self._collect_macos_profiler(result)
                self._collect_macos_ioreg(result)
        except Exception as exc:
            log.error("Unexpected error during USB device collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # -- Windows -----------------------------------------------------------

    def _collect_windows_usb(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USB", "/s"],
                timeout=60,
            )
            if rc != 0 or not stdout.strip():
                return
            self._parse_windows_reg_usb(result, stdout, "USB")
        except Exception as exc:
            log.warning("Failed to collect Windows USB registry: %s", exc)
            result.errors.append(f"Windows USB registry: {exc}")

    def _collect_windows_usbstor(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", "/s"],
                timeout=60,
            )
            if rc != 0 or not stdout.strip():
                return
            self._parse_windows_reg_usb(result, stdout, "USBSTOR")
        except Exception as exc:
            log.warning("Failed to collect Windows USBSTOR registry: %s", exc)
            result.errors.append(f"Windows USBSTOR registry: {exc}")

    def _parse_windows_reg_usb(
        self, result: CollectorResult, output: str, source: str
    ) -> None:
        current: dict[str, str] = {}
        current_key = ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USB_DEVICE,
                        source=source,
                        data={
                            "device_name": current.get("DeviceDesc", ""),
                            "vendor_id": current.get("VID", ""),
                            "product_id": current.get("PID", ""),
                            "serial_number": current.get("serial", ""),
                            "registry_key": current_key,
                        },
                    ))
                    current = {}
                continue

            if line.startswith("HKEY_"):
                current_key = line
                parts = line.rsplit("\\", 1)
                if len(parts) == 2:
                    tail = parts[1]
                    vid_match = re.search(r"VID_([0-9A-Fa-f]+)", tail)
                    pid_match = re.search(r"PID_([0-9A-Fa-f]+)", tail)
                    if vid_match:
                        current["VID"] = vid_match.group(1)
                    if pid_match:
                        current["PID"] = pid_match.group(1)
                    if not vid_match and not pid_match and "&" not in tail:
                        current["serial"] = tail
            else:
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    current[parts[0]] = parts[2]

        if current:
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.USB_DEVICE,
                source=source,
                data={
                    "device_name": current.get("DeviceDesc", ""),
                    "vendor_id": current.get("VID", ""),
                    "product_id": current.get("PID", ""),
                    "serial_number": current.get("serial", ""),
                    "registry_key": current_key,
                },
            ))

    def _collect_windows_setupapi(self, result: CollectorResult) -> None:
        try:
            log_path = r"C:\Windows\inf\setupapi.dev.log"
            content = safe_read_file(log_path)
            if not content:
                return

            for line in content.splitlines():
                if "USB" in line.upper() and ("install" in line.lower() or "device" in line.lower()):
                    ts_match = re.search(
                        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", line
                    )
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USB_DEVICE,
                        source="setupapi.dev.log",
                        timestamp=ts_match.group(1) if ts_match else "",
                        data={
                            "raw_entry": line.strip(),
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to parse setupapi.dev.log: %s", exc)
            result.errors.append(f"setupapi.dev.log: {exc}")

    # -- Linux -------------------------------------------------------------

    def _collect_linux_syslog(self, result: CollectorResult) -> None:
        try:
            for log_path in ("/var/log/syslog", "/var/log/messages"):
                content = safe_read_file(log_path)
                if not content:
                    continue
                for line in content.splitlines():
                    lower = line.lower()
                    if "usb" not in lower:
                        continue
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USB_DEVICE,
                        source=log_path,
                        data={"raw_entry": line.strip()},
                    ))
        except Exception as exc:
            log.warning("Failed to parse syslog for USB entries: %s", exc)
            result.errors.append(f"Linux syslog USB: {exc}")

    def _collect_linux_lsusb(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["lsusb"])
            if rc != 0 or not stdout.strip():
                return

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = re.match(
                    r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\s*(.*)",
                    line,
                )
                if match:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USB_DEVICE,
                        source="lsusb",
                        data={
                            "bus": match.group(1),
                            "device_number": match.group(2),
                            "vendor_id": match.group(3),
                            "product_id": match.group(4),
                            "device_name": match.group(5).strip(),
                        },
                    ))
        except Exception as exc:
            log.warning("Failed to run lsusb: %s", exc)
            result.errors.append(f"lsusb: {exc}")

    def _collect_linux_sysfs(self, result: CollectorResult) -> None:
        try:
            from pathlib import Path

            sysfs = Path("/sys/bus/usb/devices")
            if not sysfs.is_dir():
                return

            for dev_dir in sysfs.iterdir():
                if not dev_dir.is_dir():
                    continue
                vendor_file = dev_dir / "idVendor"
                product_file = dev_dir / "idProduct"
                if not vendor_file.exists():
                    continue

                data: dict[str, str] = {
                    "device_path": str(dev_dir),
                    "vendor_id": safe_read_file(vendor_file).strip(),
                    "product_id": safe_read_file(product_file).strip() if product_file.exists() else "",
                }
                manufacturer = dev_dir / "manufacturer"
                product = dev_dir / "product"
                serial = dev_dir / "serial"
                if manufacturer.exists():
                    data["device_name"] = safe_read_file(manufacturer).strip()
                if product.exists():
                    data["product_name"] = safe_read_file(product).strip()
                if serial.exists():
                    data["serial_number"] = safe_read_file(serial).strip()

                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.USB_DEVICE,
                    source="/sys/bus/usb/devices",
                    data=data,
                ))
        except Exception as exc:
            log.warning("Failed to read /sys/bus/usb/devices: %s", exc)
            result.errors.append(f"sysfs USB: {exc}")

    # -- macOS -------------------------------------------------------------

    def _collect_macos_profiler(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(
                ["system_profiler", "SPUSBDataType"], timeout=60
            )
            if rc != 0 or not stdout.strip():
                return

            current: dict[str, str] = {}
            for line in stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue

                if ":" not in stripped:
                    if current:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.USB_DEVICE,
                            source="system_profiler SPUSBDataType",
                            data=dict(current),
                        ))
                    current = {"device_name": stripped.rstrip(":")}
                    continue

                key, _, value = stripped.partition(":")
                value = value.strip()
                key_lower = key.strip().lower()
                if "vendor" in key_lower and "id" in key_lower:
                    current["vendor_id"] = value
                elif "product" in key_lower and "id" in key_lower:
                    current["product_id"] = value
                elif "serial" in key_lower:
                    current["serial_number"] = value
                elif key_lower in ("manufacturer", "vendor_id"):
                    current.setdefault("vendor_id", value)

            if current:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.USB_DEVICE,
                    source="system_profiler SPUSBDataType",
                    data=dict(current),
                ))
        except Exception as exc:
            log.warning("Failed to collect macOS USB profiler data: %s", exc)
            result.errors.append(f"system_profiler USB: {exc}")

    def _collect_macos_ioreg(self, result: CollectorResult) -> None:
        try:
            stdout, _, rc = run_command(["ioreg", "-p", "IOUSB", "-l"])
            if rc != 0 or not stdout.strip():
                return

            current: dict[str, str] = {}
            for line in stdout.splitlines():
                stripped = line.strip()
                if "+-o" in stripped:
                    if current:
                        result.artifacts.append(Artifact(
                            artifact_type=ArtifactType.USB_DEVICE,
                            source="ioreg IOUSB",
                            data=dict(current),
                        ))
                    name_match = re.search(r"\+-o\s+(.+?)\s+<", stripped)
                    current = {
                        "device_name": name_match.group(1) if name_match else stripped,
                    }
                    continue

                if "=" in stripped:
                    key, _, value = stripped.partition("=")
                    key = key.strip().strip('"')
                    value = value.strip().strip('"')
                    key_lower = key.lower()
                    if key_lower == "idvendor":
                        current["vendor_id"] = value
                    elif key_lower == "idproduct":
                        current["product_id"] = value
                    elif key_lower in ("usb serial number", "kusbbserialstring"):
                        current["serial_number"] = value

            if current:
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.USB_DEVICE,
                    source="ioreg IOUSB",
                    data=dict(current),
                ))
        except Exception as exc:
            log.warning("Failed to collect macOS ioreg USB data: %s", exc)
            result.errors.append(f"ioreg USB: {exc}")
