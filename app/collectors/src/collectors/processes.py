import platform
import time

import psutil

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp
from logger import get_logger

log = get_logger("collectors.processes")


class ProcessCollector:
    def __init__(self, hash_executables: bool = False) -> None:
        self.hash_executables = hash_executables

    @property
    def name(self) -> str:
        return "processes"

    @property
    def display_name(self) -> str:
        return "Running Processes"

    @property
    def supported_platforms(self) -> list[str]:
        return ["Windows", "Linux", "Darwin"]

    def collect(self) -> CollectorResult:
        start = time.time()
        result = CollectorResult(
            collector_name=self.name,
            platform=platform.system(),
            timestamp=normalize_timestamp(time.time()),
        )

        try:
            attrs = [
                "pid", "name", "cmdline", "username", "ppid",
                "status", "create_time", "exe", "cwd",
            ]
            for proc in psutil.process_iter(attrs=attrs):
                try:
                    info = proc.info
                    parent_name = ""
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    cmdline_parts = info.get("cmdline")
                    cmdline_str = " ".join(cmdline_parts) if cmdline_parts else ""

                    create_time = info.get("create_time")
                    create_ts = normalize_timestamp(create_time) if create_time else ""

                    exe_path = info.get("exe") or ""

                    proc_data: dict = {
                        "pid": info.get("pid"),
                        "name": info.get("name", ""),
                        "cmdline": cmdline_str,
                        "username": info.get("username", ""),
                        "ppid": info.get("ppid"),
                        "parent_name": parent_name,
                        "status": info.get("status", ""),
                        "create_time": create_ts,
                        "exe": exe_path,
                        "cwd": info.get("cwd", ""),
                    }

                    if self.hash_executables and exe_path:
                        try:
                            from utils.hashing import hash_file
                            proc_data["hashes"] = hash_file(exe_path)
                        except Exception as hex_exc:
                            log.debug(
                                "Failed to hash exe for pid %s: %s",
                                info.get("pid"), hex_exc,
                            )
                            proc_data["hashes"] = {}

                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.PROCESS,
                        source="psutil",
                        timestamp=create_ts,
                        data=proc_data,
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as exc:
                    log.debug("Error collecting process: %s", exc)
                    result.errors.append(f"Process error: {exc}")
        except Exception as exc:
            log.error("Unexpected error during process collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result
