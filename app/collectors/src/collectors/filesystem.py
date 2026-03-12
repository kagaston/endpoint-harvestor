import os
import platform
import stat
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command, safe_read_file
from utils.hashing import hash_file
from settings import MAX_FILE_HASH_SIZE
from logger import get_logger

log = get_logger("collectors.filesystem")


class FilesystemCollector:
    def __init__(self, hash_files: bool = False, scan_depth: int = 3) -> None:
        self.hash_files = hash_files
        self.scan_depth = scan_depth

    @property
    def name(self) -> str:
        return "filesystem"

    @property
    def display_name(self) -> str:
        return "Filesystem Artifacts"

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
            scan_dirs = self._get_scan_dirs(system)
            for scan_dir in scan_dirs:
                self._scan_directory(Path(scan_dir), result, current_depth=0)
        except Exception as exc:
            log.error("Unexpected error during filesystem collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _get_scan_dirs(self, system: str) -> list[str]:
        home = str(Path.home())

        if system == "Windows":
            temp = os.environ.get("TEMP", r"C:\Windows\Temp")
            userprofile = os.environ.get("USERPROFILE", home)
            return [
                temp,
                os.path.join(userprofile, "Downloads"),
                os.path.join(userprofile, "Recent"),
                r"C:\Windows\Prefetch",
            ]
        elif system == "Linux":
            return [
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                os.path.join(home, "Downloads"),
            ]
        elif system == "Darwin":
            return [
                "/tmp",
                "/var/tmp",
                os.path.join(home, "Downloads"),
                os.path.join(home, "Library", "Recent"),
            ]
        return []

    def _scan_directory(
        self,
        directory: Path,
        result: CollectorResult,
        current_depth: int,
    ) -> None:
        if current_depth >= self.scan_depth:
            return
        if not directory.is_dir():
            return

        try:
            for entry in directory.iterdir():
                try:
                    if entry.is_file():
                        self._process_file(entry, result)
                    elif entry.is_dir() and not entry.is_symlink():
                        self._scan_directory(entry, result, current_depth + 1)
                except PermissionError:
                    continue
                except Exception as exc:
                    log.debug("Error processing %s: %s", entry, exc)
        except PermissionError:
            log.debug("Permission denied listing directory: %s", directory)
        except Exception as exc:
            log.warning("Failed to scan directory %s: %s", directory, exc)
            result.errors.append(f"Directory scan {directory}: {exc}")

    def _process_file(self, file_path: Path, result: CollectorResult) -> None:
        try:
            st = file_path.stat()
        except (PermissionError, OSError) as exc:
            log.debug("Cannot stat %s: %s", file_path, exc)
            return

        file_data: dict = {
            "name": file_path.name,
            "path": str(file_path),
            "size": st.st_size,
            "created": normalize_timestamp(st.st_ctime),
            "modified": normalize_timestamp(st.st_mtime),
            "accessed": normalize_timestamp(st.st_atime),
            "permissions": stat.filemode(st.st_mode),
        }

        if self.hash_files and st.st_size <= MAX_FILE_HASH_SIZE:
            try:
                file_data["hashes"] = hash_file(file_path)
            except Exception as exc:
                log.debug("Failed to hash %s: %s", file_path, exc)
                file_data["hashes"] = {}

        result.artifacts.append(Artifact(
            artifact_type=ArtifactType.FILE_ENTRY,
            source=str(file_path.parent),
            timestamp=normalize_timestamp(st.st_mtime),
            data=file_data,
        ))
