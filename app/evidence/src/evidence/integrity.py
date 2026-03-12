import hashlib
import json
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from evidence.types import AuditEvent, ChainOfCustody, ManifestEntry
from logger import get_logger
from settings import VERSION

log = get_logger("evidence.integrity")


class EvidenceIntegrity:
    def __init__(self, output_dir: Path, case_id: str = "", examiner: str = ""):
        self.output_dir = Path(output_dir)
        self.case_id = case_id
        self.examiner = examiner
        self.manifest_entries: list[ManifestEntry] = []
        self.audit_events: list[AuditEvent] = []
        self._start_time = ""

    def start_collection(self) -> None:
        self._start_time = datetime.now(timezone.utc).isoformat()
        self.log_event("collection_start", "engine", "Collection started")

    def log_event(self, action: str, component: str, detail: str = "", success: bool = True) -> None:
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            component=component,
            detail=detail,
            success=success,
        )
        self.audit_events.append(event)

    def register_file(self, file_path: Path) -> None:
        if not file_path.is_file():
            return
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            relative = str(file_path.relative_to(self.output_dir)) if str(file_path).startswith(str(self.output_dir)) else str(file_path)
            entry = ManifestEntry(
                file_path=relative,
                sha256=sha256.hexdigest(),
                size_bytes=file_path.stat().st_size,
                collected_at=datetime.now(timezone.utc).isoformat(),
            )
            self.manifest_entries.append(entry)
        except (PermissionError, OSError) as e:
            log.warning("Cannot hash file for manifest: %s — %s", file_path, e)

    def register_directory(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file() and file_path.name not in ("manifest.json", "audit.log", "chain_of_custody.json"):
                self.register_file(file_path)

    def finalize(self, total_artifacts: int = 0) -> None:
        self.log_event("collection_end", "engine", "Collection completed")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._write_audit_log()
        self._write_manifest()
        manifest_hash = self._hash_manifest()
        self._write_chain_of_custody(total_artifacts, manifest_hash)

    def _write_audit_log(self) -> None:
        audit_path = self.output_dir / "audit.log"
        with open(audit_path, "w") as f:
            for event in self.audit_events:
                status = "OK" if event.success else "FAIL"
                f.write(f"[{event.timestamp}] [{status}] {event.component}: {event.action} — {event.detail}\n")
        log.info("Audit log written to %s", audit_path)

    def _write_manifest(self) -> None:
        manifest_path = self.output_dir / "manifest.json"
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "file_count": len(self.manifest_entries),
            "files": [entry.model_dump() for entry in self.manifest_entries],
        }
        with open(manifest_path, "w") as f:
            json.dump(data, f, indent=2)
        log.info("Manifest written to %s (%d files)", manifest_path, len(self.manifest_entries))

    def _hash_manifest(self) -> str:
        manifest_path = self.output_dir / "manifest.json"
        if not manifest_path.is_file():
            return ""
        sha256 = hashlib.sha256()
        with open(manifest_path, "rb") as f:
            sha256.update(f.read())
        return sha256.hexdigest()

    def _write_chain_of_custody(self, total_artifacts: int, manifest_hash: str) -> None:
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        coc = ChainOfCustody(
            case_id=self.case_id,
            examiner=self.examiner,
            tool_version=VERSION,
            hostname=hostname,
            os_info=f"{platform.system()} {platform.release()} {platform.version()}",
            collection_start=self._start_time,
            collection_end=datetime.now(timezone.utc).isoformat(),
            manifest_sha256=manifest_hash,
            total_artifacts=total_artifacts,
            total_files=len(self.manifest_entries),
        )
        coc_path = self.output_dir / "chain_of_custody.json"
        with open(coc_path, "w") as f:
            json.dump(coc.model_dump(), f, indent=2)
        log.info("Chain of custody written to %s", coc_path)

    @staticmethod
    def verify(output_dir: Path) -> tuple[bool, list[str]]:
        manifest_path = Path(output_dir) / "manifest.json"
        if not manifest_path.is_file():
            return False, ["manifest.json not found"]

        with open(manifest_path) as f:
            data = json.load(f)

        errors = []
        for entry_data in data.get("files", []):
            entry = ManifestEntry(**entry_data)
            file_path = Path(output_dir) / entry.file_path
            if not file_path.is_file():
                errors.append(f"MISSING: {entry.file_path}")
                continue
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            if sha256.hexdigest() != entry.sha256:
                errors.append(f"HASH MISMATCH: {entry.file_path} (expected {entry.sha256}, got {sha256.hexdigest()})")

        return len(errors) == 0, errors
