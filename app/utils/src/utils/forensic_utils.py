import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from logger import get_logger

log = get_logger("utils.forensic")


def normalize_timestamp(ts: float | int | str | datetime | None) -> str:
    if ts is None:
        return ""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    if isinstance(ts, str):
        return ts
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return str(ts)


def safe_read_file(path: str | Path, max_bytes: int = 10 * 1024 * 1024) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        return ""
    try:
        size = file_path.stat().st_size
        if size > max_bytes:
            log.debug("File too large, reading first %d bytes: %s", max_bytes, path)
            with open(file_path, "r", errors="replace") as f:
                return f.read(max_bytes)
        with open(file_path, "r", errors="replace") as f:
            return f.read()
    except (PermissionError, OSError) as e:
        log.debug("Cannot read file %s: %s", path, e)
        return ""


def resolve_user_paths(relative_path: str) -> list[Path]:
    system = platform.system()
    results = []

    if system == "Windows":
        users_dir = Path("C:/Users")
    elif system == "Darwin":
        users_dir = Path("/Users")
    else:
        users_dir = Path("/home")

    if not users_dir.is_dir():
        return results

    try:
        for user_dir in users_dir.iterdir():
            if user_dir.is_dir() and not user_dir.name.startswith("."):
                full_path = user_dir / relative_path
                if full_path.exists():
                    results.append(full_path)
    except PermissionError:
        pass

    root_path = Path.home() / relative_path
    if root_path.exists() and root_path not in results:
        results.append(root_path)

    return results


def run_command(
    cmd: list[str] | str,
    *,
    timeout: int = 30,
    shell: bool = False,
) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd}", 127
    except subprocess.TimeoutExpired:
        log.warning("Command timed out after %ds: %s", timeout, cmd)
        return "", "timeout", -1
    except Exception as e:
        log.warning("Command failed: %s — %s", cmd, e)
        return "", str(e), -1
