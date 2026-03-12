import ctypes
import os
import platform
import getpass

from logger import get_logger

log = get_logger("utils.privileges")


def is_admin() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def require_admin(action: str = "this operation") -> None:
    if not is_admin():
        log.warning(
            "Running without elevated privileges. Some %s data may be incomplete.",
            action,
        )


def get_current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
