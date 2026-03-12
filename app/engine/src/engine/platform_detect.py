import platform

from logger import get_logger

log = get_logger("engine.platform")

SUPPORTED_PLATFORMS = ["Windows", "Linux", "Darwin"]


def get_platform() -> str:
    return platform.system()


def is_supported() -> bool:
    return get_platform() in SUPPORTED_PLATFORMS


def get_platform_info() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }


def filter_by_platform(supported_platforms: list[str]) -> bool:
    return get_platform() in supported_platforms
