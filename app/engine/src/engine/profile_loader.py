from pathlib import Path

import yaml

from errors import ProfileError
from logger import get_logger

log = get_logger("engine.profile")

_PROFILES_DIR = Path(__file__).resolve().parents[4] / "profiles"


class CollectionProfile:
    def __init__(
        self,
        name: str,
        description: str = "",
        timeout: int = 300,
        hash_files: bool = False,
        yara_scan: bool = False,
        collectors: list[str] | None = None,
    ):
        self.name = name
        self.description = description
        self.timeout = timeout
        self.hash_files = hash_files
        self.yara_scan = yara_scan
        self.collectors = collectors or []

    def __repr__(self) -> str:
        return f"CollectionProfile(name={self.name!r}, collectors={len(self.collectors)})"


def load_profile(name: str, profiles_dir: Path | None = None) -> CollectionProfile:
    search_dir = Path(profiles_dir) if profiles_dir else _PROFILES_DIR
    profile_path = search_dir / f"{name}.yaml"

    if not profile_path.is_file():
        profile_path = search_dir / f"{name}.yml"
    if not profile_path.is_file():
        raise ProfileError(f"Profile not found: {name} (searched {search_dir})")

    try:
        with open(profile_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ProfileError(f"Invalid YAML in profile {name}: {e}") from e

    if not isinstance(data, dict):
        raise ProfileError(f"Profile {name} must be a YAML mapping")

    log.info("Loaded profile: %s (%d collectors)", name, len(data.get("collectors", [])))

    return CollectionProfile(
        name=data.get("name", name),
        description=data.get("description", ""),
        timeout=data.get("timeout", 300),
        hash_files=data.get("hash_files", False),
        yara_scan=data.get("yara_scan", False),
        collectors=data.get("collectors", []),
    )


def list_profiles(profiles_dir: Path | None = None) -> list[str]:
    search_dir = Path(profiles_dir) if profiles_dir else _PROFILES_DIR
    if not search_dir.is_dir():
        return []
    return sorted(
        p.stem for p in search_dir.iterdir()
        if p.suffix in (".yaml", ".yml")
    )
