import yaml

import pytest

from engine import (
    CollectionProfile,
    get_platform,
    get_platform_info,
    is_supported,
    list_profiles,
    load_profile,
)
from errors import ProfileError


PROFILES_DIR_MARKER = "profiles"


class TestProfileLoader:
    @pytest.fixture()
    def profiles_dir(self, tmp_path):
        """Create a temp profiles directory with known YAML profiles."""
        quick = {
            "name": "quick",
            "description": "Quick triage",
            "timeout": 60,
            "hash_files": False,
            "yara_scan": False,
            "collectors": ["system_info", "processes", "network", "users", "persistence"],
        }
        standard_collectors = [
            "system_info", "processes", "network", "users", "persistence",
            "filesystem", "logs", "browser", "shell_history", "usb_devices",
            "installed_software", "kernel_modules", "firewall", "environment",
            "clipboard", "certificates",
        ]
        standard = {
            "name": "standard",
            "description": "Standard collection",
            "timeout": 300,
            "hash_files": False,
            "yara_scan": False,
            "collectors": standard_collectors,
        }
        full = {
            "name": "full",
            "description": "Full collection",
            "timeout": 600,
            "hash_files": True,
            "yara_scan": True,
            "collectors": standard_collectors,
        }
        for profile_data in [quick, standard, full]:
            path = tmp_path / f"{profile_data['name']}.yaml"
            path.write_text(yaml.dump(profile_data))
        return tmp_path

    def test_load_quick_profile(self, profiles_dir):
        profile = load_profile("quick", profiles_dir=profiles_dir)
        assert isinstance(profile, CollectionProfile)
        assert profile.name == "quick"
        assert len(profile.collectors) == 5

    def test_load_standard_profile(self, profiles_dir):
        profile = load_profile("standard", profiles_dir=profiles_dir)
        assert len(profile.collectors) == 16

    def test_load_full_profile(self, profiles_dir):
        profile = load_profile("full", profiles_dir=profiles_dir)
        assert profile.hash_files is True
        assert profile.yara_scan is True

    def test_load_nonexistent_raises_profile_error(self, profiles_dir):
        with pytest.raises(ProfileError, match="Profile not found"):
            load_profile("nonexistent", profiles_dir=profiles_dir)

    def test_list_profiles_returns_expected(self, profiles_dir):
        names = list_profiles(profiles_dir=profiles_dir)
        assert "quick" in names
        assert "standard" in names
        assert "full" in names
        assert len(names) >= 3

    def test_profile_timeout(self, profiles_dir):
        profile = load_profile("quick", profiles_dir=profiles_dir)
        assert profile.timeout == 60

    def test_profile_description(self, profiles_dir):
        profile = load_profile("quick", profiles_dir=profiles_dir)
        assert profile.description == "Quick triage"

    def test_invalid_yaml_raises_profile_error(self, tmp_path):
        bad_file = tmp_path / "broken.yaml"
        bad_file.write_text(": : : not valid yaml [[[")
        with pytest.raises(ProfileError):
            load_profile("broken", profiles_dir=tmp_path)

    def test_non_mapping_yaml_raises_profile_error(self, tmp_path):
        bad_file = tmp_path / "list.yaml"
        bad_file.write_text("- item1\n- item2\n")
        with pytest.raises(ProfileError, match="must be a YAML mapping"):
            load_profile("list", profiles_dir=tmp_path)


class TestPlatformDetect:
    def test_get_platform_returns_known_string(self):
        plat = get_platform()
        assert plat in ("Windows", "Linux", "Darwin")

    def test_is_supported_returns_true(self):
        assert is_supported() is True

    def test_get_platform_info_returns_dict(self):
        info = get_platform_info()
        assert isinstance(info, dict)

    def test_get_platform_info_has_expected_keys(self):
        info = get_platform_info()
        for key in ("system", "release", "version", "machine", "processor", "python_version"):
            assert key in info, f"Missing key {key!r} in platform info"

    def test_get_platform_info_system_matches_get_platform(self):
        info = get_platform_info()
        assert info["system"] == get_platform()
