import platform
import time

import psutil

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, run_command
from logger import get_logger

log = get_logger("collectors.users")


class UserCollector:
    @property
    def name(self) -> str:
        return "users"

    @property
    def display_name(self) -> str:
        return "User Accounts"

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
            self._collect_logged_in_users(result)
            self._collect_local_accounts(result, system)
            self._collect_last_logins(result, system)
        except Exception as exc:
            log.error("Unexpected error during user collection: %s", exc)
            result.errors.append(f"Unexpected error: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _collect_logged_in_users(self, result: CollectorResult) -> None:
        try:
            for user in psutil.users():
                result.artifacts.append(Artifact(
                    artifact_type=ArtifactType.LOGIN_EVENT,
                    source="psutil",
                    timestamp=normalize_timestamp(user.started),
                    data={
                        "username": user.name,
                        "terminal": user.terminal or "",
                        "host": user.host or "",
                        "started": normalize_timestamp(user.started),
                        "pid": getattr(user, "pid", None),
                    },
                ))
        except Exception as exc:
            log.warning("Failed to collect logged-in users: %s", exc)
            result.errors.append(f"Logged-in users: {exc}")

    def _collect_local_accounts(self, result: CollectorResult, system: str) -> None:
        try:
            if system == "Windows":
                self._collect_accounts_windows(result)
            elif system == "Linux":
                self._collect_accounts_linux(result)
            elif system == "Darwin":
                self._collect_accounts_darwin(result)
        except Exception as exc:
            log.warning("Failed to collect local accounts: %s", exc)
            result.errors.append(f"Local accounts: {exc}")

    def _collect_accounts_windows(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command(["net", "user"])
        if rc != 0:
            return

        in_list = False
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("---"):
                in_list = True
                continue
            if not in_list or not stripped or stripped.startswith("The command"):
                continue
            for username in stripped.split():
                if username:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USER_ACCOUNT,
                        source="net user",
                        data={"username": username},
                    ))

    def _collect_accounts_linux(self, result: CollectorResult) -> None:
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split(":")
                    if len(parts) < 7:
                        continue
                    uid = int(parts[2]) if parts[2].isdigit() else -1
                    gid = int(parts[3]) if parts[3].isdigit() else -1
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.USER_ACCOUNT,
                        source="/etc/passwd",
                        data={
                            "username": parts[0],
                            "uid": uid,
                            "gid": gid,
                            "home": parts[5],
                            "shell": parts[6],
                            "is_system": uid < 1000,
                        },
                    ))
        except (FileNotFoundError, PermissionError) as exc:
            log.warning("Cannot read /etc/passwd: %s", exc)
            result.errors.append(f"/etc/passwd: {exc}")

    def _collect_accounts_darwin(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command(["dscl", ".", "list", "/Users"])
        if rc != 0:
            return

        for line in stdout.splitlines():
            username = line.strip()
            if not username:
                continue

            user_data: dict = {"username": username}

            uid_out, _, uid_rc = run_command(
                ["dscl", ".", "-read", f"/Users/{username}", "UniqueID"],
            )
            if uid_rc == 0:
                for uid_line in uid_out.splitlines():
                    if "UniqueID" in uid_line:
                        parts = uid_line.split(":")
                        if len(parts) >= 2:
                            uid_str = parts[-1].strip()
                            if uid_str.isdigit():
                                user_data["uid"] = int(uid_str)
                                user_data["is_system"] = int(uid_str) < 500

            gid_out, _, gid_rc = run_command(
                ["dscl", ".", "-read", f"/Users/{username}", "PrimaryGroupID"],
            )
            if gid_rc == 0:
                for gid_line in gid_out.splitlines():
                    if "PrimaryGroupID" in gid_line:
                        parts = gid_line.split(":")
                        if len(parts) >= 2:
                            gid_str = parts[-1].strip()
                            if gid_str.isdigit():
                                user_data["gid"] = int(gid_str)

            home_out, _, home_rc = run_command(
                ["dscl", ".", "-read", f"/Users/{username}", "NFSHomeDirectory"],
            )
            if home_rc == 0:
                for home_line in home_out.splitlines():
                    if "NFSHomeDirectory" in home_line:
                        user_data["home"] = home_line.split(":", 1)[-1].strip()

            shell_out, _, shell_rc = run_command(
                ["dscl", ".", "-read", f"/Users/{username}", "UserShell"],
            )
            if shell_rc == 0:
                for shell_line in shell_out.splitlines():
                    if "UserShell" in shell_line:
                        user_data["shell"] = shell_line.split(":", 1)[-1].strip()

            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.USER_ACCOUNT,
                source="dscl",
                data=user_data,
            ))

    def _collect_last_logins(self, result: CollectorResult, system: str) -> None:
        try:
            if system == "Windows":
                self._collect_last_logins_windows(result)
            elif system in ("Linux", "Darwin"):
                self._collect_last_logins_unix(result)
        except Exception as exc:
            log.warning("Failed to collect last logins: %s", exc)
            result.errors.append(f"Last logins: {exc}")

    def _collect_last_logins_windows(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command([
            "wevtutil", "qe", "Security",
            "/q:*[System[(EventID=4624)]]",
            "/c:20", "/f:text",
        ], timeout=60)
        if rc != 0:
            return

        current_event: dict = {}
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Event["):
                if current_event:
                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.LOGIN_EVENT,
                        source="Security EventLog 4624",
                        data=dict(current_event),
                    ))
                current_event = {}
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                current_event[key.strip().lower().replace(" ", "_")] = val.strip()

        if current_event:
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.LOGIN_EVENT,
                source="Security EventLog 4624",
                data=dict(current_event),
            ))

    def _collect_last_logins_unix(self, result: CollectorResult) -> None:
        stdout, _, rc = run_command(["last", "-20"])
        if rc != 0:
            return

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("wtmp") or stripped.startswith("btmp"):
                continue
            parts = stripped.split()
            if len(parts) < 3:
                continue
            result.artifacts.append(Artifact(
                artifact_type=ArtifactType.LOGIN_EVENT,
                source="last",
                data={
                    "username": parts[0],
                    "terminal": parts[1] if len(parts) > 1 else "",
                    "host": parts[2] if len(parts) > 2 else "",
                    "raw": stripped,
                },
            ))
