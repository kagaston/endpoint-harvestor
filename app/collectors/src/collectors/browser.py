import platform
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from collectors.types import Artifact, ArtifactType, CollectorResult
from utils.forensic_utils import normalize_timestamp, resolve_user_paths
from logger import get_logger

log = get_logger("collectors.browser")


class BrowserCollector:
    def __init__(self, days: int = 30) -> None:
        self.days = days

    @property
    def name(self) -> str:
        return "browser"

    @property
    def display_name(self) -> str:
        return "Browser History"

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
            self._collect_chrome(result, system)
        except Exception as exc:
            log.warning("Chrome collection failed: %s", exc)
            result.errors.append(f"Chrome: {exc}")

        try:
            self._collect_firefox(result, system)
        except Exception as exc:
            log.warning("Firefox collection failed: %s", exc)
            result.errors.append(f"Firefox: {exc}")

        if system == "Darwin":
            try:
                self._collect_safari(result)
            except Exception as exc:
                log.warning("Safari collection failed: %s", exc)
                result.errors.append(f"Safari: {exc}")

        result.duration_ms = (time.time() - start) * 1000
        return result

    # ── Chrome ───────────────────────────────────────────────────────────

    def _collect_chrome(self, result: CollectorResult, system: str) -> None:
        if system == "Windows":
            rel_path = r"AppData\Local\Google\Chrome\User Data\Default\History"
        elif system == "Linux":
            rel_path = ".config/google-chrome/Default/History"
        elif system == "Darwin":
            rel_path = "Library/Application Support/Google/Chrome/Default/History"
        else:
            return

        db_paths = resolve_user_paths(rel_path)
        query = (
            "SELECT url, title, visit_count, "
            "datetime(last_visit_time/1000000-11644473600,'unixepoch') as visit_time "
            "FROM urls ORDER BY last_visit_time DESC LIMIT 500"
        )

        for db_path in db_paths:
            self._query_sqlite_history(
                db_path, query, "chrome", result,
            )

    # ── Firefox ──────────────────────────────────────────────────────────

    def _collect_firefox(self, result: CollectorResult, system: str) -> None:
        if system == "Windows":
            profile_rel = r"AppData\Roaming\Mozilla\Firefox\Profiles"
        elif system == "Linux":
            profile_rel = ".mozilla/firefox"
        elif system == "Darwin":
            profile_rel = "Library/Application Support/Firefox/Profiles"
        else:
            return

        profile_dirs = resolve_user_paths(profile_rel)
        query = (
            "SELECT url, title, visit_count, "
            "datetime(last_visit_date/1000000,'unixepoch') as visit_time "
            "FROM moz_places ORDER BY last_visit_date DESC LIMIT 500"
        )

        for profiles_dir in profile_dirs:
            if not profiles_dir.is_dir():
                continue
            try:
                for profile in profiles_dir.iterdir():
                    if not profile.is_dir():
                        continue
                    places_db = profile / "places.sqlite"
                    if places_db.is_file():
                        self._query_sqlite_history(
                            places_db, query, "firefox", result,
                        )
            except PermissionError:
                log.debug("Permission denied reading Firefox profiles: %s", profiles_dir)
            except Exception as exc:
                log.warning("Error scanning Firefox profiles in %s: %s", profiles_dir, exc)
                result.errors.append(f"Firefox profiles {profiles_dir}: {exc}")

    # ── Safari ───────────────────────────────────────────────────────────

    def _collect_safari(self, result: CollectorResult) -> None:
        safari_db = Path.home() / "Library" / "Safari" / "History.db"
        if not safari_db.is_file():
            return

        query = (
            "SELECT url, title, "
            "datetime(visit_time + 978307200, 'unixepoch') as visit_time "
            "FROM history_items "
            "JOIN history_visits ON history_items.id = history_visits.history_item "
            "ORDER BY visit_time DESC LIMIT 500"
        )

        self._query_sqlite_history(safari_db, query, "safari", result)

    # ── Shared SQLite helper ─────────────────────────────────────────────

    def _query_sqlite_history(
        self,
        db_path: Path,
        query: str,
        browser_name: str,
        result: CollectorResult,
    ) -> None:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".sqlite", delete=False,
            ) as tmp:
                tmp_path = tmp.name

            shutil.copy2(str(db_path), tmp_path)

            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(query)
                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    row_data = dict(zip(columns, row))
                    row_data["browser"] = browser_name
                    row_data["db_path"] = str(db_path)

                    result.artifacts.append(Artifact(
                        artifact_type=ArtifactType.BROWSER_HISTORY,
                        source=f"{browser_name}:{db_path}",
                        timestamp=row_data.get("visit_time", ""),
                        data=row_data,
                    ))
            finally:
                conn.close()

        except sqlite3.OperationalError as exc:
            log.warning(
                "SQLite error querying %s (%s): %s", browser_name, db_path, exc,
            )
            result.errors.append(f"{browser_name} DB {db_path}: {exc}")
        except (PermissionError, OSError) as exc:
            log.warning("Cannot access %s DB %s: %s", browser_name, db_path, exc)
            result.errors.append(f"{browser_name} access {db_path}: {exc}")
        except Exception as exc:
            log.warning(
                "Unexpected error querying %s (%s): %s", browser_name, db_path, exc,
            )
            result.errors.append(f"{browser_name} unexpected {db_path}: {exc}")
        finally:
            if tmp_path:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except OSError:
                    pass
