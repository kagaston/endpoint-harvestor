import logging
import traceback


logger = logging.getLogger("intrusion_inspector.errors")


class InspectorError(Exception):
    def __init__(self, message: str, *, component: str | None = None):
        self.component = component
        super().__init__(message)

    def __str__(self) -> str:
        prefix = f"[{self.component}] " if self.component else ""
        return f"{prefix}{super().__str__()}"


class CollectorError(InspectorError):
    def __init__(self, message: str, *, collector: str | None = None):
        super().__init__(message, component=collector or "collector")


class AnalyzerError(InspectorError):
    def __init__(self, message: str, *, analyzer: str | None = None):
        super().__init__(message, component=analyzer or "analyzer")


class ReporterError(InspectorError):
    def __init__(self, message: str, *, reporter: str | None = None):
        super().__init__(message, component=reporter or "reporter")


class EvidenceError(InspectorError):
    def __init__(self, message: str):
        super().__init__(message, component="evidence")


class ProfileError(InspectorError):
    def __init__(self, message: str):
        super().__init__(message, component="profile")


def handle_error(exc: Exception, *, context: str | None = None) -> str:
    ctx = f" ({context})" if context else ""
    if isinstance(exc, CollectorError):
        msg = f"Collector error{ctx}: {exc}"
    elif isinstance(exc, AnalyzerError):
        msg = f"Analyzer error{ctx}: {exc}"
    elif isinstance(exc, ReporterError):
        msg = f"Reporter error{ctx}: {exc}"
    elif isinstance(exc, EvidenceError):
        msg = f"Evidence error{ctx}: {exc}"
    elif isinstance(exc, ProfileError):
        msg = f"Profile error{ctx}: {exc}"
    elif isinstance(exc, InspectorError):
        msg = f"Inspector error{ctx}: {exc}"
    else:
        msg = f"Unexpected error{ctx}: {exc}"

    logger.error(msg)
    logger.debug(traceback.format_exc())
    return msg
