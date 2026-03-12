from typing import Protocol, runtime_checkable

from analyzers.types import AnalysisResult
from collectors.types import CollectorResult


@runtime_checkable
class Analyzer(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    def analyze(self, results: list[CollectorResult]) -> AnalysisResult: ...
