from pathlib import Path
from typing import Protocol, runtime_checkable

from reporters.types import ReportData


@runtime_checkable
class Reporter(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    def generate(self, data: ReportData, output_dir: Path) -> Path: ...
