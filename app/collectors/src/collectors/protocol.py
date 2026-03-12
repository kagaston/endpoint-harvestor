from typing import Protocol, runtime_checkable

from collectors.types import CollectorResult


@runtime_checkable
class Collector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    @property
    def supported_platforms(self) -> list[str]: ...

    def collect(self) -> CollectorResult: ...
