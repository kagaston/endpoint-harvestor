from reporters.console_report import ConsoleReporter
from reporters.html_report import HTMLReporter
from reporters.json_report import JSONReporter
from reporters.csv_report import CSVReporter
from reporters.protocol import Reporter


REPORTER_REGISTRY: dict[str, type] = {
    "console": ConsoleReporter,
    "html": HTMLReporter,
    "json": JSONReporter,
    "csv": CSVReporter,
}


def get_reporter(name: str, **kwargs) -> Reporter:
    cls = REPORTER_REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"Unknown reporter: {name!r}. Available: {list(REPORTER_REGISTRY)}")
    return cls(**kwargs)


def list_reporters() -> list[str]:
    return list(REPORTER_REGISTRY.keys())
