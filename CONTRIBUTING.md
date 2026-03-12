# Contributing to IntrusionInspector

## Getting Started

1. Clone the repo and install [uv](https://docs.astral.sh/uv/)
2. Run `just sync` to install all workspace packages
3. Run `just test` to verify everything works

## Project Layout

All Python packages live under `app/`. Each has its own `pyproject.toml`, `src/<name>/`, and `tests/`.

## Development Workflow

```bash
just sync              # Install dependencies
just test              # Run all tests
just test collectors   # Run tests for a single package
just test-cov          # Run with coverage
just lint              # Pylint across all packages
just pre-commit        # Pre-commit hooks
```

## Adding a Collector

1. Create `app/collectors/src/collectors/my_collector.py`
2. Implement the `Collector` protocol from `collectors.protocol`
3. Register it in `collectors.registry.COLLECTOR_REGISTRY`
4. Add it to the relevant profile YAMLs in `profiles/`
5. Write tests in `app/collectors/tests/`

## Adding an Analyzer

1. Create `app/analyzers/src/analyzers/my_analyzer.py`
2. Implement the `Analyzer` protocol from `analyzers.protocol`
3. Register it in `analyzers.registry.ANALYZER_REGISTRY`
4. Write tests in `app/analyzers/tests/`

## Code Style

- Python 3.12+ type hints everywhere
- Pydantic models for data types
- Protocol classes for interfaces
- `pylint` for linting (config in `development/.pylintrc`)
