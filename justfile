set dotenv-load

sync:
    uv sync

test pkg="*":
    uv run pytest app/{{pkg}}/tests/ -v --tb=short

test-cov:
    uv run pytest app/*/tests/ --cov=app --cov-report=term-missing --tb=short

lint:
    uv run pylint -rn -sn --rcfile development/.pylintrc app/*/src/

pre-commit:
    uv run pre-commit run --all-files --config development/.pre-commit-config-py.yaml

triage:
    uv run intrusion-inspector triage --output ./output/

collect profile="standard":
    uv run intrusion-inspector collect --profile {{profile}} --output ./output/

report format="html":
    uv run intrusion-inspector report --input ./output/ --format {{format}}

verify:
    uv run intrusion-inspector verify --input ./output/
