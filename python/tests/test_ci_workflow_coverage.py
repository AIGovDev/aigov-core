from pathlib import Path

import yaml


def test_python_smoke_preserves_both_integration_suites():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/python-aigov.yml").read_text())
    steps = workflow["jobs"]["python-smoke"]["steps"]
    smoke = next(step["run"] for step in steps if step.get("name") == "Python smoke tests")
    for prefix in ("python -m pytest", "ruff check", "ruff format --check"):
        line = next(line for line in smoke.splitlines() if line.startswith(prefix))
        assert "tests/test_smolagents_adapter.py" in line
        assert "tests/test_oss_metrics_snapshot.py" in line
