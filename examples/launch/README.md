# Phase 25 public launch examples

The shell wrappers work from any current directory; they locate the repository root before running.

| Script | Purpose |
|--------|---------|
| [`run-public-launch-check.sh`](run-public-launch-check.sh) | Diagnostics (`scripts/public_launch_check.py`) |
| [`run-public-launch-readiness-score.sh`](run-public-launch-readiness-score.sh) | Deterministic JSON score |
| [`run-public-launch-report.sh`](run-public-launch-report.sh) | Markdown report to stdout |

Run the examples from the repository root:

```bash
bash examples/launch/run-public-launch-check.sh --json
bash examples/launch/run-public-launch-readiness-score.sh
bash examples/launch/run-public-launch-report.sh
```

The tools validate and summarize the **supplied snapshot only**. They do not inspect GitHub, run the demo, verify claims in the snapshot, or measure adoption. The sample snapshot is illustrative; its `100%` score is not a live launch-readiness or compliance certification.

The check and score commands exit `0` only when every supplied checklist field passes, and `1` for invalid input or any failed checklist item. The report prints Markdown to stdout and uses the same exit status.

Sample snapshot: [`sample-standardization-readiness-snapshot.json`](sample-standardization-readiness-snapshot.json).
