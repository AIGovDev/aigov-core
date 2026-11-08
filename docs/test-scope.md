# Runtime test scope and limits

This page maps the public checks to the claims they support. Run commands from a clean checkout unless a section says otherwise.

## End-to-end runtime path

The shortest runnable path is [quickstart-runtime.md](quickstart-runtime.md), using [smoke-runtime.sh](../examples/basic-runtime-client/smoke-runtime.sh) against a locally started `aigov_audit` service.

The script submits the committed discovery fixture with a unique `run_id`, then calls:

1. `POST /evidence` and checks that ingest returns `ok: true`;
2. `GET /compliance-summary/:run_id` and checks the configured policy verdict;
3. `GET /api/export/:run_id` and checks the `aigov.audit_export.v1` schema identifier;
4. `GET /verify/:run_id` and checks the run's ledger-chain verification result.

With the checked-in development policy and one discovery event, the expected verdict is `BLOCKED`: the minimal example intentionally lacks the model lifecycle evidence required for promotion. It demonstrates a policy outcome and a verifiable export; it does not demonstrate that a model is safe or legally compliant.

## What the automated tests cover

| Check | Evidence it provides | It does not establish |
| --- | --- | --- |
| `cargo test --locked` from `rust/` | Rust unit coverage for policy validation, ledger projection, verdict derivation, replay checks, hash-chain handling, and export construction | Correctness for every external policy, deployment configuration, or concurrent production workload |
| `cargo test --locked --test runtime_core_integration` from `rust/` | The mounted runtime's integration path, including lifecycle handling and exported evidence validation | Availability or correctness of an operator's network, database, keys, or deployment |
| `python -m pytest -q` from `python/` | Python SDK and portable standards-validator behavior covered by the checked-in tests | A hosted verdict; portable schema/conformance checks do not inspect an audit ledger |
| `python3 scripts/gate_reports.py` | Required report structure and repository-specific report invariants | Runtime behavior |
| `make cursor-plugin-smoke` | The local MCP bridge's basic startup and protocol smoke path | Hosted audit service policy enforcement |

The repository's detailed test inventory and known gaps are recorded in [core-runtime-test-hardening-audit.md](reports/core-runtime-test-hardening-audit.md). Its recorded test counts are historical; use the current CI run for current results.

## Reproduce the checks

```bash
cd rust
cargo test --locked
cargo test --locked --test runtime_core_integration
cd ../python
python -m pytest -q
cd ..
python3 scripts/gate_reports.py
make cursor-plugin-smoke
```

The end-to-end HTTP smoke requires a running audit service and local credentials; follow [quickstart-runtime.md](quickstart-runtime.md). It is distinct from the offline unit and integration suites.

## Security and interpretation limits

- `BLOCKED` means the configured evidence and lifecycle prerequisites do not permit promotion. It is not a model-quality score.
- Hash-chain verification detects changes relative to the recorded chain; it does not prove that submitted evidence was truthful or complete.
- A valid export proves consistency against the runtime's documented contracts, not compliance with a law or standard in its entirety.
- Portable standards validators establish structural and deterministic checks for their input documents; they do not replace runtime policy gates or ledger verification.
- Production guarantees depend on operator configuration, key management, storage durability, access controls, backups, and monitoring. See [SECURITY.md](../SECURITY.md), [trust-model.md](trust-model.md), and [release-checklist.md](releases/release-checklist.md).
