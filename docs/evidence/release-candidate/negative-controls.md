# Negative controls, release candidate

Each control was run against the binary named in its row. "Before" is the branch base `af4efc9` (= `origin/staging` at the start
of this work). Outputs are copied from the runs; no output is paraphrased.

| # | Claim under test | Setup | Observed before the fix | Result after the fix |
|---|---|---|---|---|
| N1 | A key that is not an executor can record a receipt for an authorization that was never issued | `af4efc9` binary, dev, principals not configured, one plain API key | `POST /evidence` with `event_type: execution_receipt`, `execution_authorization_id: "auth_never_issued"` returned HTTP 200, `ok: true`, `record_hash 9e8b47cc…039125`. The receipt was appended. | `test_forged_receipt_without_principals_is_refused`: 403 `RECEIPT_REQUIRES_EXECUTOR`, nothing appended. |
| N2 | A receipt from an authenticated executor for an authorization Core did not issue is accepted | principals configured | Not run before the fix. The code path had no provenance check (`execution_receipt` was only role-checked). | `test_receipt_for_an_authorization_never_issued_is_refused`: 422 `RECEIPT_FOR_UNISSUED_AUTHORIZATION`, nothing appended. |
| N3 | An agent key can post a receipt | principals configured | Not run before the fix. The role table already allowed only executors. | `test_agent_cannot_post_a_receipt`: 403 `ROLE_NOT_PERMITTED`. |
| N4 | A legitimate receipt is still accepted | principals configured; the authorization is issued by Core in the same run | — | `test_receipt_for_an_authorization_issued_in_the_run_is_accepted`: 200, one receipt recorded. |
| N5 | An agent key can post `human_approved` (self-approval) when principals are configured | principals configured, agent key | `POST /evidence` with `event_type: human_approved`: HTTP 403 `ROLE_NOT_PERMITTED`, "role agent may not post event_type human_approved". Refused before the fix. | Unchanged. Recorded as working. |
| N6 | Self-approval without principals | `af4efc9`, dev, principals not configured, plain key | The request was refused, but only for a missing `ai_system_id` field, so this run does not show whether approval posting is possible. **Not claimed as a bypass.** | Not re-run. Residual: principal-less deployments allow any key to post approvals (see the report, R-4). |
| N7 | Production starts without principals | production environment, valid signed bundle, no principals | Started (the check did not exist). | Refused before any database access: `production requires GOVAI_PRINCIPALS_JSON`. `production_refuses_to_start_without_principals`. |
| N8 | Fault-injection crash points exist in a normal build | normal release binary, `AIGOV_TEST_FAULT_INJECTION=1 AIGOV_TEST_CRASH_AT=before_append` | The environment-gated crash points were compiled into the normal binary. They were active only in dev. | No crash code in a normal build. The binary refuses to start when either variable is set: `test_a_normal_build_refuses_to_start_with_fault_injection_set`. |
| N9 | A discovery event is accepted for a principal-configured deployment | principals configured, agent key, `ai_discovery_reported` | HTTP 403 `ROLE_NOT_PERMITTED`: "role agent may not post event_type ai_discovery_reported". No role could post it. | Agent role allows it. `tb_http_verdict` passes with separate agent and approver keys. |
| N10 | The SDK wheel carries the PostgreSQL executor schema | `python -m build --wheel` on the branch before the fix | The wheel contained `migrations/0001_executor_store.sql` and `0002_executor_lifecycle.sql` but not `migrations/pg/0001_executor_pg.sql`. | The wheel contains `aigov_py/trusted/migrations/pg/0001_executor_pg.sql`. Offline downstream check passes from an isolated target directory. |
| N11 | Two Core processes on one ledger both authorize one approval | two principal-configured processes, same approval, released together, five rounds | Not run before this work (the case was NOT VERIFIED on #501). | Exactly one authorization per round; the other refused with `approval_already_consumed`; chain verifies. `test_one_approval_authorizes_at_most_once_across_two_processes`. |
| N12 | An oversized request is answered with a bounded response | `af4efc9`, dev, 5 MB POST body | The client received `Broken pipe`: Core closed the connection and sent no HTTP 413. | Not changed. The limit is enforced, but the response is not a 413. Residual L-2. |
| N13 | Container runtime tests on this workstation | image built from `origin/staging` (no changes from this branch) | 13 passed, 3 failed: each service's `/health` or `/ready` never answered (`assert 0 == 200`). | Same 13 passed, same 3 failed on the branch image. The branch does not change the result on this host. The CI runner passed 16 of 16 on the previous head. Residual: container tests are environment-sensitive on this workstation, and the final CI run is the authority. |

Notes on what these controls do not show:

- N6 is inconclusive, and is not reported as a bypass.
- N12 shows enforcement of a size limit, not its exact status code.
- N13 is a local environment result. It does not show a code defect on either tree.
