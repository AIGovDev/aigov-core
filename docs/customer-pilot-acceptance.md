# Customer pilot acceptance checklist: AIGov Core integration

Use this checklist to decide whether a pilot met its goals. Each item says how to verify it, so a result is a command's
output, not an impression. Section 1 lists what the pilot supports. Section 2 lists what it does not, and what a
production deployment must add.

Everything here runs on synthetic data, locally. Nothing in this checklist is a certification or a statement of
regulatory compliance.

## 1. Supported capabilities (verify each)

| # | Capability | How to verify | Pass when |
|---|---|---|---|
| 1 | Your tools are governed: an unlisted tool is refused | `pilot.py run` step 3, or `validate.py` cases | `tool_not_permitted`, and the side effect did not run |
| 2 | Writes need an approval; reads do not | `quickstart.py`; `validate.py authorization` | a write without approval is held (`approval_not_found`); a read runs |
| 3 | Approval is authenticated: the approver's identity comes from its credential | `validate.py approval` | a claimed identity is refused (`approver_identity_mismatch`) |
| 4 | An agent cannot approve | `validate.py approval` | `role_not_permitted` |
| 5 | A rejected request does not run | `validate.py rejection` | `approval_not_approved`, and no side effect |
| 6 | Only the approver can revoke; a revoked approval cannot authorize a call | `validate.py revocation` | `revocation_not_by_approver`; `approval_revoked` |
| 7 | Revocation after issue, before the executor checks, stops execution | `validate.py revocation` | `authorization_revoked`, and no side effect |
| 8 | The same authorization and the same approval cannot run twice | `validate.py replay` | `authorization_receipt_recorded`; `approval_already_consumed` |
| 9 | Changed arguments are refused by Core and by the executor | `validate.py modified_arguments` | `approval_linkage_mismatch`; `authorization_arguments_mismatch` |
| 10 | With Core down, nothing runs, and the same authorization runs once after recovery | `validate.py core_unavailable` | `INDETERMINATE`; `core_unavailable`; then one execution |
| 11 | Evidence verifies without Core's keys or database | `validate.py independent_verification` | every offline check passes, and a changed authorization fails |
| 12 | Each execution has a receipt, tied to its authorization | the pilot report's receipts section | one receipt per executed call, none without an authorization |
| 13 | Your credentials are separate and generated per run | `IntegrationConfig.generate`; `test_customer_integration.py` | every actor has its own key and role |
| 14 | A misconfiguration is rejected before Core starts | `test_customer_integration.py` | `IntegrationConfig` raises for each unsafe setting |
| 15 | The pilot cleans up only its own resources | `pilot.py run` and `validate.py` output | "cleaned up" lists only resources with the run's prefix |

Run the whole set with one command each:

```bash
python examples/customer-pilot/pilot.py run
python examples/customer-integration/acme/validate.py run
python examples/customer-integration/quickstart.py
```

A pass of all three, with the exit status 0, covers items 1 to 15.

## 2. Production limitations (state these to the customer)

These are not defects of the pilot. They are what the design does not yet provide, and each is needed before production.

| Limitation | What a production deployment needs |
|---|---|
| Identities are configuration. There is no identity provider | An identity provider for approvers and the executor. An approver's identity is only as strong as the credential issued for it |
| API keys are bearer secrets, generated per run | Keys issued and stored in the customer's secret manager, with rotation |
| Core's policy-signing key and authorization key are environment secrets | A managed key store. Rotate the pinned authorization key and publish the new public key to executors |
| The executor's store is a local SQLite file, on one host | A shared store with the same atomic reservation, if executors run on several hosts |
| A revocation after the executor's status check does not stop the side effect | Accept this window, or add a check at the external system (for example, an expiry it enforces) |
| Exactly-once execution across an external system is not claimed | Reconcile reservations that have no receipt against the external system. Design the external call to be idempotent on `execution_id` where possible |
| The approval window is 30 seconds, a demonstration value | A window chosen for the customer's approval process |
| One Core process per ledger | Operate Core with one writer per ledger, as documented for the deployment |
| Timings are from one machine and a small number of runs | Measure on the customer's infrastructure under their load before any capacity claim |
| Synthetic tools only | The customer's own tools, performer, and integration tests, run against a staging Core |

## 3. Pilot acceptance decision

The pilot is accepted when:

- every item in section 1 passes on the customer's machine, from a clean checkout, with the command above;
- the customer can state, for each limitation in section 2, who owns it and when it will be addressed;
- the customer's own performer is wired in, and its flow passes the same validation cases against a staging Core.

The pilot is not accepted for production by passing these checks. Production use needs the items in section 2, reviewed
by the customer and by AIGov.
