# Deployment preflight (read-only, for the owner)

Nothing in this checklist changes a remote environment. It describes what to check before any deployment. Railway, staging, and production
were not contacted, and no value of any secret is written here or printed by the tooling.

## 1. Check the configuration names

Export the environment to a file that stays on the operator's machine, then run:

```
python scripts/deploy_preflight.py --env-file <path> --environment staging   # or prod
```

The tool reports, for each name, whether it is set. It never prints a value. It exits 1 when a required name is missing or a forbidden name is set.

## 2. The new requirement: principals

Since this release, staging and production refuse to start without `GOVAI_PRINCIPALS_JSON` (or OIDC). The JSON maps each key to a principal, role, and
tenant. The roles are:

| Role | Posts | Key |
|---|---|---|
| agent | pipeline and agent evidence (every event type that is not protected) | one per agent system |
| approver | `human_approved`, `human_approval_revoked`, `risk_reviewed` | one per named approver |
| executor | `execution_receipt` | one per executor |

Every key in `GOVAI_PRINCIPALS_JSON` must also appear in `GOVAI_API_KEYS` and in `GOVAI_API_KEYS_JSON`, for the same tenant.

## 3. Incompatibilities with an existing staging configuration

| Existing setting | Effect with this release | Action |
|---|---|---|
| No `GOVAI_PRINCIPALS_JSON` | staging refuses to start | add principals, one agent key at least, and an approver and an executor if they are used |
| `AIGOV_POLICY_FILE` or `AIGOV_ALLOW_UNSIGNED_POLICY_FILE` | refused in staging and production | use the signed bundle (`AIGOV_POLICY_BUNDLE_FILE`) and the trust file |
| `AIGOV_APPROVER_ALLOWLIST` (environment) | refused in staging and production | the approver allowlist is in the signed policy |
| `GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX` (environment seed) | refused in staging and production | use the key registry (`AIGOV_KEY_REGISTRY_*`) and a seeds directory |
| An approval or receipt posted by a key with the wrong role | refused (`ROLE_NOT_PERMITTED`, `RECEIPT_REQUIRES_EXECUTOR`) | give each key the role it uses |
| A receipt for an authorization Core did not issue in the run | refused (`RECEIPT_FOR_UNISSUED_AUTHORIZATION`) | the executor must send only the receipts it received |
| Container with a published port and no `AIGOV_BIND` | the image now binds `0.0.0.0:8088` | no action; publish the port only where intended |
| Load on a single Core above its measured ceiling | refusals with 503 OVERLOADED (nothing recorded) | size the deployment (`docs/evidence/release-candidate/load/`) |
| `GOVAI_DATABASE_URL` missing in staging or production | refused at start | set it; the policy anchor and the registry anchor need it |

## 4. Migration

Core migrations are forward-only (`rust/migrations/0001` to `0004`). They run at start with `GOVAI_AUTO_MIGRATE=true`, or out of band.
The executor store migrates with `python -m aigov_py.trusted.store_admin migrate-pg --url "$EXECUTOR_DB_URL"`, and `status-pg` checks it.

Order: stop executors; take the backup (section 5); apply the migrations; check `GET /ready` returns 200 with `migrations_complete: true`;
check `status-pg` returns 0; start executors.

## 5. Backup

- The database and the ledger volume from one snapshot, taken while Core is stopped or with the snapshot taken at the database and the volume at the same moment.
- The head hashes of the ledger and of the executor history, written off host (`store_admin verify-history`).
- The trust file and the root key are under change control and are not part of the database backup.

## 6. Rollback

- Core: roll back to the previous image digest only if it accepts the current schema. There are no down-migrations, so a schema change is not reversed.
- The policy revision: a rollback is refused by the anchor. The fix is a higher revision.
- Executors: pin the previous wheel only if the executor schema did not change; otherwise restore the database from the section 5 backup and redeploy.

## 7. Smoke test after deployment

1. `GET /health` returns 200, and `GET /ready` returns 200.
2. A signed policy is in force: the `policy_version` in an accepted event's response names the anchored revision, and `GET /status` reports the service state.
3. One evidence write from each role: an agent event (200), an approval by the approver key (200), a receipt by the executor key for a call it received (200).
4. A refused write is refused with its code: an agent key posting `human_approved` (403 `ROLE_NOT_PERMITTED`).
5. The ledger chain verifies (`/verify` for the tenant).
6. The customer pilot (`examples/customer-pilot/pilot.py run`) against the deployed release, with a fresh output directory, reports no failing row.

## 8. What the owner must not do

- Do not change Railway, a remote database, or a volume without the owner's own change process.
- Do not reuse the development credentials from the test tooling.
- Do not publish a tag or release from this checklist. Those are separate decisions.
