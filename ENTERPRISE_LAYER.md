# Enterprise layer

This is the reference [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`DEMO_FLOW.md`](DEMO_FLOW.md) point to for the team-scoped `/api/*` surface: what it is, how it authenticates and authorizes, and — importantly — what it does **not** touch.

> **Scope reminder:** everything below is the **optional product layer**. It shares one Rust binary and one HTTP router with the frozen core (`POST /evidence`, `policy.rs`, the hash chain, `GET /verify*` / `/compliance-summary`), but there is **no code path from this layer into the ledger**. See "Boundaries vs. frozen core" below for the concrete rule.

## What it is

`/api/me`, `/api/assessments`, and `/api/compliance-workflow*` are team-scoped console routes backed by Postgres (`rust/src/govai_api.rs`), gated by:

- **Authentication**: a Supabase-issued JWT, validated against JWKS (`rust/src/auth.rs::AuthConfig`). Requires `SUPABASE_URL` in the Rust process environment at minimum; `SUPABASE_JWT_AUD` optionally adds audience validation. Every `/api/*` request needs `Authorization: Bearer <JWT>`; without a valid issuer/JWKS config these routes return `401`/`500`.
- **Team scope**: the optional `x-govai-team-id: <team-uuid>` header selects which team's rows a request operates against. If omitted, the server resolves (or bootstraps) a default team — fine for a single-user demo, non-deterministic across multiple seeded users, so pass it explicitly for reproducible testing (`GET /api/me` → `teams[].id`).
- **Authorization**: product-layer RBAC (`rust/src/rbac.rs`), mapping a DB role string (`team_members.role`) to a fixed permission set. Unknown roles default to the most restrictive (`Viewer`).

## Roles and permissions (`rbac.rs`)

| Role | `review_queue_view` | `decision_submit` | `promotion_action` | `admin_override` | `break_glass` |
|------|:---:|:---:|:---:|:---:|:---:|
| `admin` / `owner` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `compliance_officer` | ✓ | ✓ | ✓ | — | — |
| `risk_officer` | ✓ | ✓ | ✓ | — | — |
| `reviewer` (DB legacy alias: `member`) | ✓ | ✓ | — | — | — |
| `viewer` | ✓ | — | — | — | — |

The **demo pitfall** called out in `DEMO_FLOW.md`: the `reviewer` role has `decision_submit` but not `promotion_action` — use `compliance_officer`, `risk_officer`, `admin`, or `owner` for the promotion step, or expect `403 FORBIDDEN` with `reason: "INSUFFICIENT_ROLE"`.

## Compliance workflow state machine

`compliance_workflow` (Postgres, one row per `(team_id, run_id)`) is an **app-layer queue / override**, not a second interpretation of compliance:

```
pending_review --review--> approved | rejected
approved --promotion--> promotion_allowed | promotion_blocked
```

- Register (`POST /api/compliance-workflow`) requires `decision_submit`. First registration for a `(team_id, run_id)` starts at `pending_review`; a duplicate `POST` returns the existing row unchanged (idempotent, not a reset).
- Review (`POST /api/compliance-workflow/:run_id/review`, `{"decision":"approve"|"reject"}`) requires `decision_submit`, only valid from `pending_review`.
- Promotion (`POST /api/compliance-workflow/:run_id/promotion`, `{"decision":"allow"|"block"}`) requires `promotion_action`, only valid from `approved`.
- Wrong-state transitions return `409 INVALID_STATE`; bad decision strings return `400 INVALID_DECISION`.

## Boundaries vs. frozen core

This is the one rule that matters for trusting the ledger regardless of what happens in this layer:

- **Core writes the ledger and enforces `policy.rs`.** Nothing here does either. `compliance_workflow` state transitions do **not** append to `audit_log.jsonl`, and reviewing/promoting through this API does **not** substitute for the real `human_approved` / `model_promoted` evidence events — those still only come from `POST /evidence` (via `make approve` / `make promote`, or any client calling the endpoint directly).
- **The only authoritative compliance decision is `GET /compliance-summary`.** `compliance_workflow` rows are a review queue a team can look at; they are consumers of the ledger's story, not a competing source of truth for it.
- Concretely: you can delete every row in `teams`, `team_members`, and `compliance_workflow` and the ledger's `VALID`/`INVALID`/`BLOCKED` projection for any `run_id` does not change.

## Running this locally — a real gap, not just missing docs

`DEMO_FLOW.md`'s prerequisites historically pointed at `rust/migrations/0001_govai_core.sql`, `0002_add_compliance_context_fields.sql`, and `0003_compliance_workflow.sql` to create `teams`, `team_members`, and `compliance_workflow`. **Those files do not exist in this repository.** `rust/migrations/` currently only ships `0001_core_api_key_usage.sql` and `0002_core_issued_api_keys.sql` — API-key bookkeeping, not the enterprise-layer schema.

In practice this means the `teams`/`team_members`/`compliance_workflow` schema is provisioned by the hosted GovAI Platform, not by anything in AIGov Core's own migration set. If you need to exercise `/api/*` locally against Core alone, you currently have to hand-write that schema yourself (see the `CREATE TABLE`/RBAC shape implied by `rust/src/govai_api.rs` and `rust/src/rbac.rs`) or point at an operator-provisioned database that already has it. This is tracked as a real gap, not a documentation nicety — see the repo audit for 2026-09-30.
