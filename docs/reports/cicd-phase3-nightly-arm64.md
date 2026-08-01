# CI/CD Phase 3: ARM64 nightly validation

## Scope

This change introduces or updates the nightly full-validation workflow for the Linux ARM64 self-hosted runner.

The workflow is intended to execute the repository's extended validation checks outside the normal pull-request critical path.

## Changes reviewed

The change covers the nightly CI configuration, including:

- Linux ARM64 self-hosted runner selection;
- PostgreSQL service-container initialization;
- SQLx migration checksum regression validation;
- the full Rust test suite;
- the full Python test suite;
- the enterprise-readiness check;
- validation summary generation;
- optional Slack notification handling.

## Security and operational impact

The workflow executes repository-controlled validation commands on a self-hosted runner.

Relevant operational considerations include:

- runner labels must resolve only to the intended Linux ARM64 runner;
- repository secrets must not be exposed to untrusted workflow execution;
- service containers must remain isolated to the job;
- notification steps must safely handle an absent Slack webhook;
- failures must produce a non-zero job result.

No application runtime logic, public API, database schema, or production policy behavior is changed by this CI configuration.

## Validation

The workflow configuration and its constituent validation commands are subject to repository CI checks.

Expected checks include:

- workflow syntax and repository policy validation;
- PostgreSQL service startup;
- SQLx migration checksum regression;
- full Rust tests;
- full Python tests;
- enterprise-readiness validation;
- summary and notification-step execution.

## Evaluation gate

The change is acceptable when:

- the workflow is assigned exclusively to the intended Linux ARM64 self-hosted runner;
- all mandatory validation stages execute;
- any mandatory stage failure fails the job;
- service-container startup and cleanup complete correctly;
- optional notification configuration does not turn a successful validation into a failure.

Evaluation status: pending successful pull-request checks.

## Human approval gate

Human review is required before merge.

The reviewer must confirm:

- the runner labels are correct;
- the workflow trigger and execution cadence are intentional;
- no GitHub-hosted runner is selected unintentionally;
- secret handling is appropriate;
- the validation scope matches the intended nightly assurance level.

Human approval status: pending pull-request review.

## Rollback

Revert the workflow changes and this audit report.
