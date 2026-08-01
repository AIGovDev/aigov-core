# Railway build: published legal documents

## Scope

This change fixes the Railway container build for the Rust service.

The Rust module `rust/src/legal_documents.rs` embeds published legal
documents at compile time through `include_str!`. The root Dockerfile
previously omitted these files from the builder image.

## Root cause

The builder uses `/build` as its working directory. The compile-time paths
resolve to:

- `/legal/published/terms-of-service.md`
- `/legal/published/privacy-policy.md`
- `/legal/published/dpa.md`

These files were absent from the builder image, causing Rust compilation to
fail.

## Change

The root Dockerfile now copies `legal/published` to `/legal/published` before
running `cargo build`.

The three required published documents are included in this branch.

## Validation

Validation includes:

- confirming that all three documents exist and are tracked;
- confirming that the Dockerfile copies them to the compile-time path;
- running the repository report gate;
- validating the build through CI and Railway.

## Evaluation gate

The change passes when the Rust binary compiles without `include_str!`
file-not-found errors and the Railway image build succeeds.

Evaluation status: pending pull-request validation.

## Human approval gate

Human review is required before merge.

The reviewer must confirm that the included documents are the intended
published versions and contain no draft or confidential material.

Human approval status: pending pull-request review.

## Risk assessment

The change affects container build inputs only. It does not modify runtime
logic, public APIs, database schemas, or authorization behavior.

## Rollback

Revert this pull request.
