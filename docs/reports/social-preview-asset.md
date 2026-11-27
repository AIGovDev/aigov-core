# Repository Social Preview Asset

## Summary

This change adds a prepared GitHub social preview image at `assets/social-preview.png`. It presents AIGov Core as an open-source ledger-authoritative governance runtime and illustrates the evidence, compliance, and verification steps already described by the project.

The asset is static repository artwork. It does not change runtime behavior, API contracts, security controls, package contents, or release behavior.

## Evaluation gate

The image was rendered locally and visually reviewed.

- PNG dimensions: 1280 × 640 pixels.
- File size: 47,562 bytes (below GitHub's 1 MB limit).
- Color mode: RGB, with a solid background.
- Copy uses existing project terms: evidence, deterministic compliance, portable audit export, and verification.

GitHub recommends 1280 × 640 pixels for best social preview display and requires PNG, JPG, or GIF under 1 MB. This asset meets those requirements.

## Human approval gate

This PR prepares the image file only. A repository maintainer must review the artwork and upload it through **Settings → General → Social preview** after merge. No external post or launch announcement is made.

## Risk assessment

The image makes no adoption, customer, certification, or benchmark claim. It contains no third-party logo, sensitive information, or customer data. The flow is a high-level presentation of repository capabilities, not a normative architecture or enforcement diagram.

## Rollback plan

Revert this PR to remove `assets/social-preview.png` and this report. No code, data, or repository settings need migration.

## Changed files

| File | Role |
| --- | --- |
| `assets/social-preview.png` | Upload-ready GitHub social preview |
| `docs/reports/social-preview-asset.md` | Scope, checks, limitations, and maintainer upload step |
