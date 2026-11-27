# Repository Social Preview Asset

## Summary

This change adds a prepared GitHub social preview image at `assets/social-preview.png`. The artwork follows the visual identity of AIGov's existing public Open Graph card: restrained charcoal surfaces, warm ivory typography, muted neutral text, a low-contrast grid, and a small blue-gray accent.

It presents AIGov Core as open-source evidence infrastructure for high-stakes AI systems. The image is static repository artwork and does not change runtime behavior, API contracts, security controls, package contents, or release behavior.

## Evaluation gate

The image was rendered locally, visually reviewed, and compared with the existing public AIGov share image and site palette.

- PNG dimensions: 1280 × 640 pixels.
- File size: 27,572 bytes (below GitHub's 1 MB limit).
- Color mode: RGB with a solid background.
- Palette is aligned to published AIGov tokens: `#0a0d0f`, `#141a1e`, `#eceae4`, and the restrained `#6fa8b8` accent.
- Copy reuses project positioning: evidence infrastructure, auditability, policy enforcement, and compliance evidence.
- No process-flow diagram or new capability claim is depicted.

GitHub recommends 1280 × 640 pixels for best social preview display and requires PNG, JPG, or GIF under 1 MB. This asset meets those requirements.

## Human approval gate

This PR prepares the image file only. A repository maintainer must review the artwork and upload it through **Settings → General → Social preview** after merge. No external post or launch announcement is made.

## Risk assessment

The image makes no adoption, customer, certification, or benchmark claim. It contains no third-party logo, sensitive information, or customer data. The artwork is a positioning card, not a normative architecture or enforcement diagram.

## Rollback plan

Revert this PR to remove `assets/social-preview.png` and this report. No code, data, or repository settings need migration.

## Changed files

| File | Role |
| --- | --- |
| `assets/social-preview.png` | Upload-ready GitHub social preview |
| `docs/reports/social-preview-asset.md` | Scope, checks, limitations, and maintainer upload step |
