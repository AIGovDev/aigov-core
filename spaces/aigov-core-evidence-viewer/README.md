---
title: AIGov Core Evidence Viewer
sdk: static
app_file: index.html
license: agpl-3.0
short_description: Inspect an AIGov audit export locally in your browser.
tags:
  - ai-governance
  - audit
  - evidence
---

# AIGov Core evidence viewer

A static, browser-only viewer for AIGov Core audit-export JSON. The packaged `index.html` is generated from the canonical viewer at `examples/reconstructible-agent-demo/viewer/index.html` in the AIGov Core repository.

## Prepare or check the package

From the root of the AIGov Core checkout:

```bash
python3 scripts/prepare_hf_space.py
python3 scripts/prepare_hf_space.py --check
node examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs
```

To publish this Space, create a separate Hugging Face Space using the **Static** SDK and copy the files in this directory to the Space repository root. This repository change only prepares the files; it does not create, configure, or publish a Space.

## Privacy and verification scope

Choose a JSON export with the file picker. The page reads it in the browser tab; it has no upload endpoint or external script. An optional URL path is restricted to same-origin GET requests without credentials or redirects. The 8 MiB and 5,000-record limits keep the demo bounded.

The viewer recomputes every included record hash using SHA-256 over `prev_hash + newline + event_json`, checks links from the `GENESIS` value, and compares the final hash to the export's declared chain head. A passing result means the supplied records are internally consistent. It does **not** establish a trusted chain head, signer identity, that an AI action occurred, or legal compliance. It does not verify signed export bundles.

Use synthetic or public demo exports in a hosted Space. Do not use this viewer as a production verifier or upload confidential evidence to any hosted service.

## Maintenance

Edit the canonical viewer in the main repository, then run `python3 scripts/prepare_hf_space.py` to refresh this package. The Python smoke test checks that the packaged file stays synchronized and rejects network-loading or unsafe HTML insertion patterns.
