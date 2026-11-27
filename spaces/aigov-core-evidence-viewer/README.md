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

## Try the public demo

After this Space is published, open it and load `sample-evidence-export.json` with
the file picker. The file is deterministic synthetic data; its record hash should
verify, and editing the event without recomputing the chain should fail verification.
You can also open the bundled file using the same-origin path field.

## Prepare or check the package

From the root of the AIGov Core checkout:

```bash
python3 scripts/prepare_hf_space.py
python3 scripts/prepare_hf_space.py --check
node examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs
```

Generate the sample and synchronize the viewer before publishing:

```bash
python3 scripts/generate_hf_space_sample.py
python3 scripts/prepare_hf_space.py
python3 scripts/prepare_hf_space.py --check
node examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs
```

The `Sync Hugging Face Space` workflow publishes this directory to the fixed
public Static Space only when manually dispatched, using the repository's
`HF_TOKEN` secret. Never place a token in source control. A successful workflow
prints the Space URL and upload commit. Until that workflow succeeds, no public
Space URL is claimed.

## Privacy and verification scope

Choose a JSON export with the file picker. The page reads it in the browser tab; it has no upload endpoint or external script. An optional URL path is restricted to same-origin GET requests without credentials or redirects. The 8 MiB and 5,000-record limits keep the demo bounded.

The viewer recomputes every included record hash using SHA-256 over `prev_hash + newline + event_json`, checks links from the `GENESIS` value, and compares the final hash to the export's declared chain head. A passing result means the supplied records are internally consistent. It does **not** establish a trusted chain head, signer identity, that an AI action occurred, or legal compliance. It does not verify signed export bundles.

Use synthetic or public demo exports in a hosted Space. Do not use this viewer as a production verifier or upload confidential evidence to any hosted service.

## Maintenance

Edit the canonical viewer in the main repository, then run `python3 scripts/prepare_hf_space.py` to refresh this package. The Python smoke test checks that the packaged file stays synchronized and rejects network-loading or unsafe HTML insertion patterns.
