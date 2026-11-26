# Hugging Face Hub provenance

From the repository root, install the Python SDK and optional Hub client:

```sh
python -m pip install -e ./python huggingface_hub
```

```python
from huggingface_hub import hf_hub_download
from aigov_py.huggingface_provenance import (
    capture_hub_provenance, manifest_digest, verify_artifact,
)

manifest = capture_hub_provenance("openai-community/gpt2", ["config.json"], token=False)
anchor = manifest_digest(manifest)
# In production, retain the anchor in a separately trusted evidence store.
path = hf_hub_download(manifest["repo_id"], "config.json",
                       revision=manifest["commit"], token=False)
assert verify_artifact(manifest, "config.json", path,
                       expected_manifest_sha256=anchor)
```

The example hashes selected bytes without executing model code. The revision is
resolved before downloading. For datasets pass repo_type="dataset"; for private
repositories use the Hub client's authentication mechanism. Do not publish private
repository identifiers or manifests without authorization.

The manifest records source-reported license metadata separately from local
hashes. It is not a publisher signature, complete repository inventory, proof
of training provenance, or a runtime authorization decision. A digest computed
from an untrusted manifest at verification time provides no independent trust.
This example does not automatically submit evidence to Core.

Run offline tests:

```sh
cd python
python -m pytest tests/test_huggingface_provenance.py -q
```
