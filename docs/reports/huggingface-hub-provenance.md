# Hugging Face Hub provenance audit report

## Scope
Python SDK opt-in capture of selected model and dataset files at resolved immutable revisions, SHA-256 manifest and artifact verification, and offline regression tests.

## Risk assessment
Untrusted metadata is source-reported; selected file hashes do not establish publisher authenticity. Verification requires a separately trusted manifest digest. Private repository identifiers must not be disclosed without authorization. No model code is executed. No runtime enforcement or mandatory dependency is introduced.

## Changes and controls
Revision mismatch and unsafe or duplicate paths are rejected. Downloaded bytes are hashed in chunks. Remote exception messages are suppressed in ordinary tracebacks; exception context may still retain sensitive data and must not be logged indiscriminately.

## Verification and tests
Run `cd python && python -m pytest tests/test_huggingface_provenance.py -q`. Mocked cases cover model and dataset capture, tampering, invalid paths, revision mismatch and error message redaction. Results pending CI; live Hub compatibility is not yet verified.

## Limitations and residual risk
No publisher signature, complete inventory, independent metadata validation or automatic Core evidence submission. Malformed manifests and credential handling require further hardening. Do not treat this report as evidence of a completed external audit.
