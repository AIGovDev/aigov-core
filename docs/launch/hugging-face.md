# Hugging Face community draft

**Title:** AIGov Core evidence viewer: inspect an audit export in-browser

This is a browser-local static viewer for a sample AIGov Core evidence export. The file is read in the page; there is no upload endpoint. The viewer recomputes the included SHA-256 chain and rejects modified records.

A passing chain means the supplied records are internally consistent. It does not establish who created the file, whether an event occurred, whether the export is complete, or whether the system is legally compliant. Use synthetic or public examples only.

Publish only after the Space exists at its verified public URL; valid and tampered samples, malformed input, size limits, unsafe URLs and malicious HTML have been tested in the deployed Space on desktop and mobile.
