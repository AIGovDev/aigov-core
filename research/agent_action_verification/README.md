# Agent Action Verification — Synthetic Benchmark v0

Minimal, deterministic, standard-library-only prototype of proposal → approval → execution → observation verification.

Run:
```bash
cd research/agent_action_verification
python -m unittest -v test_benchmark.py
python benchmark.py > results.json
```

Eight fixtures: authorized, post-approval change, wrong approval version, missing evidence, tampering, replay, divergent state, partial failure.

The expected fixture classification is 8/8, but **this is not an empirical accuracy estimate**. The fixture generator and verifier share assumptions; there is no independent adversary, live model, trusted timestamp, signing key, or externally attested observation. SHA-256 chaining alone does not prove the origin of evidence or prevent a fully rewritten chain. This prototype is not a compliance certification and does not replace the AIGov production verifier.

Next: separate fixture generation from verification, add independently signed event receipts and trustworthy state observations, test legitimate intervening updates, integrate a sandbox agent and report false positives and latency.
