# Reddit draft

**Suggested post:** I built an open-source policy-gated evidence runtime for AI systems; looking for technical critique

I am developing AIGov Core, an AGPL-3.0 Rust audit runtime with Python tooling. It accepts structured evidence, evaluates configured policy, and exports a ledger-backed run summary. A hash-chain check can detect changes in supplied records, but cannot prove that an action happened or that the evidence is true or complete.

The repo documents a local five-minute quickstart and has sample exports. Clean-install reproduction is pending because the Rust toolchain is not available in this environment. Its current agent-verification benchmark is a small synthetic study, not a production comparison. I am preparing an independent security review and would especially value critique of the trust model and multi-process gaps.

Before posting, pick one community where technical self-promotion is allowed, read its current rules, disclose maintainer status, and avoid reposting or asking for votes.
