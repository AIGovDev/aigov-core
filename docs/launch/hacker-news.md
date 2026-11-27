# Show HN draft

**Title:** Show HN: AIGov Core – a Rust audit runtime for policy-gated AI evidence

I built AIGov Core to make one narrow part of AI governance executable: accept structured evidence, evaluate configured policy, and return an explicit VALID, INVALID, or BLOCKED state from the ledger.

The runtime is AGPL-3.0 and has Rust and Python components. The five-minute local walkthrough and example export are in the repository. The verifier checks consistency of recorded evidence; it does not prove an action happened or that evidence is truthful or complete.

The repo includes a small 20-scenario synthetic benchmark with limitations documented. A public static evidence viewer is still awaiting publication and browser verification, so this post should not go live until that status is updated.

Feedback I would value: which trust boundary or failure mode should an independent reviewer examine first?

Before posting, update the demo status after real deployment, include its URL only after browser verification, follow current Show HN rules, and do not ask for votes or stars.
