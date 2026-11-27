# LinkedIn draft

I have been building AIGov Core, an open-source Rust audit runtime for policy-linked AI evidence.

The core flow is simple: record structured evidence, evaluate the configured policy, and expose an explicit VALID, INVALID or BLOCKED result with an export that can be checked later.

The important boundary is equally simple: hash-chain consistency can reveal changes in the supplied records, but it cannot prove that an event occurred, that evidence is complete, or that a system complies with law.

The repository includes a documented local quickstart and a small synthetic benchmark with its false accepts and limitations documented. I am preparing the code and trust model for an independent security review. Technical feedback on tenant boundaries, approval binding and recovery behavior is welcome.

Add a link to the public viewer Space only if and when it is deployed. Do not tag or imply partnership with any organization.
