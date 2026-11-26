# Security review package for an external auditor: AIGov Core, release 0.4.0-rc.1

**This package is prepared for an independent security review. It is not an audit, and no review has been performed by
anyone who is independent of this project.** The internal work described in `docs/reports/` is the project's own verification.
Describing it as an independent audit would be wrong.

## What the auditor receives

| File | Contents |
|---|---|
| `architecture.md` | Components, data flows, the single-host topology, and what each component stores |
| `trust-boundaries.md` | Who and what is trusted at each boundary, and what each boundary is protected by |
| `security-invariants.md` | Each invariant the system claims, its enforcement point, and the tests that check it |
| `known-limitations.md` | Residual risks R-1 to R-11 with their current status, and the limits of each claim |
| `source-locations.md` | The source file and function for each enforcement point |
| `reproducing-the-tests.md` | Exact commands, environment, and the expected results |

## What the auditor should not rely on

- The internal tests check the behaviour the project chose to test. They do not prove that no other behaviour exists.
- The crash tests and the two-volume test need a fault-injection build or real separate volumes. They are not part of the default build.
- The benchmark and load figures are from one workstation. They are not capacity guarantees.
- Provenance and SBOMs are unsigned. Nothing in this repository proves who built a binary.

## Scope

In scope: the Core HTTP service (`rust/`), the SDK's executor, store, reconciliation, and authorization verification code (`python/aigov_py/trusted/`),
the key registry, the policy bundle verification and anchors, and the deployment configuration (`rust/Dockerfile`, the environment names in
`scripts/deploy_preflight.py`).

Out of scope: the downstream systems that executors act on, the customer's identity provider, the load balancer, the host, the database administration,
and the platform (hosted) product code, which is outside this repository's Core.
