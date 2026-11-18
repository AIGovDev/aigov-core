# Verifiable Agent Actions — External Research Collaboration Proposal

**Project:** AIGov | **Status:** Draft for external review (not an announced partnership) | **Contact:** hello@govbase.dev

## Research question
Can an independent verifier determine whether an AI agent executed precisely the state change authorized by a human, using evidence captured at proposal, approval, execution, and verification time?

## Hypothesis
Binding the proposed action, human approval, execution request, and observed post-action state into a tamper-evident evidence chain will improve detection of unauthorized or unprovable agent actions relative to an approval-status-only baseline.

## Scope and methodology
Build a reproducible test harness around a sandboxed record-update agent. No production customer data, live procurement system, or privileged external access is required.

Test conditions:
1. Authorized action with matching observed state.
2. Parameters altered after human approval.
3. Approval references a different proposal version.
4. Missing, reordered, or tampered evidence.
5. Replayed execution / duplicate action.
6. Execution succeeds but observed state diverges.
7. Legitimate subsequent update (avoid false accusations of unauthorized execution).
8. Partial failure or uncertain external state.

Baselines: (A) dashboard approval flag; (B) ordinary application logs; (C) AIGov verifiable evidence chain.

Primary outcomes: detection precision and recall by failure class; false-positive rate; unverifiable-action rate; time and compute overhead. Report confidence intervals, all failures, and explicit threat-model limitations. Do not claim causal effectiveness before running the experiment.

## Deliverables
- Public synthetic scenarios and fixtures.
- Deterministic runner and verification interface.
- Independent verification report with negative results.
- Short research manuscript and integration guide.
- Reproduction instructions and machine-readable result schema.

## Collaboration ask
Seeking a technical discussion, feedback on evaluation design, and potentially a small independent pilot with researchers or engineers working on agent reliability, evaluation, or oversight. This is not a claim of endorsement by OpenAI or Anthropic.

## Proposed milestones
Week 1: threat model, scenarios, test fixtures and baselines.
Week 2: implement harness and verification adapters.
Week 3: run experiments and error analysis.
Week 4: independent reproduction, public report and outreach.

## Boundaries
No undisclosed model access, confidential model outputs, or claims of compliance certification. Publish only after verifying security, licenses, permissions, and reproducibility.

## OpenAI Codex Open Source Fund — application draft
**Project name:** AIGov Core
**Repository:** https://github.com/AIGovDev/aigov-core
**Description:** Open-source engineering infrastructure for capturing and independently verifying evidence of AI system actions, approvals, and execution outcomes.
**Use of credits:** Codex-assisted PR review, regression-test generation, issue triage, maintainer automation, and release/security verification for the open-source repository; a separate synthetic agent-action evaluation harness where permitted.
**Other contributors:** Confirm current contributors and roles before submission. Do not invent collaborators.
**Evidence to attach:** public repo, documented tests, recent merged PRs, maintainer permissions, usage evidence, roadmap.

## Anthropic External Researcher Access — application draft
**Research topic:** Independent evaluation of whether AI agents can provide verifiable evidence linking human authorization to executed state changes.
**Safety relevance:** Oversight, agent reliability, auditability, detection of action drift and unverifiable actions.
**Methods:** Synthetic controlled scenarios, matched baselines, public test harness, error taxonomy, reproducible metrics.
**Requested support:** API credits for permitted model-based agent evaluations. No nonpublic model access requested.
**Expected output:** Open benchmark, evaluation report, and reproducible code.
**Caveat:** This is a research access request, not a corporate partnership application.

## Short outreach message
Subject: Research collaboration — independently verifiable AI agent actions

Hello,

I lead AIGov, an open-source engineering project focused on verifiable evidence for AI system actions and human oversight.

We're preparing a reproducible benchmark testing whether an independent verifier can establish that an AI agent executed the exact state change a human approved, including adversarial cases involving post-approval modifications, missing evidence, and divergent execution outcomes.

Would your team be open to a short technical discussion about evaluation design or a narrowly scoped independent pilot? I can share the threat model, public repository, and draft experimental protocol.

Best regards,
Monika Dvořáčková
AIGov | https://govbase.dev
