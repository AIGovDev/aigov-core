# Independent security review: funding and outreach

**Reviewed:** 2026-11-27  
**Status:** Eligibility research and message drafts only. No audit is booked and no external application has been submitted.

## Prioritized routes

| Route | Current fit | Funding / conditions | Status and next action |
|---|---|---|---|
| GitHub Secure Open Source Fund | A possible small-maintainer security program, but the current verified adoption baseline is only 2 stars and low PyPI downloads; its stated fit emphasizes fast-growing dependencies with demonstrated traction. | $10,000 per selected project; rolling applications; selection-based, with 15 hours over 3 weeks plus later check-ins. No audit award or selection is guaranteed. | Current traction criterion is a material weakness. Keep as a later candidate; no application submitted. |
| OSTIF project audit | Strongest first contact: OSTIF scopes FOSS audits and matches projects with audit firms. | No publicly guaranteed grant amount, award, or deadline. Funding depends on sponsor availability and scoping. | Prepare a no-commitment scoping inquiry to `derek@ostif.org`; ask whether AIGov Core can be considered for a funded or subsidized review. Not sent. |
| Trail of Bits Patch the Planet | Potentially strong, no-fee program for selected open-source projects. | Selection-based, short focused engagement; selection is not guaranteed and does not imply an endorsement or full security audit. | Prepare application for the Rust ledger, tenant isolation, authorization and release pipeline. Not submitted. |
| OpenSSF Best Practices badge | Relevant low-cost security baseline; self-assessment is not independent audit evidence. | Free self-certification; no grant or auditor provided. Badge requires meeting and documenting its criteria. | Do not claim a badge. Complete a criterion-by-criterion evidence review separately before applying. |
| NLnet Foundation | Project mission could fit privacy-respecting, open Internet infrastructure in principle. | Next published deadline: 2027-01-03 12:00 CET; typical grants €5,000–€50,000, milestone-based. CodeSupply appears narrower; Restack excludes most AI projects unless the project exceeds the program's stated adoption threshold. NLnet’s current GenAI policy prohibits using generative AI to write proposals or answer interactive evaluation questions. The applicant must write the proposal themselves; AI must not draft or edit it. | Not a direct security audit award and current fit is uncertain. Do not submit AI-written prose as applicant-authored. Ask NLnet about eligibility before investing in a full application. |
| SECURE cascade funding (EU CRA support) | Possible only if AIGov s.r.o. itself is an eligible EU/EEA mSME and the funded activity directly supports its own Cyber Resilience Act compliance. | Second call deadline: 2027-01-29. Grant up to €30,000, with 50% co-financing, project period up to 180 days, and contractual milestones. | Not a grant to audit an unrelated open-source dependency. Needs legal-entity, SME, CRA-scope and matching-funds facts. Do not apply until the user explicitly approves the potential match and contractual terms. |
| European Cybersecurity Competence Centre (DIGITAL) | Not suitable as a solo Core security-audit application. | 2027 topic targets larger deployment/capacity actions, with €3m–€5m project size and a consortium context; deadline 2027-01-14. | Monitor only if a qualified consortium invites AIGov s.r.o.; do not prepare a standalone application. |
| Cure53 | Technically relevant independent auditor. | Commercial service; no verified public subsidy or open-source grant. | Prepare a scope/pricing inquiry only. Do not accept a quote or authorize paid work. |

## Draft outreach

### OSTIF (eligibility and potential subsidy inquiry; not sent)

**Subject:** AIGov Core — request to assess eligibility for a funded independent security audit

Hello OSTIF team,

I maintain AIGov Core, an AGPL-3.0 open-source Rust audit runtime with Python authorization and evidence tooling. It records supplied evidence in tenant-scoped ledgers, evaluates configured policy, and supports offline hash-chain verification. It is intended to make controls and their evidence inspectable; the hash chain does not prove that an external action occurred or that a statement is true.

We are preparing for an independent review of the Rust service and ledger, policy enforcement, OIDC and tenant boundaries, approval binding and replay protection, key lifecycle, Python executor and crash behavior, PostgreSQL concurrency, and release supply chain. Existing regression and adversarial tests cover many invariants, while known gaps include nonce consumption and audit append not sharing one atomic transaction, unverified multi-host active-active behavior, incomplete full-build reproducibility, and no trusted timestamp. No external audit has been completed.

Would OSTIF consider AIGov Core for a funded or subsidized review, and what project maturity, scope, maintainer time, and funding details would you need to assess eligibility? We are seeking a written scope, findings with reproductions, remediation retest, and a public report if disclosure can be coordinated safely. This inquiry does not authorize paid services or commit the project to contractual terms.

Regards,  
AIGov Core maintainers

### Trail of Bits Patch the Planet (application material; not submitted)

> AIGov Core is an AGPL-3.0 Rust runtime for policy-gated AI workflow evidence. The review target is the code that authenticates principals, isolates tenants, binds approvals to actions, prevents replay, appends and verifies ledger records, and packages release artifacts. The project has regression and adversarial tests for these paths, but it has not had an independent security audit. We would prioritize a focused threat-led review of Rust authorization and ledger paths, Python replay and crash recovery, tenant isolation and CI/release supply chain. Known limitations include non-atomic nonce consumption and audit append, no verified multi-host active-active profile, and incomplete clean-build reproducibility. Desired outputs are specific findings, reproducible tests, remediation patches or guidance, and retest of fixes. AIGov Core will not present selection for a program as a certification or endorsement.

### Cure53 (non-binding scope and price inquiry; not sent)

> Could you provide an indicative scope, lead time, and price range for an independent source and security review of AIGov Core (AGPL-3.0)? Proposed areas are Rust HTTP/API authorization and tenant isolation, evidence ledger and policy evaluation, approval binding/replay prevention, Python executor and crash behavior, PostgreSQL concurrency, cryptographic export verification, and CI/release supply chain. We can provide a target commit, threat model, regression/adversarial tests and known limitations. Please clarify the distinction between source review, penetration testing, remediation retest, report publication, and any available open-source or subsidized engagement. This is a request for information only; no procurement commitment is authorized.

## Verification sources

- GitHub Secure Open Source Fund eligibility and conditions: <https://github.com/open-source/github-secure-open-source-fund>
- OSTIF audit process: <https://ostif.org/get-an-audit/>; project contact: <https://ostif.org/contact/>
- Trail of Bits Patch the Planet: <https://www.trailofbits.com/patch-the-planet>
- OpenSSF Best Practices badge: <https://bestpractices.coreinfrastructure.org/en>
- NLnet proposal process: <https://nlnet.nl/propose/>; program calls: <https://nlnet.nl/funding/>
- SECURE second call: <https://www.secure4sme.eu/cascade-funding/second-open-call>
- ECCC 2027 cybersecurity call: <https://ec.europa.eu/info/funding-tenders/opportunities/portal/screen/opportunities/topic-details/DIGITAL-ECCC-2027-DEPLOY-CYBER-11-AI4SME>
- Cure53: <https://cure53.de/>

Always re-check the live call page before applying: eligibility, budgets, dates and terms can change. A funding inquiry is not an application, an accepted application is not an audit, and an internal audit package is not independent assurance.
