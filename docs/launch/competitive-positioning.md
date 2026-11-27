# Comparison with adjacent tools

This comparison describes category roles, not a ranked product evaluation. Capabilities vary by configuration and release. No head-to-head workload, integration-depth study, price comparison or product superiority result has been measured.

| Tool/category | Primary role in the documented product | Relationship to AIGov Core |
|---|---|---|
| OpenTelemetry | Vendor-neutral APIs, SDKs and collection for traces, metrics and logs | Telemetry can supply context; AIGov Core focuses on policy-linked evidence records, verdict projection and a promotion gate. AIGov does not replace general telemetry collection. |
| MLflow Tracking | Logging parameters, code versions, metrics and artifacts for ML experiments | Experiment tracking can be one evidence source. AIGov Core does not replace a model registry or full experiment lifecycle. |
| Langfuse | LLM observability, tracing and evaluation workflows | LLM traces/evaluations can inform governance evidence. AIGov Core does not provide a general LLM tracing or analytics platform. |
| Agent security and guardrail products | Policy checks, tool controls, runtime monitoring or threat detection; scope differs by product | AIGov Core records supplied evidence and applies its configured governance policy. It is not a general prompt-injection detector or complete agent firewall. |

## Evaluation criteria for a fair comparison

Compare only the same deployment shape and use case. Record whether each product:

1. collects telemetry or receives caller-supplied evidence;
2. enforces before an action, observes after it, or supports both;
3. stores append-only records and what trust anchor protects them;
4. binds approvals to a specific action, resource, tenant and policy revision;
5. supports replay, export, signatures, retention and offline verification;
6. exposes tenant isolation, recovery, and operational guarantees;
7. measures real-world behavior or only consistency of recorded evidence.

AIGov hash-chain verification is consistency checking; it does not prove truth, completeness, signer identity, external action occurrence or legal compliance. A useful combined architecture may use observability and model tooling for signals while using a governance runtime for explicit policy and evidence handling.

Product references: OpenTelemetry documentation at https://opentelemetry.io/docs/, MLflow Tracking documentation at https://mlflow.org/docs/latest/ml/tracking/, Langfuse documentation at https://langfuse.com/docs, and AIGov docs/trust-model.md.
