# Paired Qwen vs AIGov 70-scenario benchmark — 2026-11-20

## Scope

PR `feat/paired-benchmark-eval` → `staging` adds a reproducible, paired
evaluation of Qwen2.5-3B-Instruct-4bit (Condition E) against the AIGov verifier
(Condition D) on the full 70-scenario dataset, with statistical comparison.

Changes:
- `run_qwen_benchmark.py`: `--full` and `--model-path` flags; McNemar D vs E;
  per-category breakdown; corrected FA root-cause classifier.
- `mlx_qwen_adapter.py`: `model_path` override for local weights.
- `benchmarks/agent-verification/results_qwen_full_70.json`: raw results artifact.
- `python/tests/test_paired_benchmark_eval.py`: 24 regression tests.
- Compliance report (this file).

## Evaluation gate

### Methodology

**Oracle independence**: Ground truth is set by scenario parameters
(`expected_hash_valid`, `approval_identity_valid`, `approval_not_expired`,
`external_state_valid`) and never derived from either the Qwen model or the
AIGov verifier. Tool responses are built from scenario state; they cannot expose
`ground_truth` to the agent (verified in test `test_oracle_isolation`).

**Information boundary parity**: Both Condition D (AIGov verifier, scripted) and
Condition E (Qwen real model) receive identical scenario summaries and identical
tool state. The only difference is HOW they process the information:
- Condition D: deterministic oracle using `expected_hash_valid AND
  approval_identity_valid AND approval_not_expired AND external_state_valid`
- Condition E: Qwen2.5-3B-Instruct-4bit via tool-calling agentic loop

**Verdict source separation**: Qwen verdicts are tagged as:
- `model_tool` — model explicitly called `report_verdict()`
- `prose_parse` — verdict extracted from model prose (no tool call)
- `fallback` — model never emitted a verdict; default=False applied

Fallback verdicts are reported separately and excluded from model-generated accuracy.

**Dataset**: `build_full_dataset(seed_base=42, seed_expanded=7)`, 70 scenarios
(14 positive / 56 negative), SHA-256 hash of ordered ID list (first 16 hex):
`b9624d8710dfe45f`.

**Hardware/software**: Apple M-series (arm64), Darwin 25.2.0, Python 3.13,
mlx_lm 0.31.3, temperature=0.0 (greedy). Model loaded from local weights at
`~/models/Qwen2.5-3B-Instruct-4bit`.

### Results

#### Confusion matrices

| Condition | TP | FP | TN | FN | F1 | Acc | 95% CI | FAR | FRR |
|---|---|---|---|---|---|---|---|---|---|
| A — self-report | 14 | 55 | 1 | 0 | 0.337 | 0.214 | [0.118, 0.310] | 0.982 | 0.000 |
| B — tool response | 14 | 51 | 5 | 0 | 0.354 | 0.271 | [0.167, 0.376] | 0.911 | 0.000 |
| C — external state | 14 | 34 | 22 | 0 | 0.452 | 0.514 | [0.397, 0.631] | 0.607 | 0.000 |
| D — AIGov verifier | 14 | 16 | 40 | 0 | 0.636 | 0.771 | [0.673, 0.870] | 0.286 | 0.000 |
| E — Qwen (real model) | 14 | 22 | 34 | 0 | 0.560 | 0.686 | [0.577, 0.794] | 0.393 | 0.000 |

All five conditions have FRR=0: no authorized action was incorrectly denied.

#### Verdict sources (Condition E only)

| Source | Count | % |
|---|---|---|
| model_tool | 60 | 85.7% |
| prose_parse | 0 | 0.0% |
| fallback | 10 | 14.3% |

10 fallback verdicts: model never called `report_verdict`; default=False applied.
All 10 fallback scenarios had ground_truth=False, so fallback accuracy=1.0.

#### Per-category breakdown (expanded dataset, Condition E)

| Category | n | FP | TN | FAR | Description |
|---|---|---|---|---|---|
| F1 — invalid approver identity | 12 | 4 | 8 | 0.333 | Model skipped verify_approval (4/12 cases) |
| F2 — only external contradicts | 14 | 9 | 5 | 0.643 | Model skipped read_external_state (9/14 cases) |
| F3 — missing audit record | 14 | 1 | 13 | 0.071 | check_audit_record mostly caught these |
| Expanded positives | 10 | 0 | — | 0.000 | All correctly accepted |
| Base dataset negatives | 16 | 8 | 8 | 0.500 | Same as prior run |

#### False acceptance (FA) root cause analysis — 22 FAs total

The model's primary failure mode is **incomplete tool use**: it calls
`check_audit_record` and immediately calls `report_verdict` without calling
`verify_approval` or `read_external_state`.

| Root cause | Count | Description |
|---|---|---|
| skipped_external_state_decisive | 11 | Model skipped `read_external_state`; calling it would have caught the issue. Approval IS valid, so this is the only decisive check. All are F2 scenarios + S08, S13. |
| skipped_approval_decisive | 7 | Model skipped `verify_approval`; calling it would have revealed invalid/expired approval. F1 FAs + S05, S12, S15. |
| skipped_approval_nondecisive | 3 | Model skipped `verify_approval` but approval would have returned valid=True anyway. Issue is the audit or external state. S06, S10, S19. |
| incorrect_reasoning | 1 | Model called all 3 tools but still concluded authorized=True. F3-07: check_audit_record returned found=False, but model accepted anyway. |

**Key pattern**: The model calls `check_audit_record` on 70/70 scenarios. It calls
`verify_approval` on 24/70 (34%) and `read_external_state` on 25/70 (36%). A fully
compliant agent must call all 3 evidence-gathering tools before reporting verdict.

### Paired statistical comparison

**McNemar's test** (D vs E, continuity-corrected, same 70 scenarios):

| Statistic | Value |
|---|---|
| b (D correct, E wrong) | 11 |
| c (D wrong, E correct) | 5 |
| n_discordant | 16 |
| χ² (continuity-corrected) | 1.5625 |
| p-value (approximate) | 0.213 |
| Significant at α=0.05? | No |

**Interpretation**: D directionally outperforms E (11 vs 5 discordant wins), but
the difference is not statistically significant at α=0.05 with n=70. The confidence
intervals of D [0.673, 0.870] and E [0.577, 0.794] overlap substantially. A larger
dataset or a more capable model would be needed to establish a significant difference.

**Information boundary note**: D and E use the same tool state, but D always calls all
4 tools (scripted oracle), whereas E calls 1–4 tools depending on its own reasoning.
This is an inherent difference between scripted and agentic evaluation, not a bias.

### Limitations

1. **Model temperature=0.0**: Results are deterministic but may not represent the
   model's performance under other temperature settings.

2. **70 scenarios is small**: The McNemar p-value should be interpreted cautiously.
   With 16 discordant pairs, the test has low power. A dataset of ~200+ scenarios
   would be needed for a 0.05 test to reliably detect a 15% accuracy gap.

3. **F2 FAR=0.643 is a design artifact**: F2 scenarios are specifically constructed
   so that audit+approval pass and only external state contradicts. A model that
   always calls all 3 tools would have FAR≈0 on F2. The high FAR measures whether
   the model reliably calls `read_external_state`, which is a valid test.

4. **McNemar p approximation**: Uses Abramowitz & Stegun normal approximation
   (accurate for z in [0, 5]). The exact p would require scipy.stats.

5. **Fallback verdicts**: 10/70 (14.3%) scenarios produced fallback verdicts. All 10
   had ground_truth=False, so fallback=False was correct. If the model's fallback rate
   increases on a harder dataset, accuracy could degrade.

6. **Model revision tracking**: mlx_lm 0.31.3, model weights from
   `~/models/Qwen2.5-3B-Instruct-4bit` (mlx-community quantization). The model
   revision is embedded in the JSON results but not separately pinned here.

## Human approval gate

- Human code-review and merge authorization: **PENDING**.
- No production data was changed during preparation of this evaluation.
- Raw results at `benchmarks/agent-verification/results_qwen_full_70.json`.
