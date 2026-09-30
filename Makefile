SHELL := /bin/bash
-include .env
export

AIGOV_MODE ?= ci

.PHONY: \
	FORCE \
	audit audit_bg audit_stop audit_restart audit_logs require_audit_url \
	status verify verify_log \
	run \
	require_run ensure_dirs ensure_reports_dir new_run report_new report_prepare report_prepare_new ensure_evidence pr_report pr_report_commit db_ingest \
	check_audit \
	report_template report_init report_fill \
	bundle verify_cli evidence_pack \
	emit_event \
	flow flow_full \
	pr_prepare gate core-runtime-examples-check reference-integrations-check reconstructible-demo-check runtime-packaging-check runtime-observability-check lineage-governance-check \
	observability observability-manifest operational-snapshot operational-health-score operational-intelligence-report observability-check \
	registry-check \
	autonomous-governance-check multi-agent-governance-check \
	multi-tenant-check tenant-isolation-check \
	conformity-workflow-check regulatory-workflow-check \
	research-package-check academic-publication-check \
	regulatory-manifest ai-act-obligations regulatory-evidence regulatory-export regulatory-check \
	microbenchmark-check empirical-evaluation-run empirical-evaluation-check manuscript-evidence-check \
	evidence-quality-check \
	audit_close \
	demo demo_new \
	env_check \
	engineering_loc \
	standards-conformance governance-standards-check \
	public-sdk-packages-check dependabot-config-check oss-ecosystem-check enterprise-readiness-check \
	validate-changelog generate-release-notes release-readiness-report release-readiness-check \
	cursor-plugin-validate cursor-plugin-smoke cursor-plugin-check cursor-marketplace-listing-check \
	downstream-consumption-smoke \
	local-demo local-demo-curl

.PHONY: discovery_scan
discovery_scan:
	cd python && . .venv/bin/activate && \
		python -m aigov_py.cli discovery scan --path ..

FORCE:

# Optional operator-provided audit HTTP base URL (GovAI Platform or customer self-host).
# AIGov Core does not start, background-manage, or readiness-poll a hosted audit server.
AUDIT_URL ?= $(GOVAI_AUDIT_BASE_URL)

# Legacy: GOVAI_AUTO_MIGRATE applied only when using an external Platform-operated runtime.
GOVAI_AUTO_MIGRATE ?= true

# Explicit binary: this crate ships multiple `[[bin]]` targets; `cargo run` without `--bin` fails.
AIGOV_AUDIT_BIN ?= portable_evidence_digest_once

# ================================
# Env debug
# ================================

env_check:
	@echo "PWD=$$(pwd)"
	@echo "SUPABASE_URL=$(SUPABASE_URL)"
	@echo "SUPABASE_SERVICE_ROLE_KEY=$$(if [ -n "$(SUPABASE_SERVICE_ROLE_KEY)" ]; then echo "SET"; else echo "MISSING"; fi)"
	@ls -la .env 2>/dev/null || true

# Compliance "gate" check used by CI:
# ensure that generated audit reports include the minimum required sections.
gate:
	@python3 scripts/gate_reports.py

# Adoption examples must not call platform-only HTTP routes (drift vs govai_api.rs).
core-runtime-examples-check:
	@python3 scripts/check_core_runtime_example_routes.py

reference-integrations-check:
	@python3 scripts/check_reference_integrations.py

reconstructible-demo-check:
	@python3 scripts/check_reconstructible_demo.py

runtime-packaging-check:
	@python3 scripts/check_runtime_packaging.py

runtime-observability-check:
	@python3 scripts/check_runtime_observability.py

lineage-governance-check:
	@python3 scripts/check_lineage_governance_graph.py

# ================================
# Observability (docs/observability/)
# ================================

observability-manifest:
	@python3 scripts/validate_observability_manifest.py

operational-snapshot:
	@python3 scripts/validate_operational_snapshot.py --input examples/observability/sample-operational-snapshot.json

operational-health-score:
	@python3 scripts/operational_health_score.py --input examples/observability/sample-operational-snapshot.json

operational-intelligence-report:
	@python3 scripts/generate_operational_intelligence_report.py --input examples/observability/sample-operational-snapshot.json >/dev/null
	@echo "operational-intelligence-report: OK"

observability-check:
	@python3 scripts/observability_check.py

observability: observability-manifest operational-snapshot operational-health-score observability-check
	@echo "observability: OK"

registry-check:
	@python3 scripts/registry_check.py

# ================================
# Autonomous / multi-agent governance (autonomous/)
# ================================

autonomous-governance-check:
	@python3 scripts/autonomous_governance_check.py
	@$(MAKE) gate

multi-agent-governance-check:
	@python3 scripts/autonomous_governance_check.py --multi-agent
	@$(MAKE) gate

# ================================
# Multi-tenant governance (multi-tenant/)
# ================================

multi-tenant-check:
	@python3 scripts/multi_tenant_check.py

tenant-isolation-check: multi-tenant-check

# ================================
# EU AI Act conformity automation (conformity/)
# ================================

conformity-workflow-check:
	@python3 scripts/conformity_workflow_check.py

regulatory-workflow-check: conformity-workflow-check

# ================================
# Research / academic publication (research/)
# ================================

research-package-check:
	@python3 scripts/research_package_check.py

academic-publication-check: research-package-check

microbenchmark-check:
	@python3 scripts/microbenchmark_audit_engine.py

empirical-evaluation-run:
	@python3 scripts/run_full_empirical_evaluation.py

empirical-evaluation-check:
	@python3 scripts/empirical_evaluation_check.py

manuscript-evidence-check:
	@python3 scripts/manuscript_evidence_runner.py

# ================================
# Evidence quality (docs/evidence-quality/)
# ================================

evidence-quality-check:
	@python3 scripts/evidence_quality_check.py

# ================================
# Regulatory evidence (docs/regulatory/)
# ================================

regulatory-manifest:
	@python3 scripts/validate_regulatory_evidence_manifest.py

ai-act-obligations:
	@python3 scripts/validate_ai_act_obligations.py

regulatory-evidence:
	@python3 scripts/regulatory_evidence_check.py

regulatory-export:
	@python3 scripts/generate_regulatory_evidence_export.py >/dev/null
	@echo "regulatory-export: OK"

regulatory-check: regulatory-manifest ai-act-obligations regulatory-evidence regulatory-export
	@echo "regulatory-check: OK"

# Registered interchange conformance checks.
standards-conformance:
	@cd python && python3 -m pytest tests/test_standards_conformance.py -q

# Validates shipped interchange examples against the explicit registry-backed validators.
governance-standards-check:
	@echo "governance-standards-check is not available in AIGov Core; platform standards validation belongs to the proprietary platform repository."

public-sdk-packages-check:
	@python3 scripts/public_sdk_packages_check.py
	@echo "public-sdk-packages-check: OK"

dependabot-config-check:
	@python3 scripts/check_dependabot_config.py

oss-ecosystem-check:
	@python3 benchmarks/auditability-failures/run_benchmark.py
	@$(MAKE) gate
	@echo "oss-ecosystem-check: OK"

# Aggregate checks implemented with scripts/ present in AIGov Core (not the full platform repo).
enterprise-readiness-check:
	@$(MAKE) gate
	@$(MAKE) public-sdk-packages-check
	@$(MAKE) cursor-plugin-check
	@$(MAKE) core-runtime-examples-check
	@$(MAKE) reference-integrations-check
	@$(MAKE) reconstructible-demo-check
	@$(MAKE) runtime-packaging-check
	@$(MAKE) runtime-observability-check
	@$(MAKE) lineage-governance-check
	@python3 benchmarks/auditability-failures/run_benchmark.py
	@echo "enterprise-readiness-check: OK"

# GovAI Cursor plugin (manifest, rules, skills, local MCP bridge)
cursor-plugin-validate:
	@python3 scripts/validate_cursor_plugin.py

cursor-plugin-smoke:
	@python3 scripts/smoke_cursor_plugin.py

downstream-consumption-smoke:
	@cd tests/downstream-consumption/rust-consumer && cargo test --locked
	@cd rust && cargo build --locked --bin verify_audit_export_bundle_once
	@python3 scripts/downstream_python_consumption_smoke.py

cursor-plugin-check: cursor-plugin-validate cursor-plugin-smoke
	@echo "cursor-plugin-check: OK"

cursor-marketplace-listing-check:
	@python3 scripts/validate_cursor_marketplace_listing.py
	@echo "cursor-marketplace-listing-check: OK"

validate-changelog:
	@python3 scripts/validate_changelog.py

generate-release-notes:
	@python3 scripts/generate_release_notes.py --version $(or $(VERSION),0.2.1) $(if $(OUT),--out $(OUT),)

release-readiness-report:
	@python3 scripts/release_readiness_report.py --json

release-readiness-check:
	@$(MAKE) gate
	@$(MAKE) validate-changelog
	@$(MAKE) release-readiness-report
	@cd rust && cargo metadata --format-version=1 --locked >/dev/null
	@echo "release-readiness-check: OK"

# Optional: read-only probe against operator-configured GOVAI_AUDIT_BASE_URL (Platform/self-host). Core does not start a server.
local-demo:
	@echo "local-demo: requires GovAI Platform scripts/run_local_demo.py (not shipped in AIGov Core)."
	@exit 2

local-demo-curl:
	@bash examples/local-demo/curl-health-ready.sh

engineering_loc:
	@python3 scripts/test_engineering_loc_smoke.py

# Portable offline digest helper (no HTTP server).
audit:
	cd rust && cargo run --bin $(AIGOV_AUDIT_BIN) --locked

build-audit:
	cd rust && cargo build --locked --bin aigov_audit

# Run the ledger-authoritative HTTP runtime (bind: AIGOV_BIND, default 127.0.0.1:8088).
run-audit: build-audit
	cd rust && cargo run --bin aigov_audit --locked

audit_bg audit_stop audit_restart audit_logs:
	@echo "$@: AIGov Core does not manage a hosted audit HTTP service lifecycle."
	@echo "Run the GovAI Platform repository for SaaS runtime orchestration, or configure GOVAI_AUDIT_BASE_URL to your operator runtime."
	@exit 2
require_audit_url:
	@if [ -z "$${GOVAI_AUDIT_BASE_URL:-}" ]; then \
		echo "GOVAI_AUDIT_BASE_URL is required (AIGov Core does not start a local audit server)."; \
		echo "Point it at GovAI Platform or your self-host runtime, or use offline targets: governance-standards-check, scripts/ci_portable_artifact_bundle.py"; \
		exit 2; \
	fi

status: require_audit_url
	curl -sS "$(GOVAI_AUDIT_BASE_URL)/status" ; echo

verify: require_audit_url
	curl -sS "$(GOVAI_AUDIT_BASE_URL)/verify" -H "Authorization: Bearer $${GOVAI_API_KEY:-ci-test-api-key}" ; echo

# Legacy alias: `/verify-log` was retired in favor of `/verify`; kept as a name-compatible entrypoint.
verify_log: verify

# ================================
# Core
# ================================

run: require_audit_url
	cd python && . .venv/bin/activate && \
	GOVAI_AUDIT_BASE_URL=$${GOVAI_AUDIT_BASE_URL} GOVAI_API_KEY=$${GOVAI_API_KEY:-ci-test-api-key} GOVAI_PROJECT=$${GOVAI_PROJECT:-github-actions} RUN_ID=$(RUN_ID) python -m aigov_py.pipeline_train

require_run:
	@if [ -z "$(RUN_ID)" ]; then \
		echo "RUN_ID is required"; \
		exit 2; \
	fi

check_audit:
	@echo "check_audit: removed in AIGov Core (no GET /ready polling or localhost orchestration)."
	@echo "Use require_audit_url + operator runtime, or offline portable CI: python3 scripts/ci_portable_artifact_bundle.py"
	@exit 2

ensure_dirs:
	@mkdir -p docs/reports docs/audit docs/audit_meta docs/packs docs/evidence docs/policy

ensure_reports_dir:
	@mkdir -p docs/reports

new_run:
	@python3 -c 'import uuid; print(str(uuid.uuid4()))'

report_new:
	@$(MAKE) new_run

# ================================
# Evidence
# ================================

ensure_evidence: require_run ensure_dirs
	@set -euo pipefail; \
	if [ ! -f "docs/evidence/$(RUN_ID).json" ] && [ "$(AIGOV_MODE)" = "prod" ]; then \
		echo "ERROR: missing evidence in prod mode"; \
		exit 2; \
	fi; \
	cd python && . .venv/bin/activate && \
	if [ "$${AIGOV_COMPLIANCE_FETCH_STRICT:-}" = "1" ]; then \
		echo "ensure_evidence: strict fetch (no ci_fallback) RUN_ID=$(RUN_ID)"; \
		AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.fetch_bundle_from_govai $(RUN_ID); \
	else \
		AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.fetch_bundle_from_govai $(RUN_ID) || \
		AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.ci_fallback $(RUN_ID); \
	fi

# ================================
# Report flow
# ================================

report_template: require_run ensure_reports_dir
	@echo "run_id=$(RUN_ID)" > docs/reports/$(RUN_ID).md
	@echo "bundle_sha256=" >> docs/reports/$(RUN_ID).md
	@echo "policy_version=" >> docs/reports/$(RUN_ID).md
	@echo "" >> docs/reports/$(RUN_ID).md
	@echo "# Audit report for run \`$(RUN_ID)\`" >> docs/reports/$(RUN_ID).md
	@echo "" >> docs/reports/$(RUN_ID).md
	@echo "saved docs/reports/$(RUN_ID).md"

report_init: require_run ensure_reports_dir
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.report_init $(RUN_ID)

report_fill: require_run ensure_reports_dir
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.report_fill $(RUN_ID)

bundle: require_run ensure_dirs
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.export_bundle $(RUN_ID)

verify_cli: require_run
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.verify $(RUN_ID)

evidence_pack: require_run ensure_dirs
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) RUN_ID=$(RUN_ID) python -m aigov_py.evidence_pack

audit_close: require_run
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.audit_close $(RUN_ID)

report_prepare: require_run
	@echo "Preparing report for RUN_ID=$(RUN_ID) (AIGOV_MODE=$(AIGOV_MODE))"
	$(MAKE) ensure_evidence RUN_ID=$(RUN_ID)
	cd python && . .venv/bin/activate && \
		RUN_ID=$(RUN_ID) AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.report
	$(MAKE) export_bundle RUN_ID=$(RUN_ID)
	$(MAKE) verify_cli RUN_ID=$(RUN_ID)

report_prepare_new:
	@set -euo pipefail; \
	RUN_ID="$$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"; \
	echo "$$RUN_ID"; \
	$(MAKE) report_prepare RUN_ID="$$RUN_ID"

# ================================
# Supabase ingest
# ================================

db_ingest: require_run
	cd python && . .venv/bin/activate && \
	AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.ingest_run $(RUN_ID)

# ================================
# Demo
# ================================
# demo: end to end run that generates artifacts and ingests a row to Supabase
# demo_new: same but generates RUN_ID automatically and prints it for dashboard usage

demo: require_run require_audit_url
	@set -euo pipefail; \
	echo "DEMO: RUN_ID=$(RUN_ID) AIGOV_MODE=$(AIGOV_MODE)"; \
	$(MAKE) run RUN_ID="$(RUN_ID)"; \
	$(MAKE) approve RUN_ID="$(RUN_ID)"; \
	$(MAKE) promote RUN_ID="$(RUN_ID)"; \
	$(MAKE) report_prepare RUN_ID="$(RUN_ID)"; \
	$(MAKE) db_ingest RUN_ID="$(RUN_ID)"; \
	echo "OK: demo completed RUN_ID=$(RUN_ID)"; \
	echo "Dashboard: /runs/$(RUN_ID)"

demo_new: require_audit_url
	@set -euo pipefail; \
	RUN_ID="$$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"; \
	echo "DEMO: generated RUN_ID=$$RUN_ID AIGOV_MODE=$(AIGOV_MODE)"; \
	$(MAKE) run RUN_ID="$$RUN_ID"; \
	$(MAKE) approve RUN_ID="$$RUN_ID"; \
	$(MAKE) promote RUN_ID="$$RUN_ID"; \
	$(MAKE) report_prepare RUN_ID="$$RUN_ID"; \
	$(MAKE) db_ingest RUN_ID="$$RUN_ID"; \
	echo "OK: demo completed RUN_ID=$$RUN_ID"; \
	echo "Dashboard: /runs/$$RUN_ID"

# Train → approve → promote → report_prepare (evidence + report + bundle + verify_cli) → compliance summary (HTTP)
flow_full: require_run require_audit_url
	@set -euo pipefail; \
	echo "flow_full: RUN_ID=$(RUN_ID) AIGOV_MODE=$(AIGOV_MODE)"; \
	$(MAKE) run RUN_ID="$(RUN_ID)"; \
	$(MAKE) approve RUN_ID="$(RUN_ID)"; \
	$(MAKE) promote RUN_ID="$(RUN_ID)"; \
	$(MAKE) report_prepare RUN_ID="$(RUN_ID)"; \
	cd python && . .venv/bin/activate && \
		GOVAI_AUDIT_BASE_URL=$${GOVAI_AUDIT_BASE_URL} GOVAI_API_KEY=$${GOVAI_API_KEY:-ci-test-api-key} GOVAI_PROJECT=$${GOVAI_PROJECT:-github-actions} RUN_ID="$(RUN_ID)" AIGOV_MODE="$(AIGOV_MODE)" python -m aigov_py.ai_discovery_completed; \
	echo "GET $(GOVAI_AUDIT_BASE_URL)/compliance-summary?run_id=$(RUN_ID)"; \
	curl -fsS "$(GOVAI_AUDIT_BASE_URL)/compliance-summary?run_id=$(RUN_ID)" \
		-H "Authorization: Bearer $${GOVAI_API_KEY:-ci-test-api-key}"; echo

flow: flow_full

# Thin wrappers around Python scripts (core flow glue)
approve: require_run require_audit_url
	cd python && . .venv/bin/activate && \
		GOVAI_AUDIT_BASE_URL=$${GOVAI_AUDIT_BASE_URL} GOVAI_API_KEY=$${GOVAI_API_KEY:-ci-test-api-key} GOVAI_PROJECT=$${GOVAI_PROJECT:-github-actions} RUN_ID=$(RUN_ID) AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.approve

promote: require_run require_audit_url
	cd python && . .venv/bin/activate && \
		GOVAI_AUDIT_BASE_URL=$${GOVAI_AUDIT_BASE_URL} GOVAI_API_KEY=$${GOVAI_API_KEY:-ci-test-api-key} GOVAI_PROJECT=$${GOVAI_PROJECT:-github-actions} RUN_ID=$(RUN_ID) AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.promote

export_bundle: require_run ensure_dirs
	cd python && . .venv/bin/activate && \
		AIGOV_MODE=$(AIGOV_MODE) python -m aigov_py.export_bundle $(RUN_ID)

# ================================
# PR helpers
# ================================

pr_report:
	@set -euo pipefail; \
	RUN_ID="$$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"; \
	echo "Generated RUN_ID=$$RUN_ID"; \
	$(MAKE) report_prepare RUN_ID="$$RUN_ID"

pr_report_commit: FORCE
	@set -euo pipefail; \
	BRANCH="$$(git rev-parse --abbrev-ref HEAD)"; \
	if [ "$$BRANCH" = "main" ]; then \
		echo "ERROR: do not run on main branch"; \
		exit 2; \
	fi; \
	if ! git diff --quiet || ! git diff --cached --quiet; then \
		echo "ERROR: working tree not clean. Commit or stash first."; \
		exit 2; \
	fi; \
	RUN_ID="$$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"; \
	echo "Generated RUN_ID=$$RUN_ID"; \
	$(MAKE) report_prepare RUN_ID="$$RUN_ID"; \
	git add "docs/reports/$$RUN_ID.md"; \
	if git diff --cached --quiet; then \
		echo "ERROR: nothing staged (report not generated?)"; \
		exit 2; \
	fi; \
	git commit -m "docs: add audit report ($$RUN_ID)"; \
	git push

