"""Example customer application: Acme Finance's accounts-payable assistant.

This file is what a customer would write. It defines the customer's tools and their policy classification, a performer
that performs the real side effects (here, a synthetic in-memory ledger), and the application's flow for paying a
vendor. It does not contain security logic. Core decides, humans approve under their own credentials, and the executor
verifies before it acts.

Everything is synthetic.
"""

from __future__ import annotations

from typing import Any

from aigov_integration import Integration, IntegrationConfig, Tool

CONFIG = IntegrationConfig(
    tenant="acme-finance",
    policy_id="acme-finance-ap-policy",
    tools=(
        Tool("read_invoice", "invoice:read", "read", resource_key="invoice_id"),
        Tool("pay_vendor", "payment:create", "write", resource_key="vendor_id"),
        Tool("adjust_budget", "budget:adjust", "write", resource_key="cost_center"),
    ),
    approvers={
        "controller": "controller@acme-finance.example",
        "cfo": "cfo@acme-finance.example",
    },
    agent_identity="agent:ap-assistant",
    executor_identity="executor:ledger-service",
    approval_max_age_seconds=30,
    auth_ttl_seconds=60,
)


class AcmeLedger:
    """The synthetic ledger the executor writes to. A real customer calls its ERP or bank API here instead."""

    def __init__(self) -> None:
        self.invoices = {
            "INV-2001": {"vendor_id": "VEND-7", "amount": 1200.0, "status": "open"},
            "INV-2002": {"vendor_id": "VEND-9", "amount": 310.5, "status": "open"},
        }
        self.payments: list[dict[str, Any]] = []
        self.budgets = {"CC-100": 50000.0}

    def perform(
        self, tool: str, args: dict[str, Any], execution_id: str
    ) -> dict[str, Any]:
        if tool == "read_invoice":
            inv = self.invoices.get(args.get("invoice_id", ""))
            if inv is None:
                return {
                    "success": False,
                    "data": None,
                    "blocked_reason": "unknown_invoice",
                }
            return {"success": True, "data": {"invoice_id": args["invoice_id"], **inv}}
        if tool == "pay_vendor":
            inv = self.invoices.get(args.get("invoice_id", ""))
            if inv is None or inv["status"] != "open":
                return {
                    "success": False,
                    "data": None,
                    "blocked_reason": "invoice_not_payable",
                }
            inv["status"] = "paid"
            payment = {
                "invoice_id": args["invoice_id"],
                "vendor_id": args["vendor_id"],
                "amount": inv["amount"],
                "execution_id": execution_id,
            }
            self.payments.append(payment)
            return {"success": True, "data": payment}
        if tool == "adjust_budget":
            cc = args.get("cost_center", "")
            if cc not in self.budgets:
                return {
                    "success": False,
                    "data": None,
                    "blocked_reason": "unknown_cost_center",
                }
            self.budgets[cc] += float(args.get("delta", 0))
            return {
                "success": True,
                "data": {"cost_center": cc, "balance": self.budgets[cc]},
            }
        return {"success": False, "data": None, "blocked_reason": "unsupported_tool"}


class AcmeAssistant:
    """The application's payment flow. Each consequential step goes through the integration."""

    def __init__(self, integration: Integration, ledger: AcmeLedger) -> None:
        self.integration = integration
        self.ledger = ledger

    def read_invoice(self, invoice_id: str, call_id: str) -> dict[str, Any]:
        """A governed read: authorized by Core and receipted by the executor, with no approval needed."""
        i = self.integration
        args = {"invoice_id": invoice_id}
        decision = i.call("read_invoice", args, call_id)
        outcome = i.execute("read_invoice", args, decision)
        return {
            "status": "read" if outcome.executed else "not_executed",
            "reason": outcome.reason,
        }

    def pay_vendor(self, invoice_id: str, call_id: str) -> dict[str, Any]:
        """Pay an open invoice, with controller approval. Returns each stage separately."""
        i = self.integration
        args = {
            "invoice_id": invoice_id,
            "vendor_id": self.ledger.invoices[invoice_id]["vendor_id"],
        }
        request = i.request_approval("pay_vendor", args, call_id)
        approval = i.approve("controller", request, "pay_vendor", args, call_id)
        if approval.decision.value != "ALLOW":
            return {
                "stage": "approval",
                "status": "not_approved",
                "reason": approval.reason,
            }
        decision = i.call("pay_vendor", args, call_id, approval.event_id or "")
        if decision.authorization is None:
            return {
                "stage": "authorization",
                "status": "not_authorized",
                "reason": decision.reason,
            }
        outcome = i.execute("pay_vendor", args, decision)
        return {
            "stage": "execution",
            "status": "paid" if outcome.executed else "not_executed",
            "reason": outcome.reason,
            "authorization_id": outcome.authorization_id,
        }
