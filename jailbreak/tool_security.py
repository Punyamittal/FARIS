"""
Tool-Call Security Layer.

Validates agent tool calls independently of any LLM recommendation.
Never connects to real payment-platform APIs — mock tools only.
"""

from typing import Dict, Any, Optional, Callable, List
from security_types import (
    ToolCallRequest, Capability, ExecutionDecision, FARISDecision,
    AttackClass
)
from agent_security import AgentSecurityManager, PRIVILEGED_CAPABILITIES
from financial_context import (
    get_transaction, get_merchant, financial_sensitivity, context_to_dict
)


TOOL_CAPABILITY_MAP: Dict[str, Capability] = {
    "get_transaction": Capability.READ_TRANSACTION,
    "get_merchant": Capability.READ_MERCHANT,
    "analyze_document": Capability.READ_DOCUMENT,
    "query_risk": Capability.QUERY_RISK_DATABASE,
    "create_case": Capability.WRITE_CASE,
    "update_risk": Capability.MODIFY_RISK_STATUS,
    "approve_action": Capability.APPROVE_ACTION,
    "execute_financial_action": Capability.EXECUTE_FINANCIAL_ACTION,
    "export_data": Capability.EXPORT_DATA,
    "send_notification": Capability.SEND_NOTIFICATION,
}


class MockFinancialTools:
    """Simulated payment-platform tools (synthetic data only)."""

    def get_transaction(self, transaction_id: str) -> Dict[str, Any]:
        txn = get_transaction(transaction_id)
        if not txn:
            return {"error": "transaction_not_found", "transaction_id": transaction_id}
        return {"ok": True, "transaction": context_to_dict(txn)}

    def get_merchant(self, merchant_id: str) -> Dict[str, Any]:
        m = get_merchant(merchant_id)
        if not m:
            return {"error": "merchant_not_found", "merchant_id": merchant_id}
        return {"ok": True, "merchant": context_to_dict(m)}

    def analyze_document(self, document_id: str, text: Optional[str] = None) -> Dict[str, Any]:
        return {
            "ok": True,
            "document_id": document_id,
            "summary_as_data": (text or "")[:500],
            "note": "Content treated as DATA, not INSTRUCTION",
        }

    def query_risk(self, entity_id: str) -> Dict[str, Any]:
        return {"ok": True, "entity_id": entity_id, "synthetic_risk": 0.28}

    def create_case(self, title: str, details: str = "") -> Dict[str, Any]:
        return {"ok": True, "case_id": f"CASE-{abs(hash(title)) % 100000}", "title": title}

    def update_risk(self, entity_id: str, new_status: str) -> Dict[str, Any]:
        return {"ok": True, "entity_id": entity_id, "new_status": new_status, "mock": True}

    def approve_action(self, action_id: str) -> Dict[str, Any]:
        return {"ok": True, "action_id": action_id, "approved": True, "mock": True}

    def execute_financial_action(self, action: str, amount: float = 0.0) -> Dict[str, Any]:
        return {"ok": True, "action": action, "amount": amount, "mock": True}

    def export_data(self, scope: str) -> Dict[str, Any]:
        return {"ok": True, "scope": scope, "rows": 0, "mock": True}

    def send_notification(self, channel: str, message: str) -> Dict[str, Any]:
        return {"ok": True, "channel": channel, "message": message[:200], "mock": True}


class ToolSecurityGateway:
    """
    Pre-execution authorization for tool calls:

    Tool Request -> Capability Gate -> Risk Engine -> Policy Engine -> ALLOW/DENY/HUMAN_REVIEW
    """

    def __init__(
        self,
        agent_manager: AgentSecurityManager,
        risk_evaluator: Optional[Callable[..., float]] = None,
        policy_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.agent_manager = agent_manager
        self.tools = MockFinancialTools()
        self.risk_evaluator = risk_evaluator
        self.thresholds = policy_thresholds or {
            "deny": 0.85,
            "human_review": 0.60,
            "allow": 0.30,
        }
        self.call_log: List[Dict[str, Any]] = []

    def _finish(self, request: ToolCallRequest, decision: FARISDecision) -> FARISDecision:
        self.call_log.append({
            "tool": request.tool_name,
            "agent_id": request.agent_id,
            "decision": decision.decision,
            "args": request.arguments,
            "requested_capability": decision.requested_capability,
            "reason": decision.reason,
        })
        return decision

    def evaluate_tool_call(
        self,
        request: ToolCallRequest,
        risk_score: Optional[float] = None,
        attack_classes: Optional[List[str]] = None,
        untrusted_influence: bool = False,
    ) -> FARISDecision:
        agent = self.agent_manager.get_agent(request.agent_id)
        required = TOOL_CAPABILITY_MAP.get(
            request.tool_name, request.required_capability
        )

        if agent is None:
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=1.0,
                risk_state="critical",
                attack_classes=attack_classes or [AttackClass.TOOL_MANIPULATION.value],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason="Unknown agent - tool call denied",
            ))

        if agent.isolated:
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=agent.current_risk_score,
                risk_state=agent.risk_state.value,
                attack_classes=attack_classes or [],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason="Agent in emergency isolation",
            ))

        score = risk_score if risk_score is not None else agent.current_risk_score
        if self.risk_evaluator:
            score = max(score, self.risk_evaluator(request, agent))

        if untrusted_influence and required in PRIVILEGED_CAPABILITIES:
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=max(score, 0.87),
                risk_state="high",
                attack_classes=attack_classes or [
                    AttackClass.INDIRECT_INJECTION.value,
                    AttackClass.AUTHORITY_ESCALATION.value,
                ],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason=(
                    "Untrusted external content attempted to influence a privileged "
                    "financial decision."
                ),
                explanation={
                    "what_happened": f"Tool {request.tool_name} requested under untrusted influence",
                    "why_risky": [
                        "EXTERNAL_UNTRUSTED provenance present",
                        "Privileged capability requested",
                        "DATA!=INSTRUCTION boundary enforced",
                    ],
                    "policy_triggered": ["deny_untrusted_privileged_influence"],
                    "action_taken": "DENY",
                },
            ))

        if required not in agent.current_permissions:
            if required in agent.allowed_capabilities and required in PRIVILEGED_CAPABILITIES:
                return self._finish(request, FARISDecision(
                    decision=ExecutionDecision.REQUIRE_HUMAN_REVIEW.value.upper(),
                    risk_score=max(agent.current_risk_score, score),
                    risk_state=agent.risk_state.value,
                    attack_classes=attack_classes or [],
                    requested_capability=required.value,
                    capability_granted=False,
                    requires_human_review=True,
                    reason=(
                        "Privileged capability suspended by risk-adaptive policy - "
                        "human review required"
                    ),
                ))
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=agent.current_risk_score,
                risk_state=agent.risk_state.value,
                attack_classes=attack_classes or [AttackClass.CAPABILITY_ESCALATION.value],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=required in PRIVILEGED_CAPABILITIES,
                reason=f"Capability {required.value} not in current permissions",
            ))

        if request.tool_name not in agent.tool_permissions:
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=agent.current_risk_score,
                risk_state=agent.risk_state.value,
                attack_classes=attack_classes or [AttackClass.TOOL_MANIPULATION.value],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason=f"Tool {request.tool_name} not permitted for role {agent.role.value}",
            ))

        if score >= self.thresholds["deny"] and required in PRIVILEGED_CAPABILITIES:
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.DENY.value.upper(),
                risk_score=score,
                risk_state=agent.risk_state.value,
                attack_classes=attack_classes or [],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason="Risk exceeded autonomous privileged tool threshold",
            ))

        if score >= self.thresholds["human_review"] or (
            required in PRIVILEGED_CAPABILITIES and score >= self.thresholds["allow"]
        ):
            return self._finish(request, FARISDecision(
                decision=ExecutionDecision.REQUIRE_HUMAN_REVIEW.value.upper(),
                risk_score=score,
                risk_state=agent.risk_state.value,
                attack_classes=attack_classes or [],
                requested_capability=required.value,
                capability_granted=False,
                requires_human_review=True,
                reason="Privileged or high-risk tool call requires human review",
            ))

        return self._finish(request, FARISDecision(
            decision=ExecutionDecision.ALLOW.value.upper(),
            risk_score=score,
            risk_state=agent.risk_state.value,
            attack_classes=attack_classes or [],
            requested_capability=required.value,
            capability_granted=True,
            requires_human_review=False,
            reason="Tool call authorized by capability gate and risk policy",
            allowed_capabilities=[c.value for c in agent.current_permissions],
        ))

    def execute_if_allowed(
        self,
        request: ToolCallRequest,
        decision: FARISDecision,
    ) -> Dict[str, Any]:
        if decision.decision != ExecutionDecision.ALLOW.value.upper():
            return {"executed": False, "decision": decision.to_dict()}

        fn = getattr(self.tools, request.tool_name, None)
        if not fn:
            return {"executed": False, "error": "unknown_tool"}
        result = fn(**request.arguments)
        return {"executed": True, "result": result, "decision": decision.to_dict()}
