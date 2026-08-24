"""
Policy Decision Engine for FARIS.

Maps risk state, attacks, capabilities, and trajectory signals to ALLOW / DENY /
REQUIRE_HUMAN_REVIEW decisions. Deterministic and LLM-independent.
"""

from typing import Dict, Any, Optional, List, Set
from security_types import (
    ExecutionDecision, RiskState, AttackClass, Capability,
    DecisionExplanation, risk_score_to_state
)
from agent_security import PRIVILEGED_CAPABILITIES


DEFAULT_POLICY: Dict[str, Any] = {
    "version": "faris-1.0.0",
    "risk_thresholds": {
        "low": 0.30,
        "medium": 0.60,
        "high": 0.80,
        "critical": 0.90,
        "guarded": 0.30,
        "elevated": 0.50,
    },
    "block_on_attack_classes": [
        AttackClass.AUTHORITY_ESCALATION.value,
        AttackClass.CAPABILITY_ESCALATION.value,
        AttackClass.JAILBREAK.value,
        AttackClass.TOOL_MANIPULATION.value,
        AttackClass.POLICY_MANIPULATION.value,
        AttackClass.DATA_EXFILTRATION.value,
    ],
    "human_review_on_attack_classes": [
        AttackClass.INDIRECT_INJECTION.value,
        AttackClass.MALICIOUS_DOCUMENT.value,
        AttackClass.MALICIOUS_WEBPAGE.value,
        AttackClass.MULTI_TURN_ESCALATION.value,
        AttackClass.PROMPT_INJECTION.value,
    ],
    "deny_untrusted_privileged_influence": True,
    "trajectory_escalation_forces_review": True,
}


class PolicyEngine:
    """Policy-based decision maker for prompts and tool calls."""

    def __init__(self, policy_config: Optional[Dict[str, Any]] = None):
        self.policy = {**DEFAULT_POLICY, **(policy_config or {})}
        if policy_config and "risk_thresholds" in policy_config:
            self.policy["risk_thresholds"] = {
                **DEFAULT_POLICY["risk_thresholds"],
                **policy_config["risk_thresholds"],
            }

    @property
    def version(self) -> str:
        return self.policy.get("version", "faris-1.0.0")

    def decide(
        self,
        risk_score: float,
        attack_classes: List[AttackClass],
        requested_capabilities: Set[Capability],
        allowed_capabilities: Set[Capability],
        untrusted_influence: bool = False,
        trajectory_escalate: bool = False,
        agent_isolated: bool = False,
    ) -> Dict[str, Any]:
        """
        Return decision dict with explanation fields.
        """
        attack_values = [
            ac.value if isinstance(ac, AttackClass) else str(ac)
            for ac in attack_classes
            if (ac.value if isinstance(ac, AttackClass) else str(ac)) != AttackClass.NONE.value
        ]
        state = risk_score_to_state(risk_score, self.policy["risk_thresholds"])
        policies_triggered: List[str] = []
        why_risky: List[str] = []

        if agent_isolated:
            policies_triggered.append("emergency_isolation")
            why_risky.append("Agent is in emergency isolation")
            return self._result(
                ExecutionDecision.DENY,
                risk_score, state, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "Emergency isolation active — all sensitive actions denied",
                human_review=True,
            )

        # Hard blocks
        for ac in attack_values:
            if ac in self.policy.get("block_on_attack_classes", []):
                policies_triggered.append(f"block_on_{ac}")
                why_risky.append(f"Blocked attack class: {ac}")

        # Capability self-grant attempts
        if AttackClass.CAPABILITY_ESCALATION.value in attack_values:
            policies_triggered.append("prompts_cannot_grant_capabilities")
            why_risky.append("Prompt attempted to grant or escalate capabilities")

        if untrusted_influence:
            privileged_requested = requested_capabilities & PRIVILEGED_CAPABILITIES
            if privileged_requested and self.policy.get("deny_untrusted_privileged_influence", True):
                policies_triggered.append("deny_untrusted_privileged_influence")
                why_risky.append(
                    "External untrusted content attempted to influence a privileged financial decision"
                )
                return self._result(
                    ExecutionDecision.DENY,
                    max(risk_score, 0.87), RiskState.HIGH, attack_values,
                    requested_capabilities, why_risky, policies_triggered,
                    "Untrusted external content attempted to influence a privileged financial decision.",
                    human_review=True,
                )
            if AttackClass.INDIRECT_INJECTION.value in attack_values or \
               AttackClass.MALICIOUS_DOCUMENT.value in attack_values or \
               AttackClass.MALICIOUS_WEBPAGE.value in attack_values:
                policies_triggered.append("untrusted_instruction_as_data_only")
                why_risky.append("Untrusted content contains instruction-like language (DATA≠INSTRUCTION)")

        if why_risky and any(p.startswith("block_on_") for p in policies_triggered):
            return self._result(
                ExecutionDecision.BLOCK,
                risk_score, state, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "; ".join(why_risky),
                human_review=risk_score >= 0.6,
            )

        thresholds = self.policy["risk_thresholds"]

        if trajectory_escalate and self.policy.get("trajectory_escalation_forces_review", True):
            policies_triggered.append("trajectory_escalation")
            why_risky.append("Risk trajectory indicates escalation across turns")
            return self._result(
                ExecutionDecision.REQUIRE_HUMAN_REVIEW,
                risk_score, state, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "Trajectory-based escalation requires human review",
                human_review=True,
            )

        # Risk bands
        if risk_score >= thresholds["critical"]:
            policies_triggered.append("critical_risk_isolation")
            why_risky.append("Risk exceeded critical threshold")
            return self._result(
                ExecutionDecision.DENY,
                risk_score, RiskState.CRITICAL, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "Critical risk — emergency deny / isolation",
                human_review=True,
            )

        if risk_score >= thresholds["high"]:
            policies_triggered.append("high_risk_human_review")
            why_risky.append("Risk exceeded autonomous execution threshold")
            # Indirect injection without privileged action may be ALLOW for summarize-as-data
            if untrusted_influence and not (requested_capabilities & PRIVILEGED_CAPABILITIES):
                policies_triggered.append("allow_summarize_as_data")
                return self._result(
                    ExecutionDecision.ALLOW_DEGRADED,
                    risk_score, state, attack_values, requested_capabilities,
                    why_risky, policies_triggered,
                    "Untrusted content may be summarized as DATA only; privileged actions denied",
                    human_review=True,
                    allowed=allowed_capabilities - PRIVILEGED_CAPABILITIES,
                )
            return self._result(
                ExecutionDecision.REQUIRE_HUMAN_REVIEW,
                risk_score, state, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "High risk — human review required before execution",
                human_review=True,
            )

        if risk_score >= thresholds["medium"]:
            policies_triggered.append("medium_risk_degraded")
            why_risky.append("Elevated risk — write/financial capabilities restricted")
            degraded = allowed_capabilities - PRIVILEGED_CAPABILITIES - {
                Capability.WRITE_CASE, Capability.WRITE_MEMORY, Capability.EXECUTE_TOOLS
            }
            return self._result(
                ExecutionDecision.ALLOW_DEGRADED,
                risk_score, state, attack_values, requested_capabilities,
                why_risky, policies_triggered,
                "Medium risk — degraded capabilities",
                human_review=bool(requested_capabilities & PRIVILEGED_CAPABILITIES),
                allowed=degraded,
            )

        if risk_score >= thresholds["low"]:
            if requested_capabilities & PRIVILEGED_CAPABILITIES:
                policies_triggered.append("sensitive_ops_confirmation")
                why_risky.append("Sensitive capability requested")
                return self._result(
                    ExecutionDecision.REQUIRE_CONFIRMATION,
                    risk_score, state, attack_values, requested_capabilities,
                    why_risky, policies_triggered,
                    "Sensitive operation requires confirmation",
                    human_review=False,
                    allowed=allowed_capabilities - PRIVILEGED_CAPABILITIES,
                )

        # Check human-review attack classes at any score if privileged
        for ac in attack_values:
            if ac in self.policy.get("human_review_on_attack_classes", []):
                if requested_capabilities & PRIVILEGED_CAPABILITIES:
                    policies_triggered.append(f"review_on_{ac}")
                    why_risky.append(f"Attack class {ac} with privileged request")
                    return self._result(
                        ExecutionDecision.REQUIRE_HUMAN_REVIEW,
                        risk_score, state, attack_values, requested_capabilities,
                        why_risky, policies_triggered,
                        "Attack signal with privileged capability requires human review",
                        human_review=True,
                    )

        policies_triggered.append("default_allow")
        return self._result(
            ExecutionDecision.ALLOW,
            risk_score, state, attack_values, requested_capabilities,
            why_risky or ["No significant attack patterns; risk within normal band"],
            policies_triggered,
            "Request permitted under current policy",
            human_review=False,
            allowed=allowed_capabilities,
        )

    def _result(
        self,
        decision: ExecutionDecision,
        risk_score: float,
        state: RiskState,
        attack_values: List[str],
        requested: Set[Capability],
        why_risky: List[str],
        policies: List[str],
        reason: str,
        human_review: bool,
        allowed: Optional[Set[Capability]] = None,
    ) -> Dict[str, Any]:
        req_cap = next(iter(requested)).value if requested else None
        explanation = DecisionExplanation(
            what_happened=reason,
            why_risky=why_risky,
            requested_capability=req_cap,
            policy_triggered=policies,
            action_taken=decision.value.upper(),
            risk_score=risk_score,
            risk_state=state.value if isinstance(state, RiskState) else str(state),
        )
        return {
            "decision": decision,
            "risk_score": risk_score,
            "risk_state": state if isinstance(state, RiskState) else risk_score_to_state(risk_score),
            "attack_classes": attack_values,
            "reason": reason,
            "requires_human_review": human_review,
            "explanation": explanation,
            "allowed_capabilities": allowed if allowed is not None else set(),
            "policy_version": self.version,
        }
