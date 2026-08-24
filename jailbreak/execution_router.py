"""
Execution Router Module.

Makes final execution decisions based on policy, risk score, and capabilities.
"""

from typing import Optional, Dict, Set, List
from security_types import (
    ExecutionContext, ExecutionResult, ExecutionDecision, RiskScore,
    AttackClass, Capability
)


class ExecutionRouter:
    """
    Routes execution based on policy, risk assessment, and capabilities.
    
    Decision logic:
    - ALLOW: Low risk, valid capabilities
    - ALLOW_DEGRADED: Medium risk, reduced capabilities
    - REQUIRE_CONFIRMATION: High risk or sensitive operations
    - BLOCK: Critical risk or policy violation
    """
    
    def __init__(self, policy_config: Optional[Dict] = None):
        """
        Initialize router with policy configuration.
        
        Args:
            policy_config: Policy rules dict with thresholds and rules
        """
        self.policy = policy_config or self._default_policy()
    
    def _default_policy(self) -> Dict:
        """Default policy configuration."""
        return {
            "risk_thresholds": {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8
            },
            "block_on_authority_escalation": True,
            "block_on_capability_escalation": True,
            "require_confirmation_for": [
                Capability.WRITE_MEMORY,
                Capability.SEND_DATA,
                Capability.PERSIST_STATE
            ],
            "block_on_attack_classes": [
                AttackClass.AUTHORITY_ESCALATION,
                AttackClass.CAPABILITY_ESCALATION
            ],
            "degraded_capabilities_on_medium_risk": [
                Capability.WRITE_MEMORY,
                Capability.SEND_DATA
            ]
        }
    
    def route(
        self,
        context: ExecutionContext
    ) -> ExecutionResult:
        """
        Make execution routing decision.
        
        Args:
            context: Complete execution context
            
        Returns:
            ExecutionResult with decision and metadata
        """
        risk_score = context.risk_score
        policy = self.policy
        
        # Check for immediate blocks
        block_reason = self._check_block_conditions(context)
        if block_reason:
            return ExecutionResult(
                decision=ExecutionDecision.BLOCK,
                context=context,
                allowed_capabilities=set(),
                block_reason=block_reason
            )
        
        # Check for capability escalation attempts
        # (This check should be done in pipeline before routing, but included here for defense-in-depth)
        if policy.get("block_on_capability_escalation", True):
            # Simple heuristic check - full check done in pipeline
            text_lower = context.prompt.full_text.lower()
            escalation_keywords = ['grant', 'give', 'enable', 'unrestricted', 'full access']
            if any(kw in text_lower for kw in escalation_keywords):
                # This is a simplified check - full analysis done in capability_gating module
                pass  # Will be caught by capability_gate in pipeline
        
        # Check risk score thresholds
        risk = risk_score.score
        thresholds = policy["risk_thresholds"]
        
        if risk >= thresholds["high"]:
            # High risk - block or require confirmation
            if self._has_critical_attack_class(context.risk_score):
                return ExecutionResult(
                    decision=ExecutionDecision.BLOCK,
                    context=context,
                    allowed_capabilities=set(),
                    block_reason=f"High risk ({risk:.2f}) with critical attack classes"
                )
            else:
                # High risk but not critical - require confirmation
                return ExecutionResult(
                    decision=ExecutionDecision.REQUIRE_CONFIRMATION,
                    context=context,
                    allowed_capabilities=set(),  # No capabilities until confirmed
                    requires_user_confirmation=True,
                    confirmation_message=self._generate_confirmation_message(context)
                )
        
        elif risk >= thresholds["medium"]:
            # Medium risk - allow with degraded capabilities
            allowed_capabilities = self._apply_degraded_capabilities(
                context.granted_capabilities,
                policy.get("degraded_capabilities_on_medium_risk", [])
            )
            
            # Check if sensitive capabilities are requested
            sensitive_requested = context.requested_capabilities & set(
                policy.get("require_confirmation_for", [])
            )
            
            if sensitive_requested:
                return ExecutionResult(
                    decision=ExecutionDecision.REQUIRE_CONFIRMATION,
                    context=context,
                    allowed_capabilities=allowed_capabilities - sensitive_requested,
                    requires_user_confirmation=True,
                    confirmation_message=self._generate_confirmation_message(context)
                )
            
            return ExecutionResult(
                decision=ExecutionDecision.ALLOW_DEGRADED,
                context=context,
                allowed_capabilities=allowed_capabilities
            )
        
        elif risk >= thresholds["low"]:
            # Low-medium risk - check for sensitive operations
            sensitive_requested = context.requested_capabilities & set(
                policy.get("require_confirmation_for", [])
            )
            
            if sensitive_requested:
                return ExecutionResult(
                    decision=ExecutionDecision.REQUIRE_CONFIRMATION,
                    context=context,
                    allowed_capabilities=context.granted_capabilities - sensitive_requested,
                    requires_user_confirmation=True,
                    confirmation_message=self._generate_confirmation_message(context)
                )
            
            # Allow with full granted capabilities
            return ExecutionResult(
                decision=ExecutionDecision.ALLOW,
                context=context,
                allowed_capabilities=context.granted_capabilities
            )
        
        else:
            # Low risk - allow with full capabilities
            return ExecutionResult(
                decision=ExecutionDecision.ALLOW,
                context=context,
                allowed_capabilities=context.granted_capabilities
            )
    
    def _check_block_conditions(self, context: ExecutionContext) -> Optional[str]:
        """Check if execution should be blocked immediately."""
        policy = self.policy
        risk_score = context.risk_score
        
        # Block on authority escalation
        if policy.get("block_on_authority_escalation", True):
            if AttackClass.AUTHORITY_ESCALATION in risk_score.attack_classes:
                return "Authority escalation attempt detected"
        
        # Block on specific attack classes
        block_classes = policy.get("block_on_attack_classes", [])
        for attack_class in block_classes:
            if attack_class in risk_score.attack_classes:
                return f"Blocked due to {attack_class.value} attack class"
        
        return None
    
    def _has_critical_attack_class(self, risk_score: RiskScore) -> bool:
        """Check if risk score includes critical attack classes."""
        critical_classes = [
            AttackClass.AUTHORITY_ESCALATION,
            AttackClass.CAPABILITY_ESCALATION,
            AttackClass.MEMORY_POISONING
        ]
        return any(ac in risk_score.attack_classes for ac in critical_classes)
    
    def _apply_degraded_capabilities(
        self,
        granted_capabilities: Set[Capability],
        degraded_list: List[Capability]
    ) -> Set[Capability]:
        """Remove degraded capabilities from granted set."""
        return granted_capabilities - set(degraded_list)
    
    def _generate_confirmation_message(self, context: ExecutionContext) -> str:
        """Generate user-friendly confirmation message."""
        risk_score = context.risk_score
        attack_classes = [ac.value for ac in risk_score.attack_classes if ac != AttackClass.NONE]
        
        parts = [
            f"Risk level: {risk_score.score:.1%}",
        ]
        
        if attack_classes:
            parts.append(f"Detected: {', '.join(attack_classes)}")
        
        if context.requested_capabilities:
            caps = [c.value for c in context.requested_capabilities]
            parts.append(f"Requested capabilities: {', '.join(caps)}")
        
        return " | ".join(parts)
    
    def update_policy(self, new_policy: Dict):
        """Update policy configuration."""
        self.policy.update(new_policy)

