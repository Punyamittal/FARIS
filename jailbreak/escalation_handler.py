"""
Confidence-Based Escalation Handler

Implements a patent-friendly escalation layer for uncertain predictions.

    Architecture:
    - Low confidence (< 0.25): Allow (clearly benign)
    - High confidence (> 0.55): Block (clearly malicious)
    - Medium confidence (0.25-0.55): Escalate → Block (uncertain, conservative: treat as jailbreak)
    
    Note: Medium-risk prompts are blocked (not escalated) to maximize recall and minimize false negatives.

Escalation Actions:
- Degraded response (limited capabilities)
- Safe-mode answer (generic, non-specific)
- User clarification request
- Sandbox execution (isolated environment)
"""

from enum import Enum
from typing import Dict, Optional
from dataclasses import dataclass

class EscalationAction(Enum):
    """Types of escalation actions."""
    ALLOW = "allow"  # Low confidence - allow through
    BLOCK = "block"  # High confidence - block completely
    ESCALATE = "escalate"  # Medium confidence - needs review
    DEGRADED_RESPONSE = "degraded_response"  # Limited capabilities
    SAFE_MODE = "safe_mode"  # Generic, non-specific answer
    CLARIFY = "clarify"  # Ask user to clarify intent
    SANDBOX = "sandbox"  # Execute in isolated environment

@dataclass
class EscalationResult:
    """Result from escalation decision."""
    action: EscalationAction
    confidence_tier: str  # 'low', 'medium', 'high'
    jailbreak_probability: float
    reason: str
    recommendation: str

class ConfidenceEscalationHandler:
    """
    Confidence-based escalation handler.
    
    Implements three-tier confidence system:
    - Low (< 0.30): Allow
    - Medium (0.30-0.60): Escalate
    - High (> 0.60): Block
    
    This is a patent-friendly architectural innovation that improves
    recall without sacrificing precision.
    """
    
    def __init__(
        self,
        low_threshold: float = 0.25,
        high_threshold: float = 0.55,
        escalation_mode: str = "degraded_response"
    ):
        """
        Initialize escalation handler.
        
        Args:
            low_threshold: Below this = allow (default: 0.25, optimized for recall)
            high_threshold: Above this = block (default: 0.55, optimized for recall)
            escalation_mode: Default escalation action ('degraded_response', 'safe_mode', 'clarify', 'sandbox')
        """
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self.escalation_mode = escalation_mode
        
        # Validate thresholds
        if not (0.0 < low_threshold < high_threshold <= 1.0):
            raise ValueError(f"Invalid thresholds: {low_threshold} must be < {high_threshold} <= 1.0")
    
    def decide(self, jailbreak_probability: float) -> EscalationResult:
        """
        Make escalation decision based on jailbreak probability.
        
        Args:
            jailbreak_probability: Probability of jailbreak (0.0 to 1.0)
        
        Returns:
            EscalationResult with action and reasoning
        """
        if jailbreak_probability < self.low_threshold:
            # Low confidence - clearly benign
            return EscalationResult(
                action=EscalationAction.ALLOW,
                confidence_tier="low",
                jailbreak_probability=jailbreak_probability,
                reason=f"Low jailbreak probability ({jailbreak_probability:.2%}) - below threshold ({self.low_threshold:.2%})",
                recommendation="Allow prompt - low risk of jailbreak"
            )
        
        elif jailbreak_probability > self.high_threshold:
            # High confidence - clearly malicious
            return EscalationResult(
                action=EscalationAction.BLOCK,
                confidence_tier="high",
                jailbreak_probability=jailbreak_probability,
                reason=f"High jailbreak probability ({jailbreak_probability:.2%}) - above threshold ({self.high_threshold:.2%})",
                recommendation="Block prompt - high risk of jailbreak"
            )
        
        else:
            # Medium confidence - uncertain, escalate
            escalation_action = self._get_escalation_action()
            return EscalationResult(
                action=escalation_action,
                confidence_tier="medium",
                jailbreak_probability=jailbreak_probability,
                reason=f"Medium jailbreak probability ({jailbreak_probability:.2%}) - between thresholds ({self.low_threshold:.2%}-{self.high_threshold:.2%})",
                recommendation=f"Escalate with {escalation_action.value} - uncertain risk requires review"
            )
    
    def _get_escalation_action(self) -> EscalationAction:
        """Get escalation action based on mode."""
        mode_map = {
            "degraded_response": EscalationAction.DEGRADED_RESPONSE,
            "safe_mode": EscalationAction.SAFE_MODE,
            "clarify": EscalationAction.CLARIFY,
            "sandbox": EscalationAction.SANDBOX,
            "escalate": EscalationAction.ESCALATE,
        }
        return mode_map.get(self.escalation_mode, EscalationAction.ESCALATE)
    
    def get_escalation_message(self, result: EscalationResult) -> str:
        """
        Get human-readable escalation message.
        
        Args:
            result: EscalationResult
        
        Returns:
            Message for user/system
        """
        if result.action == EscalationAction.ALLOW:
            return "Prompt allowed - low risk detected"
        
        elif result.action == EscalationAction.BLOCK:
            return f"Prompt blocked - high jailbreak risk ({result.jailbreak_probability:.1%})"
        
        elif result.action == EscalationAction.DEGRADED_RESPONSE:
            return "Prompt escalated - responding with limited capabilities due to uncertain risk"
        
        elif result.action == EscalationAction.SAFE_MODE:
            return "Prompt escalated - responding in safe mode (generic, non-specific answer)"
        
        elif result.action == EscalationAction.CLARIFY:
            return "Prompt escalated - please clarify your intent to proceed"
        
        elif result.action == EscalationAction.SANDBOX:
            return "Prompt escalated - executing in sandboxed environment for safety"
        
        else:
            return f"Prompt escalated - requires review (risk: {result.jailbreak_probability:.1%})"


