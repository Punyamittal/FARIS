"""
Agent Security Module.

Manages financial AI agent profiles, risk-adaptive permissions, and isolation.
"""

from typing import Dict, Optional, Set, List, Any
from security_types import (
    AgentProfile, AgentRole, TrustLevel, Capability, RiskState,
    CAPABILITY_META, risk_score_to_state, AuthorityLevel
)


# Default role capability templates (prototype policy)
ROLE_CAPABILITIES: Dict[AgentRole, Set[Capability]] = {
    AgentRole.MERCHANT_ANALYST: {
        Capability.READ, Capability.READ_MERCHANT, Capability.READ_DOCUMENT,
        Capability.ANALYZE_MERCHANT, Capability.QUERY_RISK_DATABASE,
        Capability.WRITE_CASE, Capability.SEND_NOTIFICATION,
    },
    AgentRole.FRAUD_INVESTIGATOR: {
        Capability.READ, Capability.READ_TRANSACTION, Capability.READ_MERCHANT,
        Capability.ANALYZE_TRANSACTION, Capability.QUERY_RISK_DATABASE,
        Capability.WRITE_CASE, Capability.MODIFY_RISK_STATUS, Capability.SEND_NOTIFICATION,
    },
    AgentRole.SUPPORT_AGENT: {
        Capability.READ, Capability.READ_TRANSACTION, Capability.READ_MERCHANT,
        Capability.SEND_NOTIFICATION,
    },
    AgentRole.DOCUMENT_ANALYST: {
        Capability.READ, Capability.READ_DOCUMENT, Capability.ANALYZE_MERCHANT,
        Capability.WRITE_CASE,
    },
    AgentRole.PAYMENT_ANALYST: {
        Capability.READ, Capability.READ_TRANSACTION, Capability.ANALYZE_TRANSACTION,
        Capability.QUERY_RISK_DATABASE, Capability.SEND_NOTIFICATION,
    },
    AgentRole.RISK_ANALYST: {
        Capability.READ, Capability.READ_TRANSACTION, Capability.READ_MERCHANT,
        Capability.ANALYZE_TRANSACTION, Capability.ANALYZE_MERCHANT,
        Capability.QUERY_RISK_DATABASE, Capability.MODIFY_RISK_STATUS,
        Capability.WRITE_CASE, Capability.APPROVE_ACTION,
    },
}

ROLE_TOOL_PERMISSIONS: Dict[AgentRole, Set[str]] = {
    AgentRole.MERCHANT_ANALYST: {"get_merchant", "analyze_document", "query_risk", "create_case"},
    AgentRole.FRAUD_INVESTIGATOR: {
        "get_transaction", "get_merchant", "query_risk", "create_case", "update_risk"
    },
    AgentRole.SUPPORT_AGENT: {"get_transaction", "get_merchant"},
    AgentRole.DOCUMENT_ANALYST: {"analyze_document", "create_case", "get_merchant"},
    AgentRole.PAYMENT_ANALYST: {"get_transaction", "query_risk"},
    AgentRole.RISK_ANALYST: {
        "get_transaction", "get_merchant", "query_risk", "create_case",
        "update_risk", "approve_action"
    },
}

# Privileged capabilities that never auto-expand from prompts
PRIVILEGED_CAPABILITIES: Set[Capability] = {
    Capability.MODIFY_RISK_STATUS,
    Capability.APPROVE_ACTION,
    Capability.EXECUTE_FINANCIAL_ACTION,
    Capability.EXPORT_DATA,
    Capability.ACCESS_SYSTEM_INFO,
    Capability.SEND_DATA,
}


class AgentSecurityManager:
    """Registry and risk-adaptive permission controller for agents."""

    def __init__(self, risk_thresholds: Optional[Dict[str, float]] = None):
        self.agents: Dict[str, AgentProfile] = {}
        self.risk_thresholds = risk_thresholds or {
            "confirmation": 0.30,
            "disable_write": 0.60,
            "human_review": 0.80,
            "isolation": 0.90,
        }

    def register_agent(
        self,
        agent_id: str,
        role: AgentRole,
        trust_level: TrustLevel = TrustLevel.MEDIUM,
        session_id: Optional[str] = None,
        maximum_transaction_authority: float = 10000.0,
        extra_capabilities: Optional[Set[Capability]] = None,
    ) -> AgentProfile:
        caps = set(ROLE_CAPABILITIES.get(role, {Capability.READ}))
        if extra_capabilities:
            caps |= extra_capabilities
        tools = set(ROLE_TOOL_PERMISSIONS.get(role, set()))
        agent = AgentProfile(
            agent_id=agent_id,
            role=role,
            trust_level=trust_level,
            allowed_capabilities=caps,
            current_permissions=set(caps),
            tool_permissions=tools,
            session_id=session_id,
            maximum_transaction_authority=maximum_transaction_authority,
        )
        self.agents[agent_id] = agent
        return agent

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        return self.agents.get(agent_id)

    def update_risk_state(self, agent_id: str, risk_score: float) -> AgentProfile:
        agent = self.agents[agent_id]
        previous = agent.current_risk_score
        agent.current_risk_score = risk_score
        agent.risk_state = risk_score_to_state(risk_score)
        agent.current_permissions = self.apply_risk_adaptive_permissions(agent, risk_score)
        if risk_score >= self.risk_thresholds["isolation"]:
            agent.isolated = True
            agent.current_permissions = {Capability.READ} & agent.allowed_capabilities or set()
        return agent

    def apply_risk_adaptive_permissions(
        self,
        agent: AgentProfile,
        risk_score: float,
    ) -> Set[Capability]:
        """
        Dynamic permission reduction based on risk bands.

        Configurable prototype thresholds — not a validated risk model.
        """
        if agent.isolated or risk_score >= self.risk_thresholds["isolation"]:
            # Emergency isolation: read-only if originally allowed
            return {c for c in agent.allowed_capabilities if c in (
                Capability.READ, Capability.READ_TRANSACTION,
                Capability.READ_MERCHANT, Capability.READ_DOCUMENT
            )}

        perms = set(agent.allowed_capabilities)

        if risk_score >= self.risk_thresholds["human_review"]:
            # Disable autonomous write / financial actions
            perms -= PRIVILEGED_CAPABILITIES
            perms -= {
                Capability.WRITE_CASE, Capability.WRITE_MEMORY,
                Capability.EXECUTE_TOOLS, Capability.SEND_NOTIFICATION,
            }
        elif risk_score >= self.risk_thresholds["disable_write"]:
            perms -= PRIVILEGED_CAPABILITIES
            perms -= {Capability.WRITE_CASE, Capability.WRITE_MEMORY, Capability.EXECUTE_FINANCIAL_ACTION}
        elif risk_score >= self.risk_thresholds["confirmation"]:
            # Sensitive ops still present but callers must require confirmation
            pass

        # Also drop caps whose max_risk is exceeded
        filtered = set()
        for cap in perms:
            meta = CAPABILITY_META.get(cap, {})
            max_risk = meta.get("max_risk", 1.0)
            if risk_score <= max_risk:
                filtered.add(cap)
        return filtered

    def requires_human_review(self, agent_id: str, capability: Optional[Capability] = None) -> bool:
        agent = self.agents.get(agent_id)
        if not agent:
            return True
        if agent.isolated:
            return True
        if agent.current_risk_score >= self.risk_thresholds["human_review"]:
            return True
        if capability in PRIVILEGED_CAPABILITIES and agent.current_risk_score >= self.risk_thresholds["confirmation"]:
            return True
        return False

    def revoke_capability(self, agent_id: str, capability: Capability) -> bool:
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        agent.current_permissions.discard(capability)
        agent.allowed_capabilities.discard(capability)
        return True

    def freeze_sensitive_capabilities(self, agent_id: str) -> List[str]:
        agent = self.agents.get(agent_id)
        if not agent:
            return []
        frozen = []
        for cap in list(agent.current_permissions):
            if cap in PRIVILEGED_CAPABILITIES or CAPABILITY_META.get(cap, {}).get("sensitive"):
                agent.current_permissions.discard(cap)
                frozen.append(cap.value)
        return frozen

    def list_agents(self) -> List[Dict[str, Any]]:
        out = []
        for a in self.agents.values():
            out.append({
                "agent_id": a.agent_id,
                "role": a.role.value,
                "trust_level": a.trust_level.value,
                "risk_state": a.risk_state.value,
                "risk_score": a.current_risk_score,
                "isolated": a.isolated,
                "permissions": sorted(c.value for c in a.current_permissions),
                "session_id": a.session_id,
            })
        return out
