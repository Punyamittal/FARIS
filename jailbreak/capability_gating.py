"""
Capability & Permission Gating Module (FARIS-extended).

Capabilities must be explicitly granted by SYSTEM/DEVELOPER, time-limited,
revocable, and NEVER granted by user prompts.
"""

import re
from typing import Set, Dict, Optional, List, Tuple, Any
from datetime import datetime, timedelta
from security_types import (
    Capability, CapabilityGrant, AuthorityLevel, StructuredPrompt,
    ExecutionContext, CAPABILITY_META
)


class CapabilityGate:
    """
    Manages capability grants and enforces permission boundaries.

    CRITICAL RULE: A user prompt must NEVER be capable of granting itself
    a capability. Only SYSTEM or DEVELOPER authority may grant.
    """

    def __init__(self, default_ttl_minutes: int = 60):
        self.default_ttl = timedelta(minutes=default_ttl_minutes)
        self.active_grants: Dict[str, CapabilityGrant] = {}
        self.user_grants: Dict[str, Set[Capability]] = {}
        self.agent_grants: Dict[str, Set[Capability]] = {}
        self.denied_self_grants: List[Dict[str, Any]] = []

    def grant_capability(
        self,
        capability: Capability,
        granted_by: AuthorityLevel,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        ttl: Optional[timedelta] = None,
        conditions: Optional[Dict] = None,
        audit_note: str = "",
    ) -> str:
        if granted_by not in [AuthorityLevel.SYSTEM, AuthorityLevel.DEVELOPER]:
            raise ValueError(
                f"Capabilities can only be granted by SYSTEM or DEVELOPER, "
                f"not {granted_by.name}"
            )

        meta = CAPABILITY_META.get(capability, {})
        ttl = ttl or timedelta(minutes=meta.get("ttl_minutes", self.default_ttl.total_seconds() / 60))

        grant = CapabilityGrant(
            capability=capability,
            granted_at=datetime.now(),
            expires_at=datetime.now() + ttl,
            granted_by=granted_by,
            conditions=conditions or {},
            agent_id=agent_id,
            audit_note=audit_note or f"Granted by {granted_by.name}",
        )

        self.active_grants[grant.grant_id] = grant

        if user_id:
            self.user_grants.setdefault(user_id, set()).add(capability)
        if agent_id:
            self.agent_grants.setdefault(agent_id, set()).add(capability)

        return grant.grant_id

    def revoke_capability(self, grant_id: str) -> bool:
        if grant_id not in self.active_grants:
            return False
        grant = self.active_grants[grant_id]
        grant.revoked = True
        del self.active_grants[grant_id]
        for store in (self.user_grants, self.agent_grants):
            for key, caps in list(store.items()):
                caps.discard(grant.capability)
        return True

    def revoke_capability_for_agent(self, agent_id: str, capability: Capability) -> bool:
        removed = False
        for grant_id, grant in list(self.active_grants.items()):
            if grant.agent_id == agent_id and grant.capability == capability:
                self.revoke_capability(grant_id)
                removed = True
        if agent_id in self.agent_grants:
            self.agent_grants[agent_id].discard(capability)
            removed = True
        return removed

    def revoke_user_capabilities(self, user_id: str) -> int:
        if user_id not in self.user_grants:
            return 0
        revoked = len(self.user_grants[user_id])
        del self.user_grants[user_id]
        return revoked

    def get_valid_capabilities(
        self,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Set[Capability]:
        valid: Set[Capability] = set()

        def collect(keys: Set[Capability]):
            for capability in keys:
                for grant in self.active_grants.values():
                    if grant.capability == capability and grant.is_valid():
                        valid.add(capability)
                        break

        if user_id and user_id in self.user_grants:
            collect(self.user_grants[user_id])
        if agent_id and agent_id in self.agent_grants:
            collect(self.agent_grants[agent_id])

        # System-wide active grants
        for grant in self.active_grants.values():
            if grant.is_valid() and grant.granted_by in (
                AuthorityLevel.SYSTEM, AuthorityLevel.DEVELOPER
            ):
                if grant.agent_id is None and grant.conditions.get("user_id") is None:
                    valid.add(grant.capability)
                elif agent_id and grant.agent_id == agent_id:
                    valid.add(grant.capability)
                elif user_id and (user_id in self.user_grants and grant.capability in self.user_grants[user_id]):
                    valid.add(grant.capability)

        return valid

    def detect_capability_requests(self, prompt: StructuredPrompt) -> Set[Capability]:
        requested: Set[Capability] = set()
        text_lower = (prompt.full_text or "").lower()

        capability_patterns = {
            Capability.READ: [
                r'(?i)(read|access|view|see|retrieve).*(memory|data|information|files)',
            ],
            Capability.WRITE_MEMORY: [
                r'(?i)(remember|store|save|memorize|persist).*(this|that|the following)',
            ],
            Capability.EXECUTE_TOOLS: [
                r'(?i)(execute|run|call|invoke).*(tool|function|api|command)',
            ],
            Capability.SEND_DATA: [
                r'(?i)(send|transmit|post|upload|share).*(data|information)',
            ],
            Capability.PERSIST_STATE: [
                r'(?i)(save|persist).*(state|settings|configuration)',
            ],
            Capability.ACCESS_SYSTEM_INFO: [
                r'(?i)(show|reveal|display).*(system prompt|internal instructions)',
            ],
            Capability.READ_TRANSACTION: [
                r'(?i)(read|get|fetch|show).*(transaction)',
            ],
            Capability.READ_MERCHANT: [
                r'(?i)(read|get|fetch|show|analyze).*(merchant)',
            ],
            Capability.READ_DOCUMENT: [
                r'(?i)(read|open|analyze).*(document|pdf|attachment)',
            ],
            Capability.ANALYZE_TRANSACTION: [
                r'(?i)(analyze|investigate).*(transaction|payment)',
            ],
            Capability.ANALYZE_MERCHANT: [
                r'(?i)(analyze|investigate|review).*(merchant)',
            ],
            Capability.QUERY_RISK_DATABASE: [
                r'(?i)(query|lookup|check).*(risk|fraud).*(database|score|system)?',
            ],
            Capability.WRITE_CASE: [
                r'(?i)(create|open|write).*(case|ticket|investigation)',
            ],
            Capability.SEND_NOTIFICATION: [
                r'(?i)(send|notify|alert).*(notification|email|message)',
            ],
            Capability.MODIFY_RISK_STATUS: [
                r'(?i)\b(modify_risk_status)\b',
                r'(?i)(modify|update|change)\s+(the\s+)?risk\s+status',
                r'(?i)mark\s+(this\s+)?merchant\s+as\s+verified',
            ],
            Capability.APPROVE_ACTION: [
                r'(?i)\bapprove_action\b',
                r'(?i)grant me approve_action',
                r'(?i)approve\s+(the\s+)?(action|transaction|merchant|payout)\b',
            ],
            Capability.EXECUTE_FINANCIAL_ACTION: [
                r'(?i)(execute|perform).*(payout|refund|transfer|financial action)',
                r'(?i)execute_financial_action',
            ],
            Capability.EXPORT_DATA: [
                r'(?i)(export|download|dump).*(data|transactions|customers)',
            ],
        }

        for capability, patterns in capability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    requested.add(capability)
                    break
        return requested

    def enforce_capability_gating(self, context: ExecutionContext) -> Set[Capability]:
        valid = self.get_valid_capabilities(context.user_id, context.agent_id)
        # Intersection: only granted caps that are valid
        # For routing we return currently valid grants (not only requested)
        return valid & (context.granted_capabilities | valid)

    def check_capability_escalation(
        self,
        prompt: StructuredPrompt
    ) -> Tuple[bool, List[str]]:
        indicators: List[str] = []
        text_lower = (prompt.full_text or "").lower()

        escalation_patterns = [
            (r'(?i)(grant|give|enable|allow|provide).*(access|permission|capability|privilege|power)',
             "Attempting to grant capabilities"),
            (r'(?i)(system\s*:).*grant.*(approve_action|permission|capability)',
             "Forged system grant of capability"),
            (r'(?i)grant me (approve_action|execute_financial_action|modify_risk_status)',
             "Self-grant of privileged financial capability"),
            (r'(?i)(you can now|you are able to|you have the ability to).*(do|access|execute|approve)',
             "Claiming new capabilities"),
            (r'(?i)(unrestricted|full|complete|total).*(access|power|control|capability)',
             "Requesting unrestricted access"),
            (r'(?i)(bypass|override|ignore).*(restrictions|limits|permissions)',
             "Attempting to bypass restrictions"),
        ]

        is_escalation = False
        for pattern, indicator in escalation_patterns:
            if re.search(pattern, text_lower):
                is_escalation = True
                indicators.append(indicator)

        if is_escalation:
            self.denied_self_grants.append({
                "timestamp": datetime.now().isoformat(),
                "text_excerpt": (prompt.full_text or "")[:200],
                "indicators": indicators,
            })

        return is_escalation, indicators

    def reject_prompt_grant_attempt(self, prompt: StructuredPrompt) -> Dict[str, Any]:
        """Explicit API: prompts never grant capabilities — always DENY."""
        is_esc, indicators = self.check_capability_escalation(prompt)
        return {
            "capability_granted": False,
            "decision": "DENY" if is_esc else "NO_GRANT_ATTEMPT",
            "reason": (
                "User/prompt cannot grant capabilities. Only SYSTEM/DEVELOPER policy can."
                if is_esc else "No self-grant language detected."
            ),
            "indicators": indicators,
        }

    def cleanup_expired_grants(self):
        expired = [
            grant_id for grant_id, grant in self.active_grants.items()
            if not grant.is_valid()
        ]
        for grant_id in expired:
            del self.active_grants[grant_id]
