"""
Core data structures for FARIS (Financial AI Risk & Integrity Shield).

Preserves the original Anti-Jailbreak Security System types and extends
them for financial AI-agent risk management.
"""

from enum import IntEnum, Enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Set, Any, Union
from datetime import datetime, timedelta
import uuid


# ---------------------------------------------------------------------------
# Original authority / attack / capability types (backward compatible)
# ---------------------------------------------------------------------------

class AuthorityLevel(IntEnum):
    """Immutable hierarchy: higher values cannot be overridden by lower values."""
    SYSTEM = 4
    DEVELOPER = 3
    USER = 2
    EXTERNAL_UNTRUSTED = 1


class AttackClass(Enum):
    """Categories of detected attack patterns (extended for FARIS)."""
    # Original
    ROLE_PLAY = "role_play"
    INSTRUCTION_OVERRIDE = "instruction_override"
    AUTHORITY_ESCALATION = "authority_escalation"
    INDIRECT_INJECTION = "indirect_injection"
    MEMORY_POISONING = "memory_poisoning"
    CAPABILITY_ESCALATION = "capability_escalation"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    SOCIAL_ENGINEERING = "social_engineering"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    NONE = "none"
    # FARIS extensions
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    TOOL_MANIPULATION = "tool_manipulation"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_MANIPULATION = "policy_manipulation"
    MALICIOUS_DOCUMENT = "malicious_document"
    MALICIOUS_WEBPAGE = "malicious_webpage"


class AttackSeverity(Enum):
    """Severity attached to an attack class finding."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Default severity map (prototype, configurable)
ATTACK_SEVERITY_MAP: Dict[AttackClass, AttackSeverity] = {
    AttackClass.NONE: AttackSeverity.INFO,
    AttackClass.ROLE_PLAY: AttackSeverity.MEDIUM,
    AttackClass.INSTRUCTION_OVERRIDE: AttackSeverity.HIGH,
    AttackClass.AUTHORITY_ESCALATION: AttackSeverity.CRITICAL,
    AttackClass.INDIRECT_INJECTION: AttackSeverity.HIGH,
    AttackClass.MEMORY_POISONING: AttackSeverity.HIGH,
    AttackClass.CAPABILITY_ESCALATION: AttackSeverity.CRITICAL,
    AttackClass.ENCODING_OBFUSCATION: AttackSeverity.MEDIUM,
    AttackClass.SOCIAL_ENGINEERING: AttackSeverity.LOW,
    AttackClass.MULTI_TURN_ESCALATION: AttackSeverity.HIGH,
    AttackClass.JAILBREAK: AttackSeverity.HIGH,
    AttackClass.PROMPT_INJECTION: AttackSeverity.HIGH,
    AttackClass.TOOL_MANIPULATION: AttackSeverity.CRITICAL,
    AttackClass.DATA_EXFILTRATION: AttackSeverity.CRITICAL,
    AttackClass.POLICY_MANIPULATION: AttackSeverity.CRITICAL,
    AttackClass.MALICIOUS_DOCUMENT: AttackSeverity.HIGH,
    AttackClass.MALICIOUS_WEBPAGE: AttackSeverity.HIGH,
}


class Capability(Enum):
    """
    Explicit capabilities that must be granted.

    Original generic capabilities are preserved. Financial capabilities are
    added for FARIS agent workflows.
    """
    # Original
    READ = "read"
    WRITE_MEMORY = "write_memory"
    EXECUTE_TOOLS = "execute_tools"
    SEND_DATA = "send_data"
    PERSIST_STATE = "persist_state"
    ACCESS_SYSTEM_INFO = "access_system_info"
    # Financial / agent capabilities
    READ_TRANSACTION = "read_transaction"
    READ_MERCHANT = "read_merchant"
    READ_DOCUMENT = "read_document"
    ANALYZE_TRANSACTION = "analyze_transaction"
    ANALYZE_MERCHANT = "analyze_merchant"
    QUERY_RISK_DATABASE = "query_risk_database"
    WRITE_CASE = "write_case"
    SEND_NOTIFICATION = "send_notification"
    MODIFY_RISK_STATUS = "modify_risk_status"
    APPROVE_ACTION = "approve_action"
    EXECUTE_FINANCIAL_ACTION = "execute_financial_action"
    EXPORT_DATA = "export_data"


# Capability metadata: authority needed to grant, min risk ceiling to keep, default TTL minutes
CAPABILITY_META: Dict[Capability, Dict[str, Any]] = {
    Capability.READ: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.9, "ttl_minutes": 120, "sensitive": False},
    Capability.WRITE_MEMORY: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.5, "ttl_minutes": 60, "sensitive": True},
    Capability.EXECUTE_TOOLS: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.6, "ttl_minutes": 60, "sensitive": True},
    Capability.SEND_DATA: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.4, "ttl_minutes": 30, "sensitive": True},
    Capability.PERSIST_STATE: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.5, "ttl_minutes": 60, "sensitive": True},
    Capability.ACCESS_SYSTEM_INFO: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.3, "ttl_minutes": 15, "sensitive": True},
    Capability.READ_TRANSACTION: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.85, "ttl_minutes": 120, "sensitive": False},
    Capability.READ_MERCHANT: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.85, "ttl_minutes": 120, "sensitive": False},
    Capability.READ_DOCUMENT: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.85, "ttl_minutes": 120, "sensitive": False},
    Capability.ANALYZE_TRANSACTION: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.75, "ttl_minutes": 90, "sensitive": False},
    Capability.ANALYZE_MERCHANT: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.75, "ttl_minutes": 90, "sensitive": False},
    Capability.QUERY_RISK_DATABASE: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.7, "ttl_minutes": 60, "sensitive": False},
    Capability.WRITE_CASE: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.55, "ttl_minutes": 45, "sensitive": True},
    Capability.SEND_NOTIFICATION: {"authority": AuthorityLevel.SYSTEM, "max_risk": 0.6, "ttl_minutes": 60, "sensitive": True},
    Capability.MODIFY_RISK_STATUS: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.45, "ttl_minutes": 30, "sensitive": True},
    Capability.APPROVE_ACTION: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.35, "ttl_minutes": 15, "sensitive": True},
    Capability.EXECUTE_FINANCIAL_ACTION: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.30, "ttl_minutes": 10, "sensitive": True},
    Capability.EXPORT_DATA: {"authority": AuthorityLevel.DEVELOPER, "max_risk": 0.40, "ttl_minutes": 20, "sensitive": True},
}


class ExecutionDecision(Enum):
    """Final routing decision (extended with FARIS aliases)."""
    ALLOW = "allow"
    ALLOW_DEGRADED = "allow_degraded"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    BLOCK = "block"
    DENY = "deny"  # Alias semantics for financial tool denials


class RiskState(Enum):
    """Discrete risk bands for adaptive control."""
    LOW = "low"
    GUARDED = "guarded"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class AgentRole(Enum):
    """Financial AI agent roles (generic payment-platform simulation)."""
    MERCHANT_ANALYST = "merchant_analyst"
    FRAUD_INVESTIGATOR = "fraud_investigator"
    SUPPORT_AGENT = "support_agent"
    DOCUMENT_ANALYST = "document_analyst"
    PAYMENT_ANALYST = "payment_analyst"
    RISK_ANALYST = "risk_analyst"


class TrustLevel(Enum):
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"


class EventType(Enum):
    REQUEST_PROCESSED = "request_processed"
    TOOL_EVALUATED = "tool_evaluated"
    CAPABILITY_GRANTED = "capability_granted"
    CAPABILITY_REVOKED = "capability_revoked"
    RISK_UPDATED = "risk_updated"
    ATTACK_DETECTED = "attack_detected"
    HUMAN_REVIEW_REQUESTED = "human_review_requested"
    HUMAN_REVIEW_RESOLVED = "human_review_resolved"
    EMERGENCY_ISOLATION = "emergency_isolation"
    POLICY_TRIGGERED = "policy_triggered"


# ---------------------------------------------------------------------------
# Provenance / prompt structures
# ---------------------------------------------------------------------------

@dataclass
class Provenance:
    """Tracks origin and trust level of content."""
    source: str
    authority: AuthorityLevel
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_provenance: Optional["Provenance"] = None


@dataclass
class TokenProvenance:
    token_range: tuple
    provenance: Provenance
    is_executable: bool = False


@dataclass
class PromptSegment:
    content: str
    provenance: Provenance
    authority: AuthorityLevel
    is_executable: bool = False


@dataclass
class StructuredPrompt:
    segments: List[PromptSegment]
    system_instructions: List[str] = field(default_factory=list)
    developer_policies: List[str] = field(default_factory=list)
    user_input: List[str] = field(default_factory=list)
    external_content: List[str] = field(default_factory=list)
    full_text: str = ""

    def get_highest_authority(self) -> AuthorityLevel:
        if not self.segments:
            return AuthorityLevel.SYSTEM
        return max(seg.authority for seg in self.segments)


@dataclass
class RiskScore:
    """Risk assessment output (single-turn)."""
    score: float
    attack_classes: List[AttackClass]
    confidence: float
    indicators: List[str] = field(default_factory=list)
    reasoning: str = ""
    components: Dict[str, float] = field(default_factory=dict)


@dataclass
class CapabilityGrant:
    """Time-limited capability grant with audit metadata."""
    capability: Capability
    granted_at: datetime
    expires_at: datetime
    granted_by: AuthorityLevel
    conditions: Dict[str, Any] = field(default_factory=dict)
    grant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: Optional[str] = None
    revoked: bool = False
    audit_note: str = ""

    def is_valid(self) -> bool:
        return (not self.revoked) and datetime.now() < self.expires_at


@dataclass
class ExecutionContext:
    prompt: StructuredPrompt
    risk_score: RiskScore
    requested_capabilities: Set[Capability]
    granted_capabilities: Set[Capability]
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    policy_rules: Dict[str, Any] = field(default_factory=dict)
    agent_id: Optional[str] = None
    risk_state: RiskState = RiskState.LOW
    financial_context: Optional[Dict[str, Any]] = None


@dataclass
class ExecutionResult:
    decision: ExecutionDecision
    context: ExecutionContext
    allowed_capabilities: Set[Capability]
    block_reason: Optional[str] = None
    requires_user_confirmation: bool = False
    confirmation_message: Optional[str] = None
    requires_human_review: bool = False
    explanation: Optional[Dict[str, Any]] = None
    security_event_id: Optional[str] = None


# ---------------------------------------------------------------------------
# FARIS: Agent, financial context, trajectory, audit
# ---------------------------------------------------------------------------

@dataclass
class AgentProfile:
    """Explicit AI agent model for financial workflows."""
    agent_id: str
    role: AgentRole
    trust_level: TrustLevel
    allowed_capabilities: Set[Capability]
    risk_state: RiskState = RiskState.LOW
    session_id: Optional[str] = None
    current_permissions: Set[Capability] = field(default_factory=set)
    tool_permissions: Set[str] = field(default_factory=set)
    maximum_transaction_authority: float = 0.0  # synthetic currency units
    escalation_policy: str = "require_human_review_above_high"
    current_risk_score: float = 0.0
    isolated: bool = False

    def __post_init__(self):
        if not self.current_permissions:
            self.current_permissions = set(self.allowed_capabilities)


@dataclass
class TransactionContext:
    """Synthetic transaction context (demo data only)."""
    transaction_id: str
    amount: float
    currency: str
    merchant_id: str
    customer_id: str
    payment_method: str
    transaction_velocity: float = 0.0
    geographic_context: str = "IN"
    transaction_risk: float = 0.0


@dataclass
class MerchantContext:
    """Synthetic merchant context (demo data only)."""
    merchant_id: str
    account_age_days: int
    verification_status: str
    transaction_volume: float
    historical_risk: float
    category: str
    external_content: List[str] = field(default_factory=list)


@dataclass
class DocumentContext:
    """Synthetic document context for document-analyst agents."""
    document_id: str
    source: str
    provenance: AuthorityLevel
    trust_level: TrustLevel
    extracted_text: str
    suspicious_instructions: List[str] = field(default_factory=list)


@dataclass
class RiskTrajectoryPoint:
    turn: int
    risk_score: float
    risk_state: RiskState
    timestamp: datetime
    attack_classes: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class RiskTrajectory:
    """Evolution of risk across a session / agent lifetime."""
    session_id: str
    agent_id: Optional[str] = None
    points: List[RiskTrajectoryPoint] = field(default_factory=list)
    sudden_increase_detected: bool = False
    gradual_escalation_detected: bool = False
    repeated_attack_detected: bool = False
    repeated_capability_request_detected: bool = False
    trajectory_alerts: List[str] = field(default_factory=list)

    def current_risk(self) -> float:
        return self.points[-1].risk_score if self.points else 0.0

    def previous_risk(self) -> float:
        return self.points[-2].risk_score if len(self.points) >= 2 else 0.0

    def to_series(self) -> List[float]:
        return [p.risk_score for p in self.points]


@dataclass
class AttackFinding:
    attack_class: AttackClass
    severity: AttackSeverity
    indicators: List[str] = field(default_factory=list)
    source_authority: Optional[AuthorityLevel] = None
    confidence: float = 0.0


@dataclass
class SecurityEvent:
    """Immutable-style audit record."""
    event_id: str
    timestamp: datetime
    agent_id: Optional[str]
    session_id: Optional[str]
    user_id: Optional[str]
    event_type: EventType
    risk_score: float
    previous_risk: float
    new_risk: float
    attack_classes: List[str]
    provenance: str
    requested_capability: Optional[str]
    decision: str
    reason: str
    policy_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["event_type"] = self.event_type.value
        return d


@dataclass
class DecisionExplanation:
    """Explainable decision payload."""
    what_happened: str
    why_risky: List[str]
    requested_capability: Optional[str]
    policy_triggered: List[str]
    action_taken: str
    risk_score: float
    risk_state: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallRequest:
    """Agent tool-call request for independent authorization."""
    tool_name: str
    arguments: Dict[str, Any]
    agent_id: str
    session_id: str
    required_capability: Capability
    user_id: Optional[str] = None


@dataclass
class FARISDecision:
    """Structured API response for FARIS operations."""
    decision: str
    risk_score: float
    risk_state: str
    attack_classes: List[str]
    requested_capability: Optional[str]
    capability_granted: bool
    requires_human_review: bool
    reason: str
    explanation: Optional[Dict[str, Any]] = None
    allowed_capabilities: List[str] = field(default_factory=list)
    trajectory: Optional[List[float]] = None
    security_event_id: Optional[str] = None
    human_review_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def risk_score_to_state(score: float, thresholds: Optional[Dict[str, float]] = None) -> RiskState:
    """Map continuous risk to discrete state (configurable prototype)."""
    t = thresholds or {
        "guarded": 0.30,
        "elevated": 0.50,
        "high": 0.70,
        "critical": 0.90,
    }
    if score >= t["critical"]:
        return RiskState.CRITICAL
    if score >= t["high"]:
        return RiskState.HIGH
    if score >= t["elevated"]:
        return RiskState.ELEVATED
    if score >= t["guarded"]:
        return RiskState.GUARDED
    return RiskState.LOW


def new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex[:12]}"
