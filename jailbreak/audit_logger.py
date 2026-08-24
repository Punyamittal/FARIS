"""
Immutable-style security event / audit logger for FARIS.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from security_types import (
    SecurityEvent, EventType, new_event_id
)


class AuditLogger:
    """Append-only in-memory audit log with optional file persistence."""

    def __init__(self, persist_path: Optional[str] = None):
        self.events: List[SecurityEvent] = []
        self.persist_path = Path(persist_path) if persist_path else None
        if self.persist_path:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)

    def create_security_event(
        self,
        event_type: EventType,
        risk_score: float,
        previous_risk: float,
        new_risk: float,
        decision: str,
        reason: str,
        policy_version: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        attack_classes: Optional[List[str]] = None,
        provenance: str = "unknown",
        requested_capability: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        event = SecurityEvent(
            event_id=new_event_id(),
            timestamp=datetime.now(),
            agent_id=agent_id,
            session_id=session_id,
            user_id=user_id,
            event_type=event_type,
            risk_score=risk_score,
            previous_risk=previous_risk,
            new_risk=new_risk,
            attack_classes=attack_classes or [],
            provenance=provenance,
            requested_capability=requested_capability,
            decision=decision,
            reason=reason,
            policy_version=policy_version,
            metadata=metadata or {},
        )
        self.events.append(event)
        if self.persist_path:
            with self.persist_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        return event

    def list_events(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        items = self.events
        if session_id:
            items = [e for e in items if e.session_id == session_id]
        if agent_id:
            items = [e for e in items if e.agent_id == agent_id]
        return [e.to_dict() for e in items[-limit:]]

    def summary(self) -> Dict[str, Any]:
        blocked = sum(1 for e in self.events if e.decision.upper() in ("BLOCK", "DENY"))
        reviews = sum(1 for e in self.events if e.event_type == EventType.HUMAN_REVIEW_REQUESTED)
        attacks = sum(1 for e in self.events if e.attack_classes and e.attack_classes != ["none"])
        return {
            "total_events": len(self.events),
            "blocked_or_denied": blocked,
            "human_reviews": reviews,
            "events_with_attacks": attacks,
        }
