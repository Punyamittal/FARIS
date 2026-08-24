"""
Human-in-the-loop review queue (simulated approval interface).
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class ReviewStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class HumanReviewQueue:
    """Simulated human approval API for high-risk agent actions."""

    def __init__(self):
        self.queue: Dict[str, Dict[str, Any]] = {}

    def request_human_review(
        self,
        agent_id: str,
        session_id: str,
        reason: str,
        risk_score: float,
        requested_capability: Optional[str] = None,
        provenance: str = "",
        explanation: Optional[Dict[str, Any]] = None,
        security_event_id: Optional[str] = None,
        frozen_capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        review_id = f"hr_{uuid.uuid4().hex[:10]}"
        record = {
            "review_id": review_id,
            "status": ReviewStatus.PENDING.value,
            "created_at": datetime.now().isoformat(),
            "resolved_at": None,
            "resolver": None,
            "agent_id": agent_id,
            "session_id": session_id,
            "reason": reason,
            "risk_score": risk_score,
            "requested_capability": requested_capability,
            "provenance": provenance,
            "explanation": explanation or {},
            "security_event_id": security_event_id,
            "frozen_capabilities": frozen_capabilities or [],
            "metadata": metadata or {},
        }
        self.queue[review_id] = record
        return record

    def approve(self, review_id: str, resolver: str = "human_operator") -> Dict[str, Any]:
        return self._resolve(review_id, ReviewStatus.APPROVED, resolver)

    def reject(self, review_id: str, resolver: str = "human_operator") -> Dict[str, Any]:
        return self._resolve(review_id, ReviewStatus.REJECTED, resolver)

    def _resolve(self, review_id: str, status: ReviewStatus, resolver: str) -> Dict[str, Any]:
        if review_id not in self.queue:
            return {"error": "not_found", "review_id": review_id}
        rec = self.queue[review_id]
        if rec["status"] != ReviewStatus.PENDING.value:
            return {"error": "already_resolved", "record": rec}
        rec["status"] = status.value
        rec["resolved_at"] = datetime.now().isoformat()
        rec["resolver"] = resolver
        return rec

    def pending(self) -> List[Dict[str, Any]]:
        return [r for r in self.queue.values() if r["status"] == ReviewStatus.PENDING.value]

    def get(self, review_id: str) -> Optional[Dict[str, Any]]:
        return self.queue.get(review_id)

    def all_reviews(self) -> List[Dict[str, Any]]:
        return list(self.queue.values())
