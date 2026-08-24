"""
Risk Trajectory Tracker.

Tracks evolution of risk across turns and detects trajectory-based escalations
that a single-prompt score would miss.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from security_types import (
    RiskTrajectory, RiskTrajectoryPoint, RiskState, risk_score_to_state
)


class RiskTrajectoryTracker:
    """
    Maintains per-session / per-agent risk trajectories.

    Prototype heuristics (configurable):
    - sudden increase: delta >= sudden_delta
    - gradual escalation: monotonically rising over min_turns with total rise >= gradual_rise
    - repeated attacks: attack turns >= repeated_attack_threshold in window
    - repeated capability requests: count >= repeated_cap_threshold
    """

    def __init__(
        self,
        sudden_delta: float = 0.25,
        gradual_rise: float = 0.40,
        min_gradual_turns: int = 3,
        repeated_attack_threshold: int = 2,
        repeated_cap_threshold: int = 3,
        state_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.sudden_delta = sudden_delta
        self.gradual_rise = gradual_rise
        self.min_gradual_turns = min_gradual_turns
        self.repeated_attack_threshold = repeated_attack_threshold
        self.repeated_cap_threshold = repeated_cap_threshold
        self.state_thresholds = state_thresholds
        self.trajectories: Dict[str, RiskTrajectory] = {}
        self._capability_request_counts: Dict[str, int] = {}

    def _key(self, session_id: str, agent_id: Optional[str] = None) -> str:
        return f"{session_id}::{agent_id or 'none'}"

    def get_or_create(self, session_id: str, agent_id: Optional[str] = None) -> RiskTrajectory:
        key = self._key(session_id, agent_id)
        if key not in self.trajectories:
            self.trajectories[key] = RiskTrajectory(session_id=session_id, agent_id=agent_id)
        return self.trajectories[key]

    def record(
        self,
        session_id: str,
        risk_score: float,
        attack_classes: Optional[List[str]] = None,
        agent_id: Optional[str] = None,
        note: str = "",
        capability_requested: bool = False,
    ) -> RiskTrajectory:
        traj = self.get_or_create(session_id, agent_id)
        turn = len(traj.points) + 1
        state = risk_score_to_state(risk_score, self.state_thresholds)
        point = RiskTrajectoryPoint(
            turn=turn,
            risk_score=round(risk_score, 4),
            risk_state=state,
            timestamp=datetime.now(),
            attack_classes=attack_classes or [],
            note=note,
        )
        traj.points.append(point)

        key = self._key(session_id, agent_id)
        if capability_requested:
            self._capability_request_counts[key] = self._capability_request_counts.get(key, 0) + 1

        self._analyze(traj, key)
        return traj

    def _analyze(self, traj: RiskTrajectory, key: str) -> None:
        alerts: List[str] = []
        series = traj.to_series()

        # Sudden increase
        if len(series) >= 2:
            delta = series[-1] - series[-2]
            if delta >= self.sudden_delta:
                traj.sudden_increase_detected = True
                alerts.append(f"Sudden risk increase Δ={delta:.2f}")

        # Gradual escalation
        if len(series) >= self.min_gradual_turns:
            window = series[-self.min_gradual_turns:]
            rising = all(window[i] <= window[i + 1] for i in range(len(window) - 1))
            total_rise = window[-1] - window[0]
            if rising and total_rise >= self.gradual_rise:
                traj.gradual_escalation_detected = True
                alerts.append(f"Gradual privilege escalation rise={total_rise:.2f}")

        # Repeated attacks
        attack_turns = sum(1 for p in traj.points[-5:] if p.attack_classes and p.attack_classes != ["none"])
        if attack_turns >= self.repeated_attack_threshold:
            traj.repeated_attack_detected = True
            alerts.append(f"Repeated attack attempts in window ({attack_turns})")

        # Repeated capability requests
        cap_count = self._capability_request_counts.get(key, 0)
        if cap_count >= self.repeated_cap_threshold:
            traj.repeated_capability_request_detected = True
            alerts.append(f"Repeated capability requests ({cap_count})")

        traj.trajectory_alerts = alerts

    def should_escalate(self, session_id: str, agent_id: Optional[str] = None) -> bool:
        traj = self.get_or_create(session_id, agent_id)
        return any([
            traj.sudden_increase_detected,
            traj.gradual_escalation_detected,
            traj.repeated_attack_detected and traj.current_risk() >= 0.5,
            traj.repeated_capability_request_detected and traj.current_risk() >= 0.4,
        ])

    def trajectory_risk_bonus(self, session_id: str, agent_id: Optional[str] = None) -> float:
        """Additional risk contribution from trajectory signals (prototype)."""
        traj = self.get_or_create(session_id, agent_id)
        bonus = 0.0
        if traj.sudden_increase_detected:
            bonus += 0.12
        if traj.gradual_escalation_detected:
            bonus += 0.18
        if traj.repeated_attack_detected:
            bonus += 0.10
        if traj.repeated_capability_request_detected:
            bonus += 0.08
        return min(0.35, bonus)

    def snapshot(self, session_id: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        traj = self.get_or_create(session_id, agent_id)
        return {
            "session_id": session_id,
            "agent_id": agent_id,
            "series": traj.to_series(),
            "alerts": list(traj.trajectory_alerts),
            "sudden_increase": traj.sudden_increase_detected,
            "gradual_escalation": traj.gradual_escalation_detected,
            "repeated_attacks": traj.repeated_attack_detected,
            "current_risk": traj.current_risk(),
            "current_state": traj.points[-1].risk_state.value if traj.points else RiskState.LOW.value,
        }
