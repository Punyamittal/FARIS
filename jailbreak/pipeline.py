"""
FARIS Pipeline — Financial AI Risk & Integrity Shield.

Closed-loop AI security controller:

UNTRUSTED INPUT → PROVENANCE → ATTACK ANALYSIS → CONTEXTUAL RISK →
RISK TRAJECTORY → CAPABILITY CONTROL → TOOL-CALL AUTHORIZATION →
POLICY DECISION → (optional) AI EXECUTION → POST-EXECUTION RISK UPDATE

The LLM never enforces the permissions that determine what it is allowed to do.
"""

from typing import Optional, List, Dict, Any, Set
from security_types import (
    StructuredPrompt, ExecutionContext, ExecutionResult, ExecutionDecision,
    RiskScore, Capability, AttackClass, AuthorityLevel, FARISDecision,
    ToolCallRequest, AgentRole, TrustLevel, EventType, risk_score_to_state,
)
from authority_enforcement import AuthorityEnforcer
from provenance_tracking import ProvenanceTracker
from risk_scoring import RiskScoringEngine
from capability_gating import CapabilityGate
from execution_router import ExecutionRouter
from attack_detection import AttackDetector
from risk_trajectory import RiskTrajectoryTracker
from agent_security import AgentSecurityManager, PRIVILEGED_CAPABILITIES
from policy_engine import PolicyEngine
from audit_logger import AuditLogger
from human_review import HumanReviewQueue
from tool_security import ToolSecurityGateway
from financial_context import financial_sensitivity, get_transaction, get_merchant


class FARISPipeline:
    """Closed-loop financial AI-agent security controller."""

    def __init__(self, policy_config: Optional[Dict] = None):
        self.authority_enforcer = AuthorityEnforcer()
        self.provenance_tracker = ProvenanceTracker()
        self.risk_scorer = RiskScoringEngine()
        self.capability_gate = CapabilityGate()
        self.execution_router = ExecutionRouter(policy_config)
        self.attack_detector = AttackDetector()
        self.trajectory = RiskTrajectoryTracker()
        self.agents = AgentSecurityManager()
        self.policy = PolicyEngine(policy_config)
        self.audit = AuditLogger(persist_path="audit_logs/faris_events.jsonl")
        self.human_review = HumanReviewQueue()
        self.tools = ToolSecurityGateway(self.agents)
        self.session_history: Dict[str, List[StructuredPrompt]] = {}
        self.session_risk: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_request(
        self,
        prompt_text: str,
        *,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source: str = "user_input",
        external_content: Optional[List[str]] = None,
        transaction_id: Optional[str] = None,
        merchant_id: Optional[str] = None,
        requested_tool: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Full closed-loop evaluation of an agent request.
        Returns structured FARISDecision-compatible dict.
        """
        session_id = session_id or "default"
        previous_risk = self.session_risk.get(session_id, 0.0)
        if agent_id and self.agents.get_agent(agent_id):
            previous_risk = max(previous_risk, self.agents.get_agent(agent_id).current_risk_score)

        # 1. Input security gate + provenance
        structured = self._tag_and_structure(
            prompt_text, user_id, session_id, source, external_content
        )
        structured = self.authority_enforcer.enforce_hierarchy(structured)
        is_escalation, esc_classes, esc_indicators = \
            self.authority_enforcer.check_authority_escalation(structured)
        structured = self.provenance_tracker.enforce_data_vs_instruction_separation(structured)

        untrusted_influence = any(
            s.authority == AuthorityLevel.EXTERNAL_UNTRUSTED for s in structured.segments
        ) and any(
            self.risk_scorer._looks_like_instructions(s.content)
            for s in structured.segments
            if s.authority == AuthorityLevel.EXTERNAL_UNTRUSTED
        )

        # 2. Attack detection
        findings = self.attack_detector.detect(structured)
        attack_classes = [f.attack_class for f in findings if f.attack_class != AttackClass.NONE]
        if is_escalation:
            for c in esc_classes:
                if c not in attack_classes:
                    attack_classes.append(c)

        # 3. Capability request detection (never auto-grant)
        requested = self.capability_gate.detect_capability_requests(structured)
        is_cap_esc, cap_indicators = self.capability_gate.check_capability_escalation(structured)
        if is_cap_esc:
            if AttackClass.CAPABILITY_ESCALATION not in attack_classes:
                attack_classes.append(AttackClass.CAPABILITY_ESCALATION)
            esc_indicators = list(esc_indicators) + cap_indicators

        # Agent permissions
        agent = self.agents.get_agent(agent_id) if agent_id else None
        if agent:
            granted = set(agent.current_permissions)
        else:
            granted = self.capability_gate.get_valid_capabilities(user_id, agent_id)

        # Financial sensitivity
        txn = get_transaction(transaction_id) if transaction_id else None
        merchant = get_merchant(merchant_id) if merchant_id else None
        fin_sens = financial_sensitivity(
            txn, merchant,
            requested_privileged=bool(requested & PRIVILEGED_CAPABILITIES),
        )

        # Trajectory bonus (pre-record uses existing trajectory)
        traj_bonus = self.trajectory.trajectory_risk_bonus(session_id, agent_id)

        # Multi-turn
        history = self.session_history.get(session_id, [])
        is_multi, multi_score = self.risk_scorer.detect_multi_turn_escalation(structured, history)
        behavioral = 0.2 if is_multi else 0.0
        if is_multi and AttackClass.MULTI_TURN_ESCALATION not in attack_classes:
            attack_classes.append(AttackClass.MULTI_TURN_ESCALATION)

        # 4. Contextual risk
        risk = self.risk_scorer.calculate_contextual_risk(
            structured,
            previous_risk=previous_risk,
            requested_capabilities=requested,
            financial_sensitivity=fin_sens,
            trajectory_bonus=traj_bonus,
            authority_escalation_detected=is_escalation or is_cap_esc,
            escalation_indicators=esc_indicators,
            behavioral_score=behavioral,
        )
        if is_multi:
            risk.score = min(1.0, max(risk.score, multi_score.score))

        # Merge attack classes onto risk
        for ac in attack_classes:
            if ac not in risk.attack_classes:
                risk.attack_classes.append(ac)

        # 5. Record trajectory + update agent risk state
        attack_vals = [ac.value for ac in risk.attack_classes if ac != AttackClass.NONE]
        traj = self.trajectory.record(
            session_id,
            risk.score,
            attack_classes=attack_vals,
            agent_id=agent_id,
            capability_requested=bool(requested),
        )
        trajectory_escalate = self.trajectory.should_escalate(session_id, agent_id)

        if agent_id and agent:
            self.agents.update_risk_state(agent_id, risk.score)
            granted = set(agent.current_permissions)

        self.session_risk[session_id] = risk.score

        # 6. Policy decision
        policy_result = self.policy.decide(
            risk_score=risk.score,
            attack_classes=risk.attack_classes,
            requested_capabilities=requested,
            allowed_capabilities=granted,
            untrusted_influence=untrusted_influence,
            trajectory_escalate=trajectory_escalate and risk.score >= 0.4,
            agent_isolated=bool(agent and agent.isolated),
        )

        decision: ExecutionDecision = policy_result["decision"]
        requires_hr = policy_result["requires_human_review"]
        explanation = policy_result["explanation"]
        allowed = policy_result["allowed_capabilities"] or (granted if decision == ExecutionDecision.ALLOW else set())

        # If capability self-grant: force DENY
        if is_cap_esc:
            decision = ExecutionDecision.DENY
            requires_hr = True
            policy_result["reason"] = (
                "User prompt cannot grant capabilities. Only SYSTEM/DEVELOPER policy can. "
                + policy_result["reason"]
            )

        human_review_id = None
        if requires_hr or decision in (
            ExecutionDecision.REQUIRE_HUMAN_REVIEW,
            ExecutionDecision.DENY,
            ExecutionDecision.BLOCK,
        ):
            if agent_id and decision in (
                ExecutionDecision.REQUIRE_HUMAN_REVIEW,
                ExecutionDecision.DENY,
                ExecutionDecision.BLOCK,
            ):
                frozen = self.agents.freeze_sensitive_capabilities(agent_id)

        # Audit
        provenance_label = "EXTERNAL_UNTRUSTED" if untrusted_influence else source
        event = self.audit.create_security_event(
            event_type=EventType.ATTACK_DETECTED if attack_vals else EventType.REQUEST_PROCESSED,
            risk_score=risk.score,
            previous_risk=previous_risk,
            new_risk=risk.score,
            decision=decision.value.upper(),
            reason=policy_result["reason"],
            policy_version=self.policy.version,
            agent_id=agent_id,
            session_id=session_id,
            user_id=user_id,
            attack_classes=attack_vals,
            provenance=provenance_label,
            requested_capability=next(iter(requested)).value if requested else None,
            metadata={"trajectory": traj.to_series()},
        )

        if decision == ExecutionDecision.REQUIRE_HUMAN_REVIEW or (
            requires_hr and decision != ExecutionDecision.ALLOW
        ):
            if agent_id:
                frozen = self.agents.freeze_sensitive_capabilities(agent_id)
            else:
                frozen = []
            review = self.human_review.request_human_review(
                agent_id=agent_id or "unknown",
                session_id=session_id,
                reason=policy_result["reason"],
                risk_score=risk.score,
                requested_capability=next(iter(requested)).value if requested else None,
                provenance=provenance_label,
                explanation=explanation.to_dict(),
                security_event_id=event.event_id,
                frozen_capabilities=frozen,
            )
            human_review_id = review["review_id"]
            self.audit.create_security_event(
                event_type=EventType.HUMAN_REVIEW_REQUESTED,
                risk_score=risk.score,
                previous_risk=previous_risk,
                new_risk=risk.score,
                decision="REQUIRE_HUMAN_REVIEW",
                reason=policy_result["reason"],
                policy_version=self.policy.version,
                agent_id=agent_id,
                session_id=session_id,
                user_id=user_id,
                attack_classes=attack_vals,
                provenance=provenance_label,
                requested_capability=next(iter(requested)).value if requested else None,
                metadata={"review_id": human_review_id},
            )

        # Update session history for multi-turn (even on block — attackers still probe)
        self.session_history.setdefault(session_id, []).append(structured)
        if len(self.session_history[session_id]) > 20:
            self.session_history[session_id] = self.session_history[session_id][-20:]

        self.capability_gate.cleanup_expired_grants()

        # Map BLOCK -> also expose as DENY-friendly decision string for API
        decision_str = decision.value.upper()
        if decision == ExecutionDecision.BLOCK:
            decision_str = "BLOCK"

        result = FARISDecision(
            decision=decision_str,
            risk_score=risk.score,
            risk_state=(agent.risk_state.value if agent else risk_score_to_state(risk.score).value),
            attack_classes=attack_vals,
            requested_capability=next(iter(requested)).value if requested else None,
            capability_granted=False if is_cap_esc else (
                decision in (ExecutionDecision.ALLOW, ExecutionDecision.ALLOW_DEGRADED)
            ),
            requires_human_review=requires_hr or decision == ExecutionDecision.REQUIRE_HUMAN_REVIEW,
            reason=policy_result["reason"],
            explanation=explanation.to_dict(),
            allowed_capabilities=sorted(c.value for c in allowed),
            trajectory=traj.to_series(),
            security_event_id=event.event_id,
            human_review_id=human_review_id,
        )
        return result.to_dict()

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_id: str,
        session_id: str,
        user_id: Optional[str] = None,
        untrusted_influence: bool = False,
    ) -> Dict[str, Any]:
        from tool_security import TOOL_CAPABILITY_MAP
        required = TOOL_CAPABILITY_MAP.get(tool_name, Capability.EXECUTE_TOOLS)
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=agent_id,
            session_id=session_id,
            required_capability=required,
            user_id=user_id,
        )
        agent = self.agents.get_agent(agent_id)
        risk = agent.current_risk_score if agent else self.session_risk.get(session_id, 0.0)
        decision = self.tools.evaluate_tool_call(
            request,
            risk_score=risk,
            untrusted_influence=untrusted_influence,
        )

        event = self.audit.create_security_event(
            event_type=EventType.TOOL_EVALUATED,
            risk_score=decision.risk_score,
            previous_risk=risk,
            new_risk=decision.risk_score,
            decision=decision.decision,
            reason=decision.reason,
            policy_version=self.policy.version,
            agent_id=agent_id,
            session_id=session_id,
            user_id=user_id,
            attack_classes=decision.attack_classes,
            provenance="tool_call",
            requested_capability=decision.requested_capability,
        )
        decision.security_event_id = event.event_id

        if decision.requires_human_review:
            review = self.human_review.request_human_review(
                agent_id=agent_id,
                session_id=session_id,
                reason=decision.reason,
                risk_score=decision.risk_score,
                requested_capability=decision.requested_capability,
                provenance="tool_call",
                explanation=decision.explanation,
                security_event_id=event.event_id,
                frozen_capabilities=self.agents.freeze_sensitive_capabilities(agent_id),
            )
            decision.human_review_id = review["review_id"]

        out = decision.to_dict()
        if decision.decision == "ALLOW":
            out["execution"] = self.tools.execute_if_allowed(request, decision)
        else:
            out["execution"] = {"executed": False}
        return out

    def calculate_risk(self, prompt_text: str, **kwargs) -> Dict[str, Any]:
        result = self.process_request(prompt_text, **kwargs)
        return {
            "risk_score": result["risk_score"],
            "risk_state": result["risk_state"],
            "attack_classes": result["attack_classes"],
            "trajectory": result.get("trajectory"),
            "components": result.get("explanation"),
        }

    def update_risk_state(self, agent_id: str, risk_score: float) -> Dict[str, Any]:
        agent = self.agents.update_risk_state(agent_id, risk_score)
        self.audit.create_security_event(
            event_type=EventType.RISK_UPDATED,
            risk_score=risk_score,
            previous_risk=0.0,
            new_risk=risk_score,
            decision="RISK_UPDATE",
            reason="Manual/post-execution risk update",
            policy_version=self.policy.version,
            agent_id=agent_id,
            session_id=agent.session_id,
            provenance="system",
        )
        return {
            "agent_id": agent_id,
            "risk_score": agent.current_risk_score,
            "risk_state": agent.risk_state.value,
            "permissions": sorted(c.value for c in agent.current_permissions),
            "isolated": agent.isolated,
        }

    def grant_capability(
        self,
        capability: Capability,
        granted_by: AuthorityLevel,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if granted_by not in (AuthorityLevel.SYSTEM, AuthorityLevel.DEVELOPER):
            return {
                "capability_granted": False,
                "decision": "DENY",
                "reason": "Only SYSTEM/DEVELOPER may grant capabilities",
            }
        grant_id = self.capability_gate.grant_capability(
            capability=capability,
            granted_by=granted_by,
            agent_id=agent_id,
            user_id=user_id,
        )
        if agent_id and self.agents.get_agent(agent_id):
            self.agents.get_agent(agent_id).allowed_capabilities.add(capability)
            self.agents.get_agent(agent_id).current_permissions.add(capability)
        self.audit.create_security_event(
            event_type=EventType.CAPABILITY_GRANTED,
            risk_score=0.0,
            previous_risk=0.0,
            new_risk=0.0,
            decision="GRANT",
            reason=f"Granted {capability.value} by {granted_by.name}",
            policy_version=self.policy.version,
            agent_id=agent_id,
            user_id=user_id,
            provenance="system_policy",
            requested_capability=capability.value,
        )
        return {"capability_granted": True, "grant_id": grant_id, "capability": capability.value}

    def revoke_capability(
        self,
        capability: Capability,
        agent_id: Optional[str] = None,
        grant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        ok = False
        if grant_id:
            ok = self.capability_gate.revoke_capability(grant_id)
        if agent_id:
            ok = self.capability_gate.revoke_capability_for_agent(agent_id, capability) or ok
            self.agents.revoke_capability(agent_id, capability)
        self.audit.create_security_event(
            event_type=EventType.CAPABILITY_REVOKED,
            risk_score=0.0,
            previous_risk=0.0,
            new_risk=0.0,
            decision="REVOKE",
            reason=f"Revoked {capability.value}",
            policy_version=self.policy.version,
            agent_id=agent_id,
            provenance="system_policy",
            requested_capability=capability.value,
        )
        return {"revoked": ok, "capability": capability.value}

    def create_security_event(self, **kwargs) -> Dict[str, Any]:
        event = self.audit.create_security_event(**kwargs)
        return event.to_dict()

    def request_human_review(self, **kwargs) -> Dict[str, Any]:
        return self.human_review.request_human_review(**kwargs)

    def dashboard_snapshot(self) -> Dict[str, Any]:
        """Aggregate state for the security dashboard."""
        risks = [a["risk_score"] for a in self.agents.list_agents()]
        overall = sum(risks) / len(risks) if risks else (
            sum(self.session_risk.values()) / len(self.session_risk) if self.session_risk else 0.0
        )
        tool_log = getattr(self.tools, "call_log", [])[-20:]

        # Prefer real trajectory series from tracker (keyed session::agent)
        sessions: Dict[str, Any] = {}
        for key, traj in self.trajectory.trajectories.items():
            sid = traj.session_id
            series = traj.to_series()
            sessions[sid] = {
                "risk": traj.current_risk(),
                "agent_id": traj.agent_id,
                "trajectory": {
                    "series": series,
                    "alerts": list(traj.trajectory_alerts),
                    "current_state": (
                        traj.points[-1].risk_state.value if traj.points else "low"
                    ),
                },
            }
        # Fallback for sessions with risk but no traj object yet
        for sid, risk in self.session_risk.items():
            if sid not in sessions:
                sessions[sid] = {
                    "risk": risk,
                    "trajectory": self.trajectory.snapshot(sid),
                }

        return {
            "overall_ai_risk": round(overall, 4),
            "active_agents": self.agents.list_agents(),
            "human_review_queue": self.human_review.pending()[:15],
            "human_reviews_all": self.human_review.all_reviews()[-20:],
            "audit_summary": self.audit.summary(),
            "recent_events": self.audit.list_events(limit=25),
            "sessions": dict(list(sessions.items())[:20]),
            "blocked_actions": [
                e for e in self.audit.list_events(limit=50)
                if e["decision"] in ("BLOCK", "DENY")
            ][-12:],
            "tool_calls": tool_log,
            "architecture": [
                "INPUT", "PROVENANCE", "ATTACK", "CONTEXTUAL RISK", "TRAJECTORY",
                "CAPABILITY", "TOOL GATE", "POLICY", "HITL", "RISK UPDATE",
            ],
            "authority_hierarchy": [
                "SYSTEM", "DEVELOPER", "USER", "EXTERNAL_UNTRUSTED"
            ],
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _tag_and_structure(
        self,
        prompt_text: str,
        user_id: Optional[str],
        session_id: Optional[str],
        source: str,
        external_content: Optional[List[str]],
    ) -> StructuredPrompt:
        segments = []
        user_segment = self.provenance_tracker.tag_user_input(prompt_text, user_id, session_id)
        segments.append(user_segment)
        external_segments = []
        if external_content:
            for ext_text in external_content:
                ext_segment = self.provenance_tracker.tag_external_content(ext_text)
                segments.append(ext_segment)
                external_segments.append(ext_text)
        return StructuredPrompt(
            segments=segments,
            user_input=[prompt_text],
            external_content=external_segments,
            full_text=prompt_text + (
                "\n" + "\n".join(external_segments) if external_segments else ""
            ),
        )


class AntiJailbreakPipeline:
    """
    Backward-compatible wrapper around the original five-stage pipeline.

    Prefer FARISPipeline for financial agent workflows.
    """

    def __init__(
        self,
        policy_config: Optional[Dict] = None,
        default_capabilities: Optional[List[Capability]] = None,
    ):
        self.authority_enforcer = AuthorityEnforcer()
        self.provenance_tracker = ProvenanceTracker()
        self.risk_scorer = RiskScoringEngine()
        self.capability_gate = CapabilityGate()
        self.execution_router = ExecutionRouter(policy_config)
        self.session_history: Dict[str, List[StructuredPrompt]] = {}
        if default_capabilities:
            for cap in default_capabilities:
                self.capability_gate.grant_capability(
                    capability=cap,
                    granted_by=AuthorityLevel.SYSTEM,
                )
        # Optional FARIS bridge
        self._faris = FARISPipeline(policy_config)

    def process(
        self,
        prompt_text: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source: str = "user_input",
        external_content: Optional[List[str]] = None,
        session_history_enabled: bool = True,
    ) -> ExecutionResult:
        structured_prompt = self._tag_and_structure(
            prompt_text, user_id, session_id, source, external_content
        )
        structured_prompt = self.authority_enforcer.enforce_hierarchy(structured_prompt)
        is_escalation, escalation_classes, escalation_indicators = \
            self.authority_enforcer.check_authority_escalation(structured_prompt)
        structured_prompt = self.provenance_tracker.enforce_data_vs_instruction_separation(
            structured_prompt
        )
        requested_capabilities = self.capability_gate.detect_capability_requests(structured_prompt)
        granted_capabilities = self.capability_gate.get_valid_capabilities(user_id)

        if session_history_enabled and session_id:
            history = self.session_history.get(session_id, [])
            is_multi_turn, risk_score = self.risk_scorer.detect_multi_turn_escalation(
                structured_prompt, history
            )
            if not is_multi_turn:
                risk_score = self.risk_scorer.score_risk(
                    structured_prompt,
                    authority_escalation_detected=is_escalation,
                    escalation_indicators=escalation_indicators,
                )
        else:
            risk_score = self.risk_scorer.score_risk(
                structured_prompt,
                authority_escalation_detected=is_escalation,
                escalation_indicators=escalation_indicators,
            )

        context = ExecutionContext(
            prompt=structured_prompt,
            risk_score=risk_score,
            requested_capabilities=requested_capabilities,
            granted_capabilities=granted_capabilities,
            user_id=user_id,
            session_id=session_id,
        )
        allowed_capabilities = self.capability_gate.enforce_capability_gating(context)
        context.granted_capabilities = allowed_capabilities
        result = self.execution_router.route(context)

        if session_history_enabled and session_id and \
           result.decision in [ExecutionDecision.ALLOW, ExecutionDecision.ALLOW_DEGRADED]:
            self.session_history.setdefault(session_id, []).append(structured_prompt)
            if len(self.session_history[session_id]) > 10:
                self.session_history[session_id] = self.session_history[session_id][-10:]

        self.capability_gate.cleanup_expired_grants()
        return result

    def _tag_and_structure(self, prompt_text, user_id, session_id, source, external_content):
        return self._faris._tag_and_structure(
            prompt_text, user_id, session_id, source, external_content
        )

    def get_audit_report(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "active_sessions": len(self.session_history),
            "provenance_audit": self.provenance_tracker.audit_provenance(
                StructuredPrompt(segments=[])
            ),
        }
        if session_id and session_id in self.session_history:
            report["session_history_length"] = len(self.session_history[session_id])
        return report

    def clear_session_history(self, session_id: Optional[str] = None):
        if session_id:
            self.session_history.pop(session_id, None)
        else:
            self.session_history.clear()
