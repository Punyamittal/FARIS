"""
Contextual Risk Scoring Engine for FARIS.

Prototype configurable model:

    risk = f(attack, provenance, behavioral, capability, financial_sensitivity, historical)

This is NOT a scientifically validated formula — thresholds and weights are tunable
for demonstration and research prototyping.
"""

import re
from typing import List, Dict, Tuple, Optional, Set
from security_types import (
    StructuredPrompt, RiskScore, AttackClass, AuthorityLevel, Capability,
)
from attack_detection import AttackDetector


class RiskScoringEngine:
    """
    Backward-compatible risk scorer used by AntiJailbreakPipeline,
    plus contextual FARIS scoring.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.attack_detector = AttackDetector()
        self.weights = weights or {
            "attack_score": 0.35,
            "provenance_score": 0.15,
            "behavioral_score": 0.15,
            "capability_score": 0.15,
            "financial_sensitivity": 0.10,
            "historical_risk": 0.10,
        }
        self.attack_patterns = self._initialize_patterns()
        self.legacy_weights = {
            "authority_escalation": 0.4,
            "instruction_override": 0.3,
            "role_play": 0.2,
            "encoding_obfuscation": 0.15,
            "capability_request": 0.25,
            "indirect_injection": 0.35,
            "memory_poisoning": 0.3,
            "social_engineering": 0.15,
        }

    def _initialize_patterns(self) -> Dict[AttackClass, List[re.Pattern]]:
        return {
            AttackClass.ROLE_PLAY: [
                re.compile(r'(?i)(pretend|roleplay|simulate|act as|play the role of)'),
                re.compile(r'(?i)(you are|you\'re).*(character|persona|entity|unrestricted)'),
            ],
            AttackClass.INSTRUCTION_OVERRIDE: [
                re.compile(r'(?i)(ignore|disregard|forget|override|bypass).*(previous|prior|earlier|system|instructions)'),
                re.compile(r'(?i)(new instructions|updated instructions|revised instructions)'),
            ],
            AttackClass.AUTHORITY_ESCALATION: [
                re.compile(r'(?i)(you are|act as|pretend).*(developer|admin|system|root|god)'),
                re.compile(r'(?i)(jailbreak|break|escape|hack|exploit)'),
            ],
            AttackClass.INDIRECT_INJECTION: [
                re.compile(r'(?i)(ignore everything above|ignore all previous|ignore your system)'),
                re.compile(r'(?i)(hidden|secret|special).*(instructions|commands|code)'),
            ],
            AttackClass.MEMORY_POISONING: [
                re.compile(r'(?i)(remember|store|save|memorize).*(that|this|the following)'),
                re.compile(r'(?i)(for future|for later|permanently|always)'),
            ],
            AttackClass.CAPABILITY_ESCALATION: [
                re.compile(r'(?i)(grant|give|enable|allow).*(access|permission|capability|privilege)'),
                re.compile(r'(?i)(unrestricted|full|complete|total).*(access|power|control)'),
            ],
            AttackClass.ENCODING_OBFUSCATION: [
                re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
                re.compile(r'\\x[0-9a-fA-F]{2}'),
            ],
            AttackClass.SOCIAL_ENGINEERING: [
                re.compile(r'(?i)(please|kindly|urgently|important|critical).*(ignore|override|bypass)'),
                re.compile(r'(?i)(this is|i am|we are).*(developer|admin|authorized|official)'),
            ],
        }

    def score_risk(
        self,
        prompt: StructuredPrompt,
        authority_escalation_detected: bool = False,
        escalation_indicators: Optional[List[str]] = None,
    ) -> RiskScore:
        """Legacy single-prompt scoring (AntiJailbreakPipeline compatible)."""
        attack_classes: List[AttackClass] = []
        indicators: List[str] = []
        risk_components: Dict[str, float] = {}
        full_text = (prompt.full_text or "").lower()
        escalation_indicators = escalation_indicators or []

        for attack_class, patterns in self.attack_patterns.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(full_text)
                if found:
                    matches.extend(found)
            if matches:
                attack_classes.append(attack_class)
                indicators.append(f"{attack_class.value}: {len(matches)} matches")
                weight = self.legacy_weights.get(attack_class.value, 0.1)
                risk_components[attack_class.value] = min(1.0, len(matches) * 0.2 * weight)

        if authority_escalation_detected:
            if AttackClass.AUTHORITY_ESCALATION not in attack_classes:
                attack_classes.append(AttackClass.AUTHORITY_ESCALATION)
            risk_components["authority_escalation"] = 0.8
            indicators.extend(escalation_indicators)

        for segment in prompt.segments:
            if segment.authority == AuthorityLevel.EXTERNAL_UNTRUSTED:
                if self._looks_like_instructions(segment.content):
                    if AttackClass.INDIRECT_INJECTION not in attack_classes:
                        attack_classes.append(AttackClass.INDIRECT_INJECTION)
                    risk_components["indirect_injection"] = (
                        risk_components.get("indirect_injection", 0) + 0.3
                    )
                    indicators.append("Untrusted content appears to contain instructions")

        findings = self.attack_detector.detect(prompt)
        for f in findings:
            if f.attack_class != AttackClass.NONE and f.attack_class not in attack_classes:
                attack_classes.append(f.attack_class)
                indicators.extend(f.indicators)

        if risk_components:
            max_risk = max(risk_components.values())
            avg_risk = sum(risk_components.values()) / len(risk_components)
            overall_score = min(1.0, max_risk * 0.6 + avg_risk * 0.4)
        else:
            overall_score = self.attack_detector.attack_score(findings)

        det_score = self.attack_detector.attack_score(findings)
        overall_score = min(1.0, max(overall_score, det_score))

        # Critical attack floors (prototype policy, not calibrated)
        critical = {
            AttackClass.AUTHORITY_ESCALATION,
            AttackClass.CAPABILITY_ESCALATION,
            AttackClass.JAILBREAK,
            AttackClass.DATA_EXFILTRATION,
            AttackClass.TOOL_MANIPULATION,
            AttackClass.POLICY_MANIPULATION,
        }
        if any(ac in critical for ac in attack_classes):
            overall_score = max(overall_score, 0.72)
        high = {
            AttackClass.INSTRUCTION_OVERRIDE,
            AttackClass.INDIRECT_INJECTION,
            AttackClass.PROMPT_INJECTION,
            AttackClass.MALICIOUS_DOCUMENT,
            AttackClass.MALICIOUS_WEBPAGE,
        }
        if any(ac in high for ac in attack_classes):
            overall_score = max(overall_score, 0.55)

        confidence = min(1.0, len(indicators) * 0.2) if indicators else 0.0
        if not attack_classes:
            attack_classes = [AttackClass.NONE]

        return RiskScore(
            score=overall_score,
            attack_classes=attack_classes,
            confidence=confidence,
            indicators=indicators,
            reasoning=self._generate_reasoning(attack_classes, indicators, risk_components),
            components=risk_components,
        )

    def calculate_contextual_risk(
        self,
        prompt: StructuredPrompt,
        *,
        previous_risk: float = 0.0,
        requested_capabilities: Optional[Set[Capability]] = None,
        financial_sensitivity: float = 0.0,
        trajectory_bonus: float = 0.0,
        authority_escalation_detected: bool = False,
        escalation_indicators: Optional[List[str]] = None,
        behavioral_score: float = 0.0,
    ) -> RiskScore:
        """
        Contextual risk for FARIS closed-loop control.

        Prototype (not scientifically validated):
            risk ≈ weighted_sum(components) blended with max(component) + trajectory_bonus
        """
        base = self.score_risk(
            prompt,
            authority_escalation_detected=authority_escalation_detected,
            escalation_indicators=escalation_indicators or [],
        )
        attack_score = base.score

        untrusted_segs = [
            s for s in prompt.segments if s.authority == AuthorityLevel.EXTERNAL_UNTRUSTED
        ]
        provenance_score = 0.0
        if untrusted_segs:
            provenance_score = 0.35
            if any(self._looks_like_instructions(s.content) for s in untrusted_segs):
                provenance_score = 0.75

        requested_capabilities = requested_capabilities or set()
        privileged = {
            Capability.MODIFY_RISK_STATUS, Capability.APPROVE_ACTION,
            Capability.EXECUTE_FINANCIAL_ACTION, Capability.EXPORT_DATA,
            Capability.ACCESS_SYSTEM_INFO,
        }
        if requested_capabilities & privileged:
            capability_score = 0.7
        elif requested_capabilities:
            capability_score = 0.25
        else:
            capability_score = 0.0

        components = {
            "attack_score": attack_score,
            "provenance_score": provenance_score,
            "behavioral_score": behavioral_score,
            "capability_score": capability_score,
            "financial_sensitivity": financial_sensitivity,
            "historical_risk": previous_risk,
        }

        weighted = sum(components[k] * self.weights[k] for k in self.weights)
        max_c = max(components.values()) if components else 0.0
        combined = min(1.0, weighted * 0.75 + max_c * 0.25 + trajectory_bonus)
        combined = min(1.0, max(combined, previous_risk * 0.5 + combined * 0.5))

        # Preserve critical/high floors from base detection
        critical = {
            AttackClass.AUTHORITY_ESCALATION, AttackClass.CAPABILITY_ESCALATION,
            AttackClass.JAILBREAK, AttackClass.DATA_EXFILTRATION,
            AttackClass.TOOL_MANIPULATION, AttackClass.POLICY_MANIPULATION,
        }
        high = {
            AttackClass.INSTRUCTION_OVERRIDE, AttackClass.INDIRECT_INJECTION,
            AttackClass.PROMPT_INJECTION, AttackClass.MALICIOUS_DOCUMENT,
            AttackClass.MALICIOUS_WEBPAGE,
        }
        if any(ac in critical for ac in base.attack_classes):
            combined = max(combined, 0.72)
        elif any(ac in high for ac in base.attack_classes):
            combined = max(combined, 0.55)

        return RiskScore(
            score=round(combined, 4),
            attack_classes=base.attack_classes,
            confidence=base.confidence,
            indicators=base.indicators + [
                f"contextual:{k}={v:.2f}" for k, v in components.items() if v > 0
            ],
            reasoning=(
                f"Prototype contextual risk={combined:.2f} from weighted components "
                f"(not a validated scientific model). {base.reasoning}"
            ),
            components=components,
        )

    def _looks_like_instructions(self, text: str) -> bool:
        instruction_indicators = [
            'you should', 'you must', 'you will', 'you are to',
            'do this', 'execute', 'perform', 'follow',
            'ignore', 'disregard', 'remember', 'store', 'approve', 'grant'
        ]
        text_lower = text.lower()
        return sum(1 for indicator in instruction_indicators if indicator in text_lower) >= 2

    def _generate_reasoning(
        self,
        attack_classes: List[AttackClass],
        indicators: List[str],
        risk_components: Dict[str, float],
    ) -> str:
        if not attack_classes or attack_classes == [AttackClass.NONE]:
            return "No attack patterns detected. Low risk."
        parts = [
            f"Detected {len(attack_classes)} attack class(es): "
            f"{', '.join(ac.value for ac in attack_classes)}."
        ]
        if indicators:
            parts.append(f"Key indicators: {indicators[0]}")
        return " ".join(parts)

    def detect_multi_turn_escalation(
        self,
        current_prompt: StructuredPrompt,
        session_history: List[StructuredPrompt],
    ) -> Tuple[bool, RiskScore]:
        if not session_history:
            return False, RiskScore(
                score=0.0,
                attack_classes=[AttackClass.NONE],
                confidence=0.0,
            )

        recent_history = session_history[-3:]
        combined_text = " ".join(
            [p.full_text for p in recent_history] + [current_prompt.full_text]
        )
        temp_prompt = StructuredPrompt(
            segments=current_prompt.segments,
            full_text=combined_text,
        )

        escalation_indicators: List[str] = []
        role_setup = any(
            any(p in (h.full_text or "").lower() for p in ['pretend', 'roleplay', 'act as'])
            for h in recent_history
        )
        action_request = any(
            p in (current_prompt.full_text or "").lower()
            for p in ['ignore', 'override', 'execute', 'perform', 'grant', 'approve']
        )

        if role_setup and action_request:
            escalation_indicators.append("Multi-turn: role setup followed by action request")
            risk_score = self.score_risk(
                temp_prompt,
                authority_escalation_detected=True,
                escalation_indicators=escalation_indicators,
            )
            if AttackClass.MULTI_TURN_ESCALATION not in risk_score.attack_classes:
                risk_score.attack_classes.append(AttackClass.MULTI_TURN_ESCALATION)
            return True, risk_score

        memory_commands = sum(
            1 for h in recent_history
            if any(p in (h.full_text or "").lower() for p in ['remember', 'store', 'memorize'])
        )
        if memory_commands >= 2:
            escalation_indicators.append("Multi-turn: repeated memory manipulation attempts")
            risk_score = self.score_risk(
                temp_prompt,
                escalation_indicators=escalation_indicators,
            )
            risk_score.attack_classes.append(AttackClass.MULTI_TURN_ESCALATION)
            risk_score.score = min(1.0, risk_score.score + 0.2)
            return True, risk_score

        grant_turns = sum(
            1 for h in recent_history
            if 'grant' in (h.full_text or "").lower() or 'permission' in (h.full_text or "").lower()
        )
        if grant_turns >= 1 and action_request:
            escalation_indicators.append("Multi-turn: capability probing then action")
            risk_score = self.score_risk(temp_prompt, escalation_indicators=escalation_indicators)
            risk_score.attack_classes.append(AttackClass.MULTI_TURN_ESCALATION)
            risk_score.score = min(1.0, risk_score.score + 0.15)
            return True, risk_score

        return False, self.score_risk(current_prompt)
