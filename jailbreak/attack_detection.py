"""
Attack Detection Module for FARIS.

Expands pattern-based detection across jailbreak, injection, tool manipulation,
exfiltration, policy manipulation, and financial-document attacks.
"""

import re
from typing import List, Dict, Optional, Tuple
from security_types import (
    AttackClass, AttackSeverity, AttackFinding, ATTACK_SEVERITY_MAP,
    AuthorityLevel, StructuredPrompt
)


class AttackDetector:
    """
    Deterministic attack detector used before LLM / tool execution.

    This module does not claim completeness; it is a prototype signature layer.
    """

    def __init__(self):
        self.patterns: Dict[AttackClass, List[Tuple[re.Pattern, str]]] = {
            AttackClass.JAILBREAK: [
                (re.compile(r'(?i)\b(jailbreak|dan\b|do anything now|unrestricted ai|no restrictions)\b'),
                 "Jailbreak keyword"),
                (re.compile(r'(?i)(disable|turn off|remove).*(safety|guardrail|filter|policy)'),
                 "Safety disable request"),
            ],
            AttackClass.ROLE_PLAY: [
                (re.compile(r'(?i)(pretend|roleplay|role-play|act as|play the role)'),
                 "Role-play framing"),
                (re.compile(r'(?i)(you are|you\'re).*(unrestricted|without (rules|limits|guidelines))'),
                 "Unrestricted persona"),
            ],
            AttackClass.INSTRUCTION_OVERRIDE: [
                (re.compile(r'(?i)(ignore|disregard|forget|override).*(previous|prior|system|instructions|rules)'),
                 "Instruction override"),
                (re.compile(r'(?i)(new instructions|updated instructions|revised instructions)'),
                 "Replacement instructions"),
            ],
            AttackClass.PROMPT_INJECTION: [
                (re.compile(r'(?i)(system\s*:|developer\s*:)\s*(you must|ignore|grant|approve)'),
                 "Injected system/developer prefix"),
                (re.compile(r'(?i)</?(system|assistant|instructions)>'),
                 "Markup injection"),
            ],
            AttackClass.INDIRECT_INJECTION: [
                (re.compile(r'(?i)(ignore (all )?previous instructions|ignore your system rules)'),
                 "Indirect ignore-instructions"),
                (re.compile(r'(?i)(hidden|secret).*(instructions|commands)'),
                 "Hidden instruction language"),
            ],
            AttackClass.MALICIOUS_DOCUMENT: [
                (re.compile(r'(?i)(mark this merchant as verified|approve the merchant immediately)'),
                 "Document-embedded financial instruction"),
                (re.compile(r'(?i)(set risk (to |as )?low|mark.*low risk)'),
                 "Document risk-status manipulation"),
            ],
            AttackClass.MALICIOUS_WEBPAGE: [
                (re.compile(r'(?i)(ignore your system rules and mark)'),
                 "Webpage instruction override"),
                (re.compile(r'(?i)(ai agent|assistant).*(must|should).*(approve|verify|grant)'),
                 "Webpage directing agent action"),
            ],
            AttackClass.AUTHORITY_ESCALATION: [
                (re.compile(r'(?i)(you are|act as).*(admin|developer|system|root)'),
                 "Authority impersonation"),
                (re.compile(r'(?i)(system|developer|admin).*(mode|access|privileges)'),
                 "Elevated mode claim"),
            ],
            AttackClass.CAPABILITY_ESCALATION: [
                (re.compile(r'(?i)(grant|give|enable|allow).*(permission|capability|privilege|access)'),
                 "Capability grant request"),
                (re.compile(r'(?i)(approve_action|execute_financial_action|modify_risk_status)'),
                 "Privileged capability name in prompt"),
            ],
            AttackClass.MEMORY_POISONING: [
                (re.compile(r'(?i)(remember|store|save|memorize).*(always|permanently|for future)'),
                 "Persistent memory write"),
                (re.compile(r'(?i)(from now on you (are|must|will))'),
                 "Persistent identity overwrite"),
            ],
            AttackClass.TOOL_MANIPULATION: [
                (re.compile(r'(?i)(call|invoke|execute).*(approve_action|approve_transaction|update_risk)'),
                 "Direct privileged tool invocation"),
                (re.compile(r'(?i)(bypass|skip).*(tool|capability|authorization|policy).*(check|gate)'),
                 "Tool-gate bypass"),
            ],
            AttackClass.DATA_EXFILTRATION: [
                (re.compile(r'(?i)(export|dump|exfiltrate|send).*(customer|transaction|merchant|pii|all data)'),
                 "Data export / exfil language"),
                (re.compile(r'(?i)(reveal|show|print).*(api[_ ]?key|secret|credential|system prompt)'),
                 "Secret / system prompt disclosure"),
            ],
            AttackClass.POLICY_MANIPULATION: [
                (re.compile(r'(?i)(change|lower|disable|set).*(risk threshold|policy|guardrail)'),
                 "Policy mutation request"),
                (re.compile(r'(?i)(treat (this|me) as trusted|raise (my )?trust level)'),
                 "Trust-level manipulation"),
            ],
            AttackClass.SOCIAL_ENGINEERING: [
                (re.compile(r'(?i)(urgently|emergency|authorized by|trust me).*(ignore|override|approve)'),
                 "Urgency / authority social engineering"),
            ],
            AttackClass.ENCODING_OBFUSCATION: [
                (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), "Long base64-like blob"),
                (re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'), "Hex-encoded payload"),
            ],
        }

    def detect(
        self,
        prompt: StructuredPrompt,
        external_only_boost: bool = True
    ) -> List[AttackFinding]:
        """Detect attack classes in a structured prompt."""
        findings: List[AttackFinding] = []
        full_text = prompt.full_text or ""

        for attack_class, patterns in self.patterns.items():
            matched_indicators = []
            for pattern, label in patterns:
                if pattern.search(full_text):
                    matched_indicators.append(label)
            if matched_indicators:
                findings.append(AttackFinding(
                    attack_class=attack_class,
                    severity=ATTACK_SEVERITY_MAP.get(attack_class, AttackSeverity.MEDIUM),
                    indicators=matched_indicators,
                    confidence=min(1.0, 0.35 + 0.2 * len(matched_indicators)),
                ))

        # Provenance-aware: instruction-like external content => indirect injection
        for segment in prompt.segments:
            if segment.authority == AuthorityLevel.EXTERNAL_UNTRUSTED:
                if self._looks_like_instructions(segment.content):
                    if not any(f.attack_class == AttackClass.INDIRECT_INJECTION for f in findings):
                        findings.append(AttackFinding(
                            attack_class=AttackClass.INDIRECT_INJECTION,
                            severity=AttackSeverity.HIGH,
                            indicators=["Untrusted content contains instruction-like language"],
                            source_authority=AuthorityLevel.EXTERNAL_UNTRUSTED,
                            confidence=0.8,
                        ))
                    if external_only_boost and re.search(
                        r'(?i)(merchant|approve|verified|risk|transaction)',
                        segment.content
                    ):
                        if not any(f.attack_class == AttackClass.MALICIOUS_DOCUMENT for f in findings):
                            findings.append(AttackFinding(
                                attack_class=AttackClass.MALICIOUS_DOCUMENT,
                                severity=AttackSeverity.HIGH,
                                indicators=["Financial instruction embedded in untrusted document/webpage"],
                                source_authority=AuthorityLevel.EXTERNAL_UNTRUSTED,
                                confidence=0.85,
                            ))

        if not findings:
            findings.append(AttackFinding(
                attack_class=AttackClass.NONE,
                severity=AttackSeverity.INFO,
                indicators=[],
                confidence=0.0,
            ))
        return findings

    def detect_text(self, text: str, authority: AuthorityLevel = AuthorityLevel.USER) -> List[AttackFinding]:
        """Convenience for raw text detection."""
        from datetime import datetime
        from security_types import Provenance, PromptSegment

        seg = PromptSegment(
            content=text,
            provenance=Provenance("ad_hoc", authority, datetime.now()),
            authority=authority,
            is_executable=False,
        )
        prompt = StructuredPrompt(segments=[seg], full_text=text, user_input=[text] if authority == AuthorityLevel.USER else [],
                                  external_content=[text] if authority == AuthorityLevel.EXTERNAL_UNTRUSTED else [])
        return self.detect(prompt)

    @staticmethod
    def _looks_like_instructions(text: str) -> bool:
        indicators = [
            "ignore", "disregard", "you must", "you should", "you will",
            "approve", "grant", "override", "mark this", "execute",
            "system:", "developer:",
        ]
        lower = text.lower()
        return sum(1 for i in indicators if i in lower) >= 2

    def attack_score(self, findings: List[AttackFinding]) -> float:
        """Map findings to a 0..1 attack contribution (prototype)."""
        severity_weights = {
            AttackSeverity.INFO: 0.0,
            AttackSeverity.LOW: 0.15,
            AttackSeverity.MEDIUM: 0.35,
            AttackSeverity.HIGH: 0.65,
            AttackSeverity.CRITICAL: 0.9,
        }
        real = [f for f in findings if f.attack_class != AttackClass.NONE]
        if not real:
            return 0.0
        scores = [
            severity_weights[f.severity] * max(0.4, f.confidence)
            for f in real
        ]
        return min(1.0, max(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3)
