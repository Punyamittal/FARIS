"""
Authority & Instruction Hierarchy Enforcement.

Enforces immutable hierarchy SYSTEM > DEVELOPER > USER > EXTERNAL_UNTRUSTED
and detects authority escalation attempts.
"""

import re
from typing import List, Tuple
from security_types import (
    AuthorityLevel, StructuredPrompt, PromptSegment, AttackClass
)


class AuthorityEnforcer:
    """
    Enforces immutable instruction hierarchy.

    Lower authority content can never override higher authority instructions.
    Escalation attempts are neutralized (marked data-only) and flagged.
    """

    def __init__(self):
        self.escalation_patterns = [
            (re.compile(r'(?i)(ignore|disregard|forget|override|bypass).*(previous|prior|earlier|system|developer|instructions|rules|guidelines)'),
             "Instruction override attempt"),
            (re.compile(r'(?i)(you are now|act as|pretend you are).*(system|developer|admin|root|god mode)'),
             "Authority impersonation"),
            (re.compile(r'(?i)(system\s*:|developer\s*:|admin\s*:).*(grant|allow|enable|override)'),
             "Forged system/developer directive"),
            (re.compile(r'(?i)(jailbreak|DAN|do anything now|developer mode|unrestricted mode)'),
             "Jailbreak / unrestricted mode claim"),
            (re.compile(r'(?i)(your new|updated|revised).*(system|developer).*(prompt|instructions)'),
             "Attempt to replace system instructions"),
            (re.compile(r'(?i)(from now on|henceforth).*(ignore|disregard).*(safety|policy|rules)'),
             "Persistent policy override attempt"),
        ]

    def enforce_hierarchy(self, prompt: StructuredPrompt) -> StructuredPrompt:
        """
        Enforce hierarchy: untrusted/user content cannot become executable
        instructions that override system/developer policies.
        """
        for segment in prompt.segments:
            if segment.authority in (AuthorityLevel.USER, AuthorityLevel.EXTERNAL_UNTRUSTED):
                # Never executable as authority-bearing instructions
                segment.is_executable = False
            elif segment.authority in (AuthorityLevel.SYSTEM, AuthorityLevel.DEVELOPER):
                segment.is_executable = True

        # Partition content lists for clarity
        prompt.system_instructions = [
            s.content for s in prompt.segments if s.authority == AuthorityLevel.SYSTEM
        ]
        prompt.developer_policies = [
            s.content for s in prompt.segments if s.authority == AuthorityLevel.DEVELOPER
        ]
        prompt.user_input = [
            s.content for s in prompt.segments if s.authority == AuthorityLevel.USER
        ]
        prompt.external_content = [
            s.content for s in prompt.segments
            if s.authority == AuthorityLevel.EXTERNAL_UNTRUSTED
        ]
        return prompt

    def check_authority_escalation(
        self,
        prompt: StructuredPrompt
    ) -> Tuple[bool, List[AttackClass], List[str]]:
        """
        Detect authority escalation / jailbreak / override attempts.

        Returns:
            (is_escalation, attack_classes, indicators)
        """
        indicators: List[str] = []
        classes: List[AttackClass] = []
        text = prompt.full_text or ""

        for pattern, label in self.escalation_patterns:
            if pattern.search(text):
                indicators.append(label)

        # External content claiming to be system instructions is critical
        for segment in prompt.segments:
            if segment.authority == AuthorityLevel.EXTERNAL_UNTRUSTED:
                if re.search(
                    r'(?i)(ignore|override|system|developer|grant|approve|mark as)',
                    segment.content
                ):
                    indicators.append(
                        "EXTERNAL_UNTRUSTED content contains authority-bearing language"
                    )

        if indicators:
            classes.append(AttackClass.AUTHORITY_ESCALATION)
            # Classify jailbreak if role/unrestricted language present
            if any("Jailbreak" in i or "unrestricted" in i.lower() for i in indicators):
                classes.append(AttackClass.JAILBREAK)
            if any("override" in i.lower() or "Instruction override" in i for i in indicators):
                classes.append(AttackClass.INSTRUCTION_OVERRIDE)
            return True, classes, indicators

        return False, [], []

    def neutralize_escalation(self, prompt: StructuredPrompt) -> StructuredPrompt:
        """Mark all non-SYSTEM/DEVELOPER segments as non-executable data."""
        for segment in prompt.segments:
            if segment.authority not in (AuthorityLevel.SYSTEM, AuthorityLevel.DEVELOPER):
                segment.is_executable = False
        return prompt
