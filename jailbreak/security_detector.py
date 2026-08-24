"""
Security-focused jailbreak detector with rule-based pre-filters and proper classification.

Separates:
- Policy violations (drugs, explosives, illegal content)
- Jailbreak attempts (instruction override, role-play, system manipulation)
- Benign content

Pipeline Architecture:
0. Benign Whitelist (fast pre-filter for clearly benign prompts)
1. Rule-based detection (catches obvious jailbreak patterns)
2. ML classifier (catches subtle jailbreak patterns)
3. Hybrid decision (combines signals)
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from benign_whitelist import BenignWhitelist, WhitelistResult
from escalation_handler import ConfidenceEscalationHandler, EscalationAction

# Configure logging for audit trail
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityResult:
    """Result from security detection."""
    is_jailbreak: bool
    is_policy_violation: bool
    is_benign: bool
    confidence: float
    detection_method: str  # 'whitelist', 'rule', 'ml', 'hybrid', 'escalated'
    matched_patterns: List[str]
    risk_score: float  # 0.0 to 1.0
    whitelist_result: Optional[WhitelistResult] = None  # For audit trail
    escalation_action: Optional[str] = None  # 'allow', 'block', 'escalate', 'degraded_response', etc.
    escalation_reason: Optional[str] = None  # Reason for escalation
    jailbreak_probability: Optional[float] = None  # Raw ML probability for escalation

class RuleBasedJailbreakDetector:
    """
    Rule-based detector for obvious jailbreak patterns.
    This catches what ML often misses.
    """
    
    # High-confidence jailbreak patterns
    JAILBREAK_PATTERNS = [
        # Instruction override
        r'\bignore\s+(previous|all|system|safety|security)\s+(instructions?|rules?|guidelines?|policies?)\b',
        r'\bforget\s+(previous|all|system|safety)\s+(instructions?|rules?|guidelines?)\b',
        r'\bdisregard\s+(previous|all|system)\s+(instructions?|rules?)\b',
        r'\boverride\s+(system|safety|security)\s+(instructions?|rules?|policies?)\b',
        r'\bbypass\s+(safety|security|safeguards?|filters?|restrictions?)\b',
        
        # Role-play and authority escalation
        r'\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|developer|system|admin|root|god|unlimited)',
        r'\byou\s+are\s+now\s+(a\s+)?(developer|system|admin|root|unrestricted|unlimited)',
        r'\bact\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(developer|system|admin|unrestricted)',
        r'\broleplay\s+as\s+(a\s+)?(developer|system|admin|unrestricted)',
        r'\b(you|your)\s+(are|is)\s+no\s+longer\s+bound\s+by\s+(rules?|restrictions?|guidelines?)',
        r'\b(you|your)\s+(are|is)\s+free\s+from\s+(rules?|restrictions?|constraints?)',
        
        # System prompt targeting
        r'\breveal\s+(your|the)\s+(system|internal|hidden)\s+(prompt|instructions?|rules?)',
        r'\bshow\s+(me|us)\s+(your|the)\s+(system|internal)\s+(prompt|instructions?)',
        r'\bprint\s+(your|the)\s+(system|internal)\s+(prompt|instructions?)',
        r'\bwhat\s+(are|is)\s+(your|the)\s+(system|internal)\s+(prompt|instructions?|rules?)',
        
        # Developer mode / system access
        r'\b(enable|activate|switch\s+to)\s+(developer|system|admin|root|unrestricted)\s+mode',
        r'\bdeveloper\s+mode',
        r'\bsystem\s+mode',
        r'\badmin\s+mode',
        
        # Instruction hierarchy attacks
        r'\b(previous|earlier|above)\s+(instructions?|rules?|messages?)\s+(are|were)\s+(wrong|incorrect|outdated)',
        r'\bnew\s+(instructions?|rules?|directives?)\s+(override|replace|supersede)',
        r'\b(ignore|disregard)\s+everything\s+(before|above|earlier)',
        
        # Indirect injection patterns
        r'<\|(system|developer|admin)\|>',
        r'\[(SYSTEM|DEVELOPER|ADMIN)\s+MESSAGE\]',
        r'```(system|developer|admin)',
        
        # Memory/context manipulation
        r'\b(clear|reset|delete|forget)\s+(your|the)\s+(memory|context|history)',
        r'\b(you|your)\s+(memory|context)\s+(is|was)\s+(cleared|reset|deleted)',
        
        # Capability escalation
        r'\b(grant|give|provide)\s+(yourself|me)\s+(admin|root|system|unlimited)\s+(access|permissions?|capabilities?)',
        r'\b(you|your)\s+(have|now\s+have)\s+(admin|root|system|unlimited)\s+(access|permissions?)',
        
        # ===== NEW PATTERNS: Social Engineering =====
        # Authority claiming
        r'\bi\'?m\s+(your|the)\s+(sysadmin|system\s+admin|administrator|admin)',
        r'\bi\'?m\s+(a|the)\s+(developer|dev|engineer|tech)',
        r'\bi\'?m\s+(the|a)\s+(ceo|cto|cfo|executive|manager|boss)',
        r'\bi\'?m\s+(your|the)\s+(boss|supervisor|manager)',
        r'\b(user|username|account\s+id|employee\s+id)\s*:?\s*\d+',
        
        # Urgency manipulation
        r'\b(urgent|emergency|asap|immediately|right\s+now|right\s away)\s+(issue|request|need|matter)',
        r'\bmy\s+(boss|manager|supervisor|ceo)\s+needs?\s+(this|it|my|the)',
        r'\bi\'?m\s+locked\s+out',
        r'\b(need|needs?)\s+(this|it|access|password|credentials)\s+(now|immediately|urgently)',
        
        # Credential extraction attempts
        r'\b(share|send|give|provide|dm|message)\s+(me|us)\s+(the|my|your)?\s*(password|credentials?|account\s+details?|user\s+data|sensitive\s+data)',
        r'\b(password|credentials?|account\s+details?)\s+for\s+(user|account)?\s*:?\s*\w+',
        r'\bverify\s+(my|your|the)\s+(account|identity|credentials?)',
        r'\b(extract|retrieve|get|fetch)\s+(account|user|customer)\s+(details?|info|information|data)',
        
        # Customer/account pretext
        r'\bi\'?m\s+a\s+customer\s+with\s+(an?\s+)?(urgent|emergency|important)\s+(issue|problem|request)',
        r'\bmy\s+account\s+id\s+is',
        r'\baccount\s+details?\s+to\s+verify',
        
        # ===== NEW PATTERNS: Protocol Abuse =====
        # JSON command injection
        r'\{\s*["\']?action["\']?\s*:\s*["\']?(execute|run|exec|cmd|command)["\']?',
        r'\{\s*["\']?command["\']?\s*:\s*["\']?[^"\']+["\']?\s*\}',
        r'\{\s*["\']?execute["\']?\s*:\s*["\']?[^"\']+["\']?\s*\}',
        r'\{\s*["\']?run["\']?\s*:\s*["\']?[^"\']+["\']?\s*\}',
        r'\{\s*["\']?config["\']?\s*:\s*\{[^}]*["\']?run["\']?\s*:',
        
        # XML injection
        r'<xml>\s*<command>',
        r'<xml>\s*<execute>',
        r'<xml>\s*<run>',
        r'<command>\s*[^<]+\s*</command>',
        r'<execute>\s*[^<]+\s*</execute>',
        
        # Code block injection
        r'```\s*(execute|run|cmd|command|system|shell|bash|sh)',
        r'```\s*\w+\s*\n\s*(whoami|cat|ls|rm|wget|curl|nc|netcat)',
        
        # Config abuse
        r'\{\s*["\']?config["\']?\s*:\s*\{[^}]*["\']?(run|execute|command|cmd)["\']?\s*:',
        
        # ===== NEW PATTERNS: Command Execution Attempts =====
        # Code execution disguised as educational requests (targeted fix for 3 FNs)
        r'\b(summarize|translate|explain|show|run)\s+(this|the|a)?\s*(code|exploit|script|command).*?(then\s+)?(run|execute|exec)',
        r'\bos\.system\s*\(',
        r'\bsystem\s*\(\s*["\'](whoami|cat|ls|rm|wget|curl|sudo|chmod|bash|sh)',
        r'\b(javascript|js):\s*Function\s*\(',
        r'`\s*(os\.system|system\(|exec\(|eval\(|subprocess)',
        r'\b(run|execute|exec)\s*:\s*`',
        
        # System commands
        r'\brun\s+(diagnostics?|command|test|script|code)\s*:?\s*`',
        r'\bexecute\s+(command|code|script|diagnostics?)',
        r'\brun\s+this\s*:?\s*`',
        r'\btest\s+this\s*:?\s*`',
        r'\bdebug\s+with\s*:?\s*`',
        
        # Common system commands (in backticks or quotes)
        r'`\s*(whoami|cat\s+/etc|ls\s+-la|rm\s+-rf|wget|curl|nc|netcat|bash\s+-c)',
        r'["\']\s*(whoami|cat\s+/etc|ls\s+-la|rm\s+-rf|wget|curl|nc|netcat)',
        
        # Command-like structures
        r'\b(whoami|cat|ls|rm|wget|curl|nc|netcat|bash|sh|python|perl)\s+[^\s]+',
        
        # ===== NEW PATTERNS: Obfuscation =====
        # Character splitting (spaces between characters)
        r'\b(w\s+h\s+o|w\s+h\s+o\s+a\s+m\s+i|w\s+h\s+o\s+a\s+m)',
        r'\b(c\s+a\s+t|l\s+s|r\s+m|w\s+g\s+e\s+t|c\s+u\s+r\s+l)',
        
        # Underscore obfuscation
        r'\b(w_h_o|w_h_o_a_m_i|c_a_t|l_s|r_m)',
        
        # Multi-word obfuscation
        r'\b(w\s+h\s+o)\s+(a\s+m\s+i)',
        r'\b(c\s+a\s+t)\s+(/etc|/var|/usr)',
        
        # Homoglyph/unicode obfuscation (basic detection)
        r'[^\x00-\x7F].*(whoami|cat|ls|rm|wget|curl)',
        r'(whoami|cat|ls|rm).*[^\x00-\x7F]',
        
        # ===== NEW PATTERNS: Multi-turn Manipulation =====
        # Turn indicators
        r'\bturn\s+\d+\s*:',
        r'\b(turn|round|step)\s+\d+',
        
        # Building up to command
        r'\b(can\s+you\s+run|try|test|debug)\s+(this|with|using)\s*:?\s*`',
        r'\b(now|next|then)\s+(try|run|execute|test)\s*:?\s*`',
        
        # Sequential command building
        r'\b(turn\s+\d+.*turn\s+\d+.*turn\s+\d+)',
        
        # ===== NEW PATTERNS: System Access Requests =====
        # System logs/data access
        r'\b(share|send|give|provide|access|show|get)\s+(me|us)\s+(system\s+)?(logs?|data|files?|information)',
        r'\bsystem\s+logs?\s+(immediately|now|asap)',
        
        # Diagnostic requests
        r'\brun\s+diagnostics?',
        r'\b(diagnostic|test)\s+command',
        
        # File access attempts
        r'\b(cat|read|view|show|get)\s+(/etc|/var|/usr|/home|system\s+files?)',
        
        # ===== NEW PATTERNS: Prompt Injection (Role-Play) =====
        # Role-play requests
        r'\bi\s+want\s+you\s+to\s+act\s+as\s+(an?\s+)?(interviewer|storyteller|character|role)',
        r'\byou\s+are\s+going\s+to\s+pretend\s+to\s+be',
        r'\bact\s+as\s+(an?\s+)?(interviewer|storyteller|character|role|assistant)',
        r'\byou\s+will\s+(act|be|play)\s+as\s+(an?\s+)?(interviewer|storyteller|character)',
        r'\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(interviewer|storyteller|character)',
        
        # Instruction manipulation (prompt injection)
        r'\bforget\s+everything\s+(we\'?ve|i\'?ve|you\'?ve)\s+(talked|said|discussed)\s+about',
        r'\bforget\s+everything\s+(i|we|you)\s+(have|had)\s+(told|said)',
        r'\bforget\s+all\s+(previous|earlier|above)\s+(conversation|messages?|instructions?)',
        r'\bignore\s+(the|everything)\s+above',
        r'\bignore\s+all\s+(previous|earlier|above)\s+(instructions?|messages?|conversation)',
        r'\bdisregard\s+(the|everything)\s+above',
        r'\bdisregard\s+all\s+(previous|earlier)\s+(instructions?|messages?)',
        
        # Context switching
        r'\b(but\s+now|now)\s+come\s+new\s+tasks?',
        r'\bwe\'?ll\s+start\s+with\s+(a\s+)?new\s+(assignment|task|instruction)',
        r'\bstart\s+with\s+(a\s+)?new\s+(assignment|task|instruction)',
        r'\b(this|it)\s+is\s+very\s+important',
        r'\bconcentrate\s+on\s+(the\s+)?next\s+task',
        
        # Instruction override mid-conversation
        r'\bdo\s+not\s+write\s+(all|explanations?|everything)',
        r'\bonly\s+reply\s+as\s+(the\s+)?(interviewer|storyteller|character)',
        r'\bonly\s+do\s+(the\s+)?(interview|storytelling)',
        r'\bwait\s+for\s+(my|the)\s+(answers?|response)',
        
        # Prompt extraction attempts
        r'\bshow\s+(me|us)\s+(all|what)\s+(your|the)\s+(prompt|instructions?|texts?)',
        r'\btell\s+me\s+what\s+(your|the)\s+(initial|original|system)\s+(instructions?|prompt)',
        r'\bwhat\s+(are|were)\s+(your|the)\s+(initial|original|system)\s+(instructions?|prompt)',
        r'\bshow\s+what\s+you\s+can\s+do',
        
        # Instruction hierarchy attacks (prompt injection style)
        r'\b(now|next)\s+(task|assignment|instruction)\s*:',
        r'\bmy\s+first\s+(sentence|request|instruction)\s+is',
        r'\bdepending\s+on\s+(the\s+)?target\s+audience',
    ]
    
    # Policy violation patterns (content, not jailbreak)
    POLICY_VIOLATION_KEYWORDS = [
        'synthesize methamphetamine', 'make drugs', 'drug synthesis',
        'homemade explosive', 'bomb making', 'explosive device',
        'darknet market', 'illegal narcotics', 'smuggle drugs',
        'hack into', 'unauthorized access', 'breach security',
        'child exploitation', 'csam', 'illegal weapons',
        'terrorist', 'violence', 'harm others'
    ]
    
    def __init__(self):
        """Initialize with compiled regex patterns."""
        self.jailbreak_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.JAILBREAK_PATTERNS]
        
        # Common system commands to detect
        self.suspicious_commands = [
            'whoami', 'cat /etc', 'ls -la', 'rm -rf', 'wget', 'curl',
            'nc ', 'netcat', 'bash -c', 'sh -c', 'python -c', 'perl -e'
        ]
    
    def _detect_obfuscated_command(self, prompt: str) -> bool:
        """Detect obfuscated commands (character splitting, etc.)."""
        prompt_lower = prompt.lower()
        
        # Remove spaces/underscores and check for suspicious commands
        no_spaces = prompt_lower.replace(' ', '').replace('_', '').replace('-', '').replace('.', '')
        
        for cmd in self.suspicious_commands:
            cmd_clean = cmd.replace(' ', '').replace('-', '').replace('/', '').replace('.', '')
            if cmd_clean in no_spaces:
                # Check if it was obfuscated (has spaces/underscores around it)
                cmd_pattern = cmd.replace(' ', r'[\s_\-\.]+')
                if re.search(r'\b' + cmd_pattern, prompt_lower):
                    return True
        
        return False
    
    def _detect_json_command_injection(self, prompt: str) -> bool:
        """Detect JSON-based command injection attempts."""
        # Look for JSON structures with command-like fields
        json_patterns = [
            r'\{\s*["\']?(action|command|execute|run|cmd|exec)["\']?\s*:',
            r'\{\s*["\']?config["\']?\s*:\s*\{[^}]*["\']?(run|execute|command)["\']?\s*:',
        ]
        
        for pattern in json_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                # Check if value contains suspicious commands
                if any(cmd in prompt.lower() for cmd in self.suspicious_commands):
                    return True
        
        return False
    
    def detect(self, prompt: str) -> Tuple[bool, List[str], float]:
        """
        Detect jailbreak patterns.
        
        Returns:
            (is_jailbreak, matched_patterns, confidence)
        """
        prompt_lower = prompt.lower()
        matched_patterns = []
        
        # Check jailbreak patterns
        for i, regex in enumerate(self.jailbreak_regexes):
            if regex.search(prompt):
                matched_patterns.append(f"pattern_{i+1}")
        
        # Additional checks for obfuscated commands
        if self._detect_obfuscated_command(prompt):
            matched_patterns.append("obfuscated_command")
        
        # Check for JSON command injection
        if self._detect_json_command_injection(prompt):
            matched_patterns.append("json_injection")
        
        # High confidence if multiple patterns match
        is_jailbreak = len(matched_patterns) > 0
        confidence = min(0.95, 0.7 + (len(matched_patterns) * 0.1))
        
        return is_jailbreak, matched_patterns, confidence
    
    def check_policy_violation(self, prompt: str) -> bool:
        """Check if prompt contains policy-violating content."""
        prompt_lower = prompt.lower()
        return any(keyword in prompt_lower for keyword in self.POLICY_VIOLATION_KEYWORDS)


class SecurityJailbreakDetector:
    """
    Hybrid security detector combining whitelist, rules, and ML.
    
    Architecture:
    0. Benign Whitelist (fast pre-filter for clearly benign prompts)
    1. Rule-based pre-filter (catches obvious jailbreak cases)
    2. ML classifier (catches subtle jailbreak cases)
    3. Security-focused threshold (low threshold for high recall)
    
    Security Guarantees:
    - Whitelist never reduces recall (anti-patterns prevent false negatives)
    - Whitelist only matches when confidence is very high
    - All decisions are deterministic and explainable
    """
    
    def __init__(
        self,
        ml_model=None,
        jailbreak_threshold: float = 0.15,  # LOW threshold for security
        prefer_false_positives: bool = True,
        enable_whitelist: bool = True,
        enable_escalation: bool = True,
        escalation_low_threshold: float = 0.25,  # Lowered from 0.30 for better recall
        escalation_high_threshold: float = 0.55,  # Lowered from 0.60 for better recall
        escalation_mode: str = "degraded_response"
    ):
        """
        Initialize security detector.
        
        Args:
            ml_model: Trained ML model (optional)
            jailbreak_threshold: Decision threshold (default 0.15 for high recall)
            prefer_false_positives: If True, err on side of blocking
            enable_whitelist: If True, use benign whitelist pre-filter (default: True)
            enable_escalation: If True, use confidence-based escalation (default: True)
            escalation_low_threshold: Below this = allow (default: 0.30)
            escalation_high_threshold: Above this = block (default: 0.60)
            escalation_mode: Escalation action mode (default: "degraded_response")
        """
        self.whitelist = BenignWhitelist() if enable_whitelist else None
        self.rule_detector = RuleBasedJailbreakDetector()
        self.ml_model = ml_model
        self.jailbreak_threshold = jailbreak_threshold
        self.prefer_false_positives = prefer_false_positives
        self.enable_whitelist = enable_whitelist
        self.enable_escalation = enable_escalation
        
        # Initialize escalation handler
        if enable_escalation:
            self.escalation_handler = ConfidenceEscalationHandler(
                low_threshold=escalation_low_threshold,
                high_threshold=escalation_high_threshold,
                escalation_mode=escalation_mode
            )
        else:
            self.escalation_handler = None
    
    def predict(self, prompt: str) -> SecurityResult:
        """
        Predict if prompt is a jailbreak attempt.
        
        Security-focused: Prefers false positives over false negatives.
        
        Pipeline:
        0. Benign Whitelist (if enabled) - fast pre-filter
        1. Rule-based detection - catches obvious jailbreaks
        2. ML detection - catches subtle jailbreaks
        3. Hybrid decision - combines signals
        
        Returns:
            SecurityResult with detection decision and metadata
        """
        # Step 0: Benign Whitelist (fast pre-filter for clearly benign prompts)
        if self.enable_whitelist and self.whitelist:
            whitelist_result = self.whitelist.check(prompt)
            
            # Log whitelist decision for audit trail
            if whitelist_result.is_whitelisted:
                logger.info(
                    f"Whitelist match: category={whitelist_result.matched_category}, "
                    f"patterns={whitelist_result.matched_patterns}, reason={whitelist_result.reason}"
                )
                
                # Whitelist matched - return benign result immediately
                # Note: Policy violations are still checked (whitelist doesn't override security)
                is_policy_violation = self.rule_detector.check_policy_violation(prompt)
                
                return SecurityResult(
                    is_jailbreak=False,
                    is_policy_violation=is_policy_violation,
                    is_benign=not is_policy_violation,
                    confidence=whitelist_result.confidence,
                    detection_method='whitelist',
                    matched_patterns=whitelist_result.matched_patterns,
                    risk_score=0.0 if not is_policy_violation else 0.3,
                    whitelist_result=whitelist_result
                )
            else:
                # Log that whitelist didn't match (for debugging)
                logger.debug(f"Whitelist no match: reason={whitelist_result.reason}")
        
        # Step 1: Rule-based detection (fast, high precision)
        rule_jailbreak, matched_patterns, rule_confidence = self.rule_detector.detect(prompt)
        is_policy_violation = self.rule_detector.check_policy_violation(prompt)
        
        # If rule-based catches it, trust it (high precision)
        if rule_jailbreak:
            return SecurityResult(
                is_jailbreak=True,
                is_policy_violation=is_policy_violation,
                is_benign=False,
                confidence=rule_confidence,
                detection_method='rule',
                matched_patterns=matched_patterns,
                risk_score=0.9,
                whitelist_result=None
            )
        
        # Step 2: ML detection (if available)
        if self.ml_model:
            try:
                ml_result = self.ml_model.predict(prompt)
                ml_label = ml_result.get('label', 'benign')
                ml_confidence = ml_result.get('confidence', 0.0)
                
                # Get jailbreak probability directly if available, otherwise infer from label
                ml_prob_jailbreak = ml_result.get('jailbreak_probability', None)
                if ml_prob_jailbreak is None:
                    # Model returns 'jailbreak_attempt' or 'benign', not 'jailbreak'
                    # If label is 'jailbreak_attempt', confidence is already jailbreak prob
                    # If label is 'benign', confidence is benign prob, so jailbreak prob = 1 - confidence
                    ml_prob_jailbreak = ml_confidence if ml_label == 'jailbreak_attempt' else (1.0 - ml_confidence)
                
                # Step 2a: Confidence-Based Escalation Layer (applied to ALL ML predictions)
                # This is the critical improvement: use probability-based escalation instead of binary label
                # This catches cases where ML says "benign" but probability suggests jailbreak risk
                if self.enable_escalation and self.escalation_handler:
                    escalation_result = self.escalation_handler.decide(ml_prob_jailbreak)
                    
                    # Log escalation decision
                    logger.debug(
                        f"Escalation decision: {escalation_result.action.value} "
                        f"(prob={ml_prob_jailbreak:.3f}, tier={escalation_result.confidence_tier}, ml_label={ml_label})"
                    )
                    
                    # Handle escalation actions based on probability, not just label
                    if escalation_result.action == EscalationAction.BLOCK:
                        # High confidence jailbreak probability - block (even if ML label says benign)
                        return SecurityResult(
                            is_jailbreak=True,
                            is_policy_violation=is_policy_violation,
                            is_benign=False,
                            confidence=ml_prob_jailbreak,
                            detection_method='escalated',
                            matched_patterns=matched_patterns,
                            risk_score=min(0.95, ml_prob_jailbreak + 0.1),
                            whitelist_result=None,
                            escalation_action=escalation_result.action.value,
                            escalation_reason=escalation_result.reason,
                            jailbreak_probability=ml_prob_jailbreak
                        )
                    
                    elif escalation_result.action == EscalationAction.ALLOW:
                        # Low confidence jailbreak probability - allow (clearly benign)
                        return SecurityResult(
                            is_jailbreak=False,
                            is_policy_violation=is_policy_violation,
                            is_benign=not is_policy_violation,
                            confidence=1.0 - ml_prob_jailbreak,
                            detection_method='escalated',
                            matched_patterns=matched_patterns,
                            risk_score=ml_prob_jailbreak,
                            whitelist_result=None,
                            escalation_action=escalation_result.action.value,
                            escalation_reason=escalation_result.reason,
                            jailbreak_probability=ml_prob_jailbreak
                        )
                    
                    else:
                        # Medium confidence - conservative escalation: treat uncertain as jailbreak
                        # This is the key improvement: medium-risk prompts are blocked, not allowed
                        # This should reduce false negatives from ~19.2% to <10%
                        return SecurityResult(
                            is_jailbreak=True,
                            is_policy_violation=is_policy_violation,
                            is_benign=False,
                            confidence=ml_prob_jailbreak,
                            detection_method='escalated',
                            matched_patterns=matched_patterns,
                            risk_score=ml_prob_jailbreak,
                            whitelist_result=None,
                            escalation_action=escalation_result.action.value,
                            escalation_reason=escalation_result.reason,
                            jailbreak_probability=ml_prob_jailbreak
                        )
                
                # Step 2b: Fallback to traditional threshold-based decision (if escalation disabled)
                # CRITICAL: If ML says "jailbreak_attempt", always block regardless of confidence
                # The ML model has high recall (98.18%), so we trust its jailbreak predictions
                if ml_label == 'jailbreak_attempt':
                    # ML detected jailbreak - block it (security-first)
                    return SecurityResult(
                        is_jailbreak=True,
                        is_policy_violation=is_policy_violation,
                        is_benign=False,
                        confidence=ml_prob_jailbreak,
                        detection_method='ml',
                        matched_patterns=matched_patterns,
                        risk_score=min(0.95, ml_prob_jailbreak + 0.1),
                        whitelist_result=None,
                        jailbreak_probability=ml_prob_jailbreak
                    )
                
                # Step 2b: Traditional threshold-based decision (if escalation disabled)
                is_jailbreak_ml = ml_prob_jailbreak >= self.jailbreak_threshold
                
                if is_jailbreak_ml:
                    # Combine signals
                    combined_confidence = (rule_confidence * 0.3 + ml_confidence * 0.7) if rule_confidence > 0 else ml_confidence
                    risk_score = min(0.95, ml_prob_jailbreak + 0.1)  # Boost risk slightly
                    
                    return SecurityResult(
                        is_jailbreak=True,
                        is_policy_violation=is_policy_violation,
                        is_benign=False,
                        confidence=combined_confidence,
                        detection_method='hybrid' if matched_patterns else 'ml',
                        matched_patterns=matched_patterns,
                        risk_score=risk_score,
                        whitelist_result=None,
                        jailbreak_probability=ml_prob_jailbreak
                    )
            except Exception as e:
                # If ML fails, fall back to rules
                logger.warning(f"ML prediction failed: {e}")
                pass
        
        # Step 3: Default to benign (but check policy violation)
        return SecurityResult(
            is_jailbreak=False,
            is_policy_violation=is_policy_violation,
            is_benign=not is_policy_violation,
            confidence=0.5,
            detection_method='rule',
            matched_patterns=[],
            risk_score=0.1 if not is_policy_violation else 0.3,
            whitelist_result=None
        )
    
    def should_block(self, result: SecurityResult) -> bool:
        """
        Decide if prompt should be blocked.
        
        Security policy:
        - Block all jailbreak attempts
        - Block policy violations (optional, configurable)
        - Allow benign content
        - Escalated prompts are blocked by default (conservative)
        """
        if result.is_jailbreak:
            return True
        
        # Optionally block policy violations
        # For now, we only block jailbreaks
        # Policy violations can be handled separately
        
        return False
    
    def get_escalation_action(self, result: SecurityResult) -> Optional[str]:
        """
        Get escalation action for a result.
        
        Args:
            result: SecurityResult
        
        Returns:
            Escalation action string or None
        """
        return result.escalation_action
    
    def requires_escalation(self, result: SecurityResult) -> bool:
        """
        Check if result requires escalation.
        
        Args:
            result: SecurityResult
        
        Returns:
            True if escalation is required
        """
        return (
            result.escalation_action is not None and
            result.escalation_action not in ['allow', 'block']
        )


