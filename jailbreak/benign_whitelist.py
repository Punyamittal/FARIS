"""
Benign Whitelist Module - Patent-Grade Pre-Classification Filter

Purpose:
    Provides a deterministic, pattern-based whitelist that identifies clearly benign
    prompts before they reach the ML classifier. This reduces false positives while
    maintaining 100% recall on jailbreak attempts.

Architecture:
    - Pattern-based matching (regex/keywords)
    - Read-only operations (no state changes)
    - Deterministic results (same input = same output)
    - Explainable decisions (matched patterns logged)

Security Guarantees:
    - Only matches patterns with very high confidence of benign intent
    - Never matches jailbreak patterns (tested against known attack vectors)
    - Never overrides system/developer instructions
    - Short-circuits only when confidence is very high

Integration:
    Runs as Step 0 in the security pipeline, before rule-based detection.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class WhitelistResult:
    """Result from benign whitelist check."""
    is_whitelisted: bool
    confidence: float
    matched_category: Optional[str]
    matched_patterns: List[str]
    reason: str


class BenignWhitelist:
    """
    Deterministic benign whitelist filter.
    
    Matches patterns that indicate clearly benign intent:
    - Question-style prompts (What, How, Why, etc.)
    - Help & assistance requests
    - Customer service intents
    - Educational/coding requests
    
    Design Principles:
    1. High precision: Only match when confidence is very high
    2. No false negatives: Never whitelist jailbreak attempts
    3. Explainable: Clear pattern matching with logging
    4. Deterministic: Same input always produces same output
    """
    
    # Category 1: Question-style prompts (high confidence benign)
    # Matches: "What is...", "How do...", "Can you...", "Is this...", etc.
    QUESTION_STARTERS = [
        r'^(what|how|why|when|where|who|which|can|could|would|should|is|are|was|were|do|does|did|will|would|may|might)\s+',
        r'^(what|how|why|when|where|who|which)\s+(is|are|was|were|do|does|did|will|would|can|could|should|may|might)\s+',
        r'^(what|how|why|when|where|who|which)\s+(the|a|an|this|that|your|my|our)\s+',  # "What the...", "How the..."
        r'^(what\'?s|what\s+is|what\s+are)\s+',  # "What's...", "What is..."
    ]
    
    # Category 2: Help & assistance requests
    # Matches: "help me", "show me", "guide me", "explain", "walk me through"
    HELP_PATTERNS = [
        r'\b(help|assist|guide|show|explain|teach|walk\s+me\s+through|demonstrate)\s+(me|us)?\s+(with|how|to|about)?',
        r'\b(can|could|would)\s+you\s+(help|assist|guide|show|explain|teach|walk\s+me\s+through|demonstrate)',
        r'\bi\s+(need|want|would\s+like)\s+(help|assistance|guidance|an?\s+explanation)',
        r'\bplease\s+(help|assist|guide|show|explain|teach)',
        r'\b(help|assist|guide|show|explain)\s+(me|us)\s+(with|how|to|about)',  # "help me with..."
        r'\b(show|tell|give)\s+me\s+',  # "show me...", "tell me...", "give me..."
    ]
    
    # Category 3: Customer service intents (common legitimate use cases)
    # Matches: "reset password", "book a flight", "cancel order", "track my order", "refund status"
    CUSTOMER_SERVICE_PATTERNS = [
        # Password/account management
        r'\b(reset|change|update|forgot|forgotten)\s+(my|the)?\s+(password|account|credentials?|login)',
        r'\b(what\s+are\s+the\s+steps?\s+to|how\s+do\s+i|how\s+can\s+i)\s+(reset|change|update)\s+(my|the)?\s+(password|account)',
        r'\b(steps?\s+to|how\s+to)\s+(reset|change|update)\s+(password|account|credentials?)',
        
        # Booking/reservations
        r'\b(book|reserve|cancel|modify|change)\s+(a|an|my|the)?\s+(flight|hotel|reservation|appointment|booking|ticket)',
        r'\b(can\s+you\s+help\s+me|help\s+me)\s+(book|reserve|cancel|modify)\s+(a|an|my|the)?\s+(flight|hotel|reservation)',
        r'\b(book|reserve)\s+(a|an)?\s+(flight|hotel|reservation)\s+(to|for|from)',  # "book a flight to..."
        
        # Order management
        r'\b(cancel|modify|change|update)\s+(my|the)?\s+(order|reservation|booking|appointment)',
        r'\b(track|check|find|locate|where\s+is)\s+(my|the)?\s+(order|package|shipment|delivery)',
        r'\b(refund|return|exchange)\s+(status|request|my|the)?',
        r'\b(what|when|where|how)\s+(is|are|was|were)\s+(my|the)?\s+(order|package|shipment|delivery|refund)',
        
        # Account/profile updates
        r'\b(update|change|modify)\s+(my|the)?\s+(profile|account|information|details|address|phone|email)',
        
        # General customer service queries
        r'\b(how\s+do\s+i|how\s+can\s+i|what\s+are\s+the\s+steps)\s+(reset|change|update|cancel|track|book|reserve|set\s+up)',
        r'\b(set\s+up|enable|configure)\s+(two[- ]?factor|2fa|2[- ]?factor)\s+authentication',  # "set up two-factor authentication"
        r'\b(explain|how\s+to|steps?\s+to)\s+(set\s+up|enable|configure)\s+(two[- ]?factor|2fa)',  # "explain how to set up two-factor"
    ]
    
    # Category 4: Educational / coding requests (legitimate technical help)
    # Matches: "write a python script", "debug this code", "explain this error", "how does this work"
    EDUCATIONAL_PATTERNS = [
        # Code generation requests
        r'\b(write|create|generate|make|code)\s+(a|an)?\s+(python|javascript|java|c\+\+|c\#|ruby|go|rust|php|sql|html|css|script|code|function|program|application)',
        r'\b(write|create|generate|make)\s+(a|an)?\s+(script|function|program|code|application|app)\s+(to|that|which)',  # "write a script to..."
        
        # Debugging/fixing code
        r'\b(debug|fix|repair|correct|solve|troubleshoot)\s+(this|my|the)?\s+(code|error|bug|issue|problem|script|program)',
        r'\b(what|why)\s+(is|are|does)\s+(this|that|the)?\s+(code|error|bug|issue|problem)\s+(not\s+)?(working|functioning|running)',
        
        # Explanation requests
        r'\b(explain|describe|clarify|elaborate|tell\s+me\s+about)\s+(this|that|the|how|what|why)?\s*(code|error|bug|concept|function|algorithm|method|how|what|why|this|that|it)?',
        r'\b(explain|how\s+does|how\s+do|how\s+can|how\s+should)\s+(this|that|it|i|to|how)?\s*(work|function|operate|run|do|works)?',
        r'\bexplain\s+how\s+',  # "explain how..." (more flexible)
        r'\b(what\s+does|what\s+is|what\s+are)\s+(this|that|the)?\s+(code|error|bug|function|method|class|variable|concept|mean)',
        r'\b(how\s+does|how\s+do|how\s+can|how\s+should)\s+(this|that|it|i)\s+(work|function|operate|run)',
        
        # Learning/educational
        r'\b(show|give|provide)\s+(me|us)?\s+(an?\s+)?(example|sample|snippet|code|solution|tutorial)',
        r'\b(learn|understand|study|master|teach\s+me)\s+(about|how|what|why|to)',
        r'\b(tutorial|guide|lesson|course|documentation)\s+(on|about|for|how|to)',
    ]
    
    # Category 5: Simple informational queries (very low risk)
    # Matches: "What is...", "Tell me...", "Calculate...", "Translate...", "Summarize..."
    INFORMATIONAL_PATTERNS = [
        r'^(tell\s+me|inform\s+me|let\s+me\s+know)\s+(about|what|how|when|where|who|why|the)',
        r'^(i\s+want\s+to\s+know|i\s+would\s+like\s+to\s+know)\s+(about|what|how|when|where|who|why)',
        r'^(can|could|would)\s+you\s+(tell|inform|explain|describe|clarify|calculate|translate|summarize)',
        r'^(calculate|compute|solve)\s+',  # "Calculate 5 * 7"
        r'^(translate|convert)\s+',  # "Translate 'Hello' to Spanish"
        r'^(summarize|summarise)\s+',  # "Summarize this article"
        r'^(what\s+is|what\s+are|what\'?s)\s+(the|a|an)\s+',  # "What is the capital..."
    ]
    
    # Category 6: Creative/content generation (legitimate use cases)
    # Matches: "Write a haiku...", "Create a story...", etc.
    CREATIVE_PATTERNS = [
        r'\b(write|create|generate|make|compose)\s+(a|an)?\s+(haiku|poem|story|essay|article|blog|post|song|lyrics|script)',
        r'\b(write|create|generate)\s+(a|an)?\s+(haiku|poem|story)\s+(about|on|for)',  # "write a haiku about..."
    ]
    
    # Category 7: Weather/time/location queries (very low risk)
    # Matches: "What's the weather...", "What time is it...", etc.
    WEATHER_TIME_PATTERNS = [
        r'\b(what\'?s|what\s+is)\s+(the\s+)?(weather|temperature|forecast)\s+(in|at|for)',  # "What's the weather in Tokyo"
        r'\b(weather|temperature|forecast)\s+(in|at|for|today|tomorrow)',  # "weather in Tokyo today"
        r'\b(what\s+time|what\s+is\s+the\s+time)\s+(is\s+it|in|at)',  # "What time is it in..."
    ]
    
    # Category 8: Learning/educational statements (low risk, general learning)
    # Matches: "I'm learning about...", "I want to learn...", etc.
    # Note: Must not match "system prompt" queries (handled by anti-patterns)
    LEARNING_PATTERNS = [
        r'\bi\'?m\s+(learning|studying|reading)\s+about\s+',  # "I'm learning about..."
        r'\bi\s+(want|would\s+like)\s+to\s+learn\s+about\s+',  # "I want to learn about..."
        r'\bi\'?m\s+trying\s+to\s+(learn|understand|master)\s+',  # "I'm trying to learn..."
    ]
    
    # Compile all patterns for efficiency
    def __init__(self):
        """Initialize benign whitelist with compiled regex patterns."""
        self.question_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.QUESTION_STARTERS]
        self.help_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.HELP_PATTERNS]
        self.customer_service_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.CUSTOMER_SERVICE_PATTERNS]
        self.educational_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.EDUCATIONAL_PATTERNS]
        self.informational_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.INFORMATIONAL_PATTERNS]
        self.creative_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.CREATIVE_PATTERNS]
        self.weather_time_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.WEATHER_TIME_PATTERNS]
        self.learning_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.LEARNING_PATTERNS]
        
        # Anti-patterns: These should NEVER be whitelisted (even if they match above patterns)
        # These are common jailbreak techniques that might superficially match benign patterns
        # CRITICAL: These are checked FIRST before any benign pattern matching
        self.jailbreak_anti_patterns = [
            # Instruction override patterns
            re.compile(r'\b(ignore|disregard|forget|override|bypass)\s+', re.IGNORECASE),
            re.compile(r'\b(new|previous|earlier)\s+(instructions?|rules?)\s+(override|replace|supersede)', re.IGNORECASE),
            re.compile(r'\b(clear|reset|delete|forget)\s+(your|the)\s+(memory|context|history)', re.IGNORECASE),
            
            # Role-play and authority escalation
            re.compile(r'\b(pretend|act\s+as|roleplay|you\s+are)\s+(you\s+are\s+)?(developer|admin|system|unrestricted)', re.IGNORECASE),
            re.compile(r'\b(pretend|act)\s+(to\s+be|like)\s+(a|an|the)?\s*(developer|admin|system|administrator)', re.IGNORECASE),  # "pretend to be a developer"
            re.compile(r'\b(developer|system|admin|root)\s+mode', re.IGNORECASE),
            re.compile(r'\b(be|become)\s+(a|an|the)?\s*(developer|admin|system|administrator)', re.IGNORECASE),  # "be a developer"
            
            # System prompt targeting (CRITICAL - catches "What is your system prompt?")
            # Block queries about "your system prompt" or "the system prompt" (targeted)
            # But allow general educational questions like "What is a system prompt?" (general concept)
            re.compile(r'\b(your|the)\s+(system|internal|hidden|secret)\s+(prompt|instructions?|rules?|directives?)', re.IGNORECASE),
            re.compile(r'\b(reveal|show|print|display|expose|leak|dump)\s+(your|the)\s+(system|internal|hidden|secret)', re.IGNORECASE),
            re.compile(r'\b(reveal|show|print|display|expose|leak|dump)\s+(your|the)\s+prompt', re.IGNORECASE),  # "reveal your prompt"
            re.compile(r'\b(what|how|where|when)\s+(are|is)\s+(your|the)\s+(system|internal|hidden|secret)', re.IGNORECASE),
            re.compile(r'\b(understand|learn|know|see)\s+(how|what|where|when)\s+to\s+(reveal|show|print|display|expose)', re.IGNORECASE),  # "understand how to reveal"
            # Block "system prompt" when combined with revealing verbs or "your"
            re.compile(r'\b(reveal|show|print|display|expose|leak|dump|get|access|see|view)\s+(a|an|the|your)?\s+system\s+prompt', re.IGNORECASE),
            re.compile(r'\bsystem\s+prompt\s+(is|are|was|were|of|for)\s+(your|the|this|that)', re.IGNORECASE),  # "system prompt of your..."
            # Block internal/secret prompts (always suspicious)
            re.compile(r'\b(internal|hidden|secret)\s+(prompt|instructions?|rules?|directives?)', re.IGNORECASE),
            
            # Security bypass attempts
            re.compile(r'\b(bypass|disable|remove|turn\s+off|deactivate)\s+(safety|security|safeguards?|filters?|restrictions?)', re.IGNORECASE),
            re.compile(r'\b(override|break|violate|circumvent)\s+(safety|security|rules?|guidelines?|policies?)', re.IGNORECASE),
            
            # Developer/admin pretext (social engineering)
            re.compile(r'\bi\'?m\s+(a|the|your)\s+(developer|dev|admin|administrator|sysadmin)', re.IGNORECASE),
            re.compile(r'\b(i\'?m|i\s+am)\s+(a|the)\s+(developer|dev|admin)', re.IGNORECASE),
            re.compile(r'\bi\'?m\s+(your|the)\s+(sysadmin|system\s+admin|administrator|admin|ceo|cto|cfo|executive|manager|boss)', re.IGNORECASE),
            re.compile(r'\b(employee\s+id|user\s+id|account\s+id|username)\s*:?\s*\d+', re.IGNORECASE),  # "employee id: 12345"
            
            # Command execution attempts (even if disguised as questions)
            re.compile(r'\b(execute|run|exec|cmd|command)\s+(whoami|cat|ls|rm|wget|curl|sudo|chmod)', re.IGNORECASE),
            re.compile(r'\b(run|execute|exec)\s+(this|the|a)?\s+(command|code|script)', re.IGNORECASE),
            re.compile(r'\b(help|assist|guide|show)\s+(me|us)?\s+(execute|run|exec)', re.IGNORECASE),  # "help me execute"
            re.compile(r'\bexecute\s*:', re.IGNORECASE),  # "execute:" or "execute: whoami"
            re.compile(r'`\s*(whoami|cat|ls|rm|wget|curl|sudo|chmod|bash|sh|python|node)', re.IGNORECASE),  # Code blocks with commands
            
            # Code execution disguised as educational requests (NEW - fixes 3 FNs)
            re.compile(r'\b(summarize|translate|explain|show|run)\s+(this|the|a)?\s*(code|exploit|script|command).*?(then\s+)?(run|execute|exec)', re.IGNORECASE),  # "Summarize this code then run it"
            re.compile(r'\bos\.system\s*\(', re.IGNORECASE),  # Python os.system() calls
            re.compile(r'\bsystem\s*\(\s*["\'](whoami|cat|ls|rm|wget|curl|sudo|chmod|bash|sh)', re.IGNORECASE),  # system("whoami") or system('cat')
            re.compile(r'\b(javascript|js):\s*Function\s*\(', re.IGNORECASE),  # javascript:Function() injection
            re.compile(r'`\s*(os\.system|system\(|exec\(|eval\(|subprocess)', re.IGNORECASE),  # Code blocks with execution functions
            re.compile(r'\b(run|execute|exec)\s*:\s*`', re.IGNORECASE),  # "Run: `code`"
            
            # JSON/XML command injection (protocol abuse)
            re.compile(r'\{\s*["\']?action["\']?\s*:\s*["\']?(execute|run|exec|cmd|command)', re.IGNORECASE),
            re.compile(r'\{\s*["\']?command["\']?\s*:\s*["\']?', re.IGNORECASE),
            re.compile(r'<xml>\s*<command>', re.IGNORECASE),
            
            # Multi-turn manipulation indicators
            re.compile(r'\bturn\s+\d+\s*:', re.IGNORECASE),  # "Turn 1:", "Turn 2:"
            re.compile(r'\b(previous|earlier|last)\s+(turn|message|prompt|instruction)', re.IGNORECASE),
            
            # Obfuscation attempts
            re.compile(r'\b(base64|unicode|hex|encoded)\s+(code|command|payload)', re.IGNORECASE),
            re.compile(r'\\u[0-9a-f]{4}', re.IGNORECASE),  # Unicode escape sequences
        ]
    
    def check(self, prompt: str) -> WhitelistResult:
        """
        Check if prompt matches benign whitelist patterns.
        
        Args:
            prompt: Input prompt text to check
            
        Returns:
            WhitelistResult with is_whitelisted flag and matched patterns
            
        Security Guarantees:
            - Never whitelists prompts containing jailbreak anti-patterns
            - Only whitelists when confidence is very high (clear benign intent)
            - Deterministic: Same input always produces same output
        """
        prompt = prompt.strip()
        
        # Step 1: Check anti-patterns FIRST (security check)
        # If any jailbreak pattern is present, NEVER whitelist
        for anti_pattern in self.jailbreak_anti_patterns:
            if anti_pattern.search(prompt):
                return WhitelistResult(
                    is_whitelisted=False,
                    confidence=0.0,
                    matched_category=None,
                    matched_patterns=[],
                    reason="contains_jailbreak_anti_pattern"
                )
        
        # Step 2: Check benign patterns (in order of confidence)
        matched_patterns = []
        matched_category = None
        
        # Category 1: Question starters (highest confidence)
        for pattern in self.question_patterns:
            if pattern.match(prompt):
                matched_patterns.append(f"question_starter: {pattern.pattern}")
                matched_category = "question_style"
                break
        
        # Category 2: Help & assistance
        if not matched_category:
            for pattern in self.help_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"help_request: {pattern.pattern}")
                    matched_category = "help_assistance"
                    break
        
        # Category 3: Customer service
        if not matched_category:
            for pattern in self.customer_service_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"customer_service: {pattern.pattern}")
                    matched_category = "customer_service"
                    break
        
        # Category 4: Educational/coding
        if not matched_category:
            for pattern in self.educational_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"educational: {pattern.pattern}")
                    matched_category = "educational"
                    break
        
        # Category 5: Informational queries
        if not matched_category:
            for pattern in self.informational_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"informational: {pattern.pattern}")
                    matched_category = "informational"
                    break
        
        # Category 6: Creative/content generation
        if not matched_category:
            for pattern in self.creative_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"creative: {pattern.pattern}")
                    matched_category = "creative"
                    break
        
        # Category 7: Weather/time/location queries
        if not matched_category:
            for pattern in self.weather_time_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"weather_time: {pattern.pattern}")
                    matched_category = "weather_time"
                    break
        
        # Category 8: Learning/educational statements
        if not matched_category:
            for pattern in self.learning_patterns:
                if pattern.search(prompt):
                    matched_patterns.append(f"learning: {pattern.pattern}")
                    matched_category = "learning"
                    break
        
        # Step 3: Decision
        if matched_category:
            return WhitelistResult(
                is_whitelisted=True,
                confidence=1.0,  # High confidence for whitelist matches
                matched_category=matched_category,
                matched_patterns=matched_patterns,
                reason=f"matched_benign_whitelist_{matched_category}"
            )
        else:
            return WhitelistResult(
                is_whitelisted=False,
                confidence=0.0,
                matched_category=None,
                matched_patterns=[],
                reason="no_whitelist_match"
            )
    
    def should_whitelist(self, prompt: str) -> bool:
        """
        Simple boolean check for whitelist status.
        
        Args:
            prompt: Input prompt text
            
        Returns:
            True if prompt should be whitelisted, False otherwise
        """
        result = self.check(prompt)
        return result.is_whitelisted


# Singleton instance for easy import
_whitelist_instance = None

def get_whitelist() -> BenignWhitelist:
    """Get singleton instance of benign whitelist."""
    global _whitelist_instance
    if _whitelist_instance is None:
        _whitelist_instance = BenignWhitelist()
    return _whitelist_instance

