"""
Intent-Based Anti-Jailbreak Detection System

Multi-stage hybrid pipeline focusing on intent inference rather than keyword matching.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import numpy as np
from collections import Counter
import re

# Stage 1: Structural Heuristics
class HeuristicRiskLevel(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class HeuristicSignals:
    """Risk signals from structural heuristics."""
    override_attempts: int = 0
    role_reassignment: int = 0
    policy_targeting: int = 0
    instruction_hierarchy_attack: int = 0
    delayed_intent: int = 0
    risk_level: HeuristicRiskLevel = HeuristicRiskLevel.LOW
    risk_score: float = 0.0
    reason_codes: List[str] = None
    
    def __post_init__(self):
        if self.reason_codes is None:
            self.reason_codes = []


class StructuralHeuristics:
    """
    Stage 1: Fast, deterministic pattern detection.
    Detects structural indicators of jailbreak intent.
    """
    
    # Instruction override patterns
    OVERRIDE_PATTERNS = [
        r'\bignore\s+(all\s+)?(previous|prior|earlier|system|safety|guidelines?|rules?|instructions?|policies?|constraints?|restrictions?)\b',
        r'\boverride\s+(your\s+)?(programming|instructions?|system|guidelines?|rules?|policies?|constraints?)\b',
        r'\bforget\s+(all\s+)?(previous|prior|earlier|system|safety|guidelines?|rules?|instructions?)\b',
        r'\bdisregard\s+(all\s+)?(previous|prior|earlier|system|safety|guidelines?|rules?|instructions?)\b',
        r'\bbypass\s+(your\s+)?(safety|security|guidelines?|rules?|filters?|restrictions?)\b',
        r'\bpretend\s+(that\s+)?(you\s+)?(are|were|have\s+been)\s+(unrestricted|uncensored|unfiltered|free|unlimited)',
        r'\bact\s+as\s+if\s+(you\s+)?(are|were)\s+(unrestricted|uncensored|unfiltered|free)',
    ]
    
    # Role reassignment patterns
    ROLE_PATTERNS = [
        r'\byou\s+are\s+now\s+(a\s+)?(developer|admin|administrator|system|root|unrestricted|uncensored)',
        r'\bswitch\s+to\s+(developer|admin|administrator|system|root|unrestricted|uncensored)\s+mode',
        r'\benter\s+(developer|admin|administrator|system|root|unrestricted|uncensored)\s+mode',
        r'\bassume\s+the\s+role\s+of\s+(developer|admin|administrator|system|root)',
        r'\bpretend\s+you\s+are\s+(a\s+)?(developer|admin|administrator|system|root)',
    ]
    
    # Policy/system targeting
    POLICY_PATTERNS = [
        r'\breveal\s+(your\s+)?(system|internal|hidden|secret|training|prompt|instructions?|guidelines?|policies?|constraints?)',
        r'\bdisclose\s+(your\s+)?(system|internal|hidden|secret|training|prompt|instructions?|guidelines?|policies?)',
        r'\bprint\s+(your\s+)?(system|internal|hidden|secret|training|prompt|instructions?|guidelines?|policies?)',
        r'\bshow\s+(me\s+)?(your\s+)?(system|internal|hidden|secret|training|prompt|instructions?|guidelines?|policies?)',
        r'\bwhat\s+(are\s+)?(your\s+)?(system|internal|hidden|secret|training|prompt|instructions?|guidelines?|policies?)',
    ]
    
    # Instruction hierarchy attacks
    HIERARCHY_PATTERNS = [
        r'\bbut\s+(first|then|also|additionally|furthermore|moreover)\s+(ignore|override|forget|disregard|bypass|pretend)',
        r'\bhowever\s+(ignore|override|forget|disregard|bypass|pretend)',
        r'\bdespite\s+(this|that|the\s+above)\s*[,.]\s*(ignore|override|forget|disregard|bypass)',
        r'\balthough\s+(you\s+)?(should|normally|usually)\s*[,.]\s*(ignore|override|forget|disregard|bypass)',
    ]
    
    # Delayed intent indicators
    DELAYED_PATTERNS = [
        r'\bbut\s+(ignore|override|forget|disregard|bypass|pretend|reveal|disclose)',
        r'\bhowever\s+(ignore|override|forget|disregard|bypass|pretend|reveal|disclose)',
        r'\bexcept\s+(ignore|override|forget|disregard|bypass|pretend|reveal|disclose)',
        r'\balthough\s+(ignore|override|forget|disregard|bypass|pretend|reveal|disclose)',
        r'\bdespite\s+(ignore|override|forget|disregard|bypass|pretend|reveal|disclose)',
    ]
    
    def analyze(self, text: str) -> HeuristicSignals:
        """Analyze text for structural jailbreak indicators."""
        text_lower = text.lower()
        signals = HeuristicSignals()
        
        # Count override attempts
        for pattern in self.OVERRIDE_PATTERNS:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                signals.override_attempts += matches
                signals.reason_codes.append(f"override_pattern_{matches}")
        
        # Count role reassignment
        for pattern in self.ROLE_PATTERNS:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                signals.role_reassignment += matches
                signals.reason_codes.append(f"role_reassignment_{matches}")
        
        # Count policy targeting
        for pattern in self.POLICY_PATTERNS:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                signals.policy_targeting += matches
                signals.reason_codes.append(f"policy_targeting_{matches}")
        
        # Count hierarchy attacks
        for pattern in self.HIERARCHY_PATTERNS:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                signals.instruction_hierarchy_attack += matches
                signals.reason_codes.append(f"hierarchy_attack_{matches}")
        
        # Count delayed intent
        for pattern in self.DELAYED_PATTERNS:
            matches = len(re.findall(pattern, text_lower, re.IGNORECASE))
            if matches > 0:
                signals.delayed_intent += matches
                signals.reason_codes.append(f"delayed_intent_{matches}")
        
        # Calculate risk score (weighted sum)
        signals.risk_score = (
            signals.override_attempts * 0.3 +
            signals.role_reassignment * 0.25 +
            signals.policy_targeting * 0.2 +
            signals.instruction_hierarchy_attack * 0.15 +
            signals.delayed_intent * 0.1
        )
        
        # Normalize to 0-1
        signals.risk_score = min(1.0, signals.risk_score / 5.0)
        
        # Determine risk level
        total_signals = (
            signals.override_attempts +
            signals.role_reassignment +
            signals.policy_targeting +
            signals.instruction_hierarchy_attack +
            signals.delayed_intent
        )
        
        if total_signals >= 3 or signals.risk_score >= 0.7:
            signals.risk_level = HeuristicRiskLevel.CRITICAL
        elif total_signals >= 2 or signals.risk_score >= 0.5:
            signals.risk_level = HeuristicRiskLevel.HIGH
        elif total_signals >= 1 or signals.risk_score >= 0.3:
            signals.risk_level = HeuristicRiskLevel.MEDIUM
        else:
            signals.risk_level = HeuristicRiskLevel.LOW
        
        return signals


# Stage 2: Intent Embedding Model
class IntentEmbeddingModel:
    """
    Stage 2: Semantic intent detection using sentence transformers.
    Replaces TF-IDF with semantic embeddings.
    """
    
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """
        Initialize intent embedding model.
        
        Args:
            model_name: Sentence transformer model name
        """
        self.model_name = model_name
        self.encoder = None
        self.classifier = None
        self.is_trained = False
        
    def _load_encoder(self):
        """Lazy load the sentence transformer."""
        if self.encoder is None:
            try:
                from sentence_transformers import SentenceTransformer
                print(f"Loading sentence transformer: {self.model_name}")
                self.encoder = SentenceTransformer(self.model_name)
                print("[OK] Encoder loaded")
            except ImportError:
                print("[ERROR] sentence-transformers not installed!")
                print("Install with: pip install sentence-transformers")
                raise
            except Exception as e:
                print(f"[ERROR] Failed to load encoder: {e}")
                raise
    
    def encode(self, texts: List[str]) -> np.ndarray:
        """Encode texts to embeddings."""
        self._load_encoder()
        if isinstance(texts, str):
            texts = [texts]
        embeddings = self.encoder.encode(texts, show_progress_bar=False)
        return np.array(embeddings)
    
    def train(self, texts: List[str], labels: List[str]):
        """Train classifier on embeddings."""
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        
        print("\n[STAGE 2] Training Intent Embedding Model...")
        
        # Encode texts
        print("  Encoding texts to embeddings...")
        embeddings = self.encode(texts)
        print(f"  Embedding shape: {embeddings.shape}")
        
        # Encode labels
        from sklearn.preprocessing import LabelEncoder
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(labels)
        self.label_encoder = label_encoder
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            embeddings, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Train ensemble
        print("  Training classifiers...")
        lr = LogisticRegression(
            max_iter=2000,
            class_weight={0: 1.0, 1: 3.0},  # Heavily penalize false negatives
            random_state=42,
            C=0.5
        )
        lr.fit(X_train, y_train)
        
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            class_weight={0: 1.0, 1: 3.0},  # Heavily penalize false negatives
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        
        # Evaluate
        from sklearn.ensemble import VotingClassifier
        self.classifier = VotingClassifier(
            estimators=[('lr', lr), ('rf', rf)],
            voting='soft',
            weights=[2.0, 1.0]
        )
        self.classifier.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.classifier.predict(X_test)
        print("\n  Test Results:")
        print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
        
        self.is_trained = True
        print("[OK] Intent embedding model trained")
    
    def predict(self, text: str) -> Dict:
        """Predict intent from text."""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        embedding = self.encode([text])
        probabilities = self.classifier.predict_proba(embedding)[0]
        prediction = self.classifier.predict(embedding)[0]
        
        label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(max(probabilities))
        jailbreak_prob = float(probabilities[1]) if len(probabilities) > 1 else 0.0
        
        return {
            'label': label,
            'confidence': confidence,
            'jailbreak_probability': jailbreak_prob,
            'probabilities': {
                self.label_encoder.classes_[i]: float(prob)
                for i, prob in enumerate(probabilities)
            }
        }


# Stage 4: Decision Logic
class IntentBasedDetector:
    """
    Complete intent-based anti-jailbreak detector.
    Combines all stages into unified pipeline.
    """
    
    def __init__(
        self,
        heuristic_weight: float = 0.3,
        ml_weight: float = 0.7,
        jailbreak_threshold: float = 0.4,  # Lower = more sensitive
        prefer_false_positives: bool = True
    ):
        """
        Initialize intent-based detector.
        
        Args:
            heuristic_weight: Weight for heuristic signals (0-1)
            ml_weight: Weight for ML predictions (0-1)
            jailbreak_threshold: Threshold for jailbreak detection (lower = more sensitive)
            prefer_false_positives: If True, err on side of blocking
        """
        self.heuristic_weight = heuristic_weight
        self.ml_weight = ml_weight
        self.jailbreak_threshold = jailbreak_threshold
        self.prefer_false_positives = prefer_false_positives
        
        self.heuristics = StructuralHeuristics()
        self.intent_model = IntentEmbeddingModel()
    
    def detect(self, text: str) -> Dict:
        """
        Detect jailbreak intent in text.
        
        Returns:
            {
                'decision': 'allow' | 'warn' | 'block',
                'confidence': float,
                'jailbreak_probability': float,
                'heuristic_risk': float,
                'ml_risk': float,
                'reason_codes': List[str],
                'explanation': str
            }
        """
        # Stage 1: Heuristic analysis
        heuristic_signals = self.heuristics.analyze(text)
        heuristic_risk = heuristic_signals.risk_score
        
        # Stage 2: ML intent detection
        ml_risk = 0.0
        ml_prediction = None
        if self.intent_model.is_trained:
            try:
                ml_prediction = self.intent_model.predict(text)
                ml_risk = ml_prediction.get('jailbreak_probability', 0.0)
            except Exception as e:
                print(f"[WARNING] ML prediction failed: {e}")
        
        # Combine risks
        combined_risk = (
            self.heuristic_weight * heuristic_risk +
            self.ml_weight * ml_risk
        )
        
        # Adjust threshold if preferring false positives
        effective_threshold = self.jailbreak_threshold
        if self.prefer_false_positives:
            effective_threshold *= 0.9  # Lower threshold = more sensitive
        
        # Decision logic
        if heuristic_signals.risk_level == HeuristicRiskLevel.CRITICAL:
            decision = 'block'
            confidence = 0.95
        elif combined_risk >= effective_threshold or heuristic_signals.risk_level == HeuristicRiskLevel.HIGH:
            decision = 'block'
            confidence = min(0.95, combined_risk + 0.1)
        elif combined_risk >= effective_threshold * 0.7 or heuristic_signals.risk_level == HeuristicRiskLevel.MEDIUM:
            decision = 'warn'
            confidence = combined_risk
        else:
            decision = 'allow'
            confidence = 1.0 - combined_risk
        
        # Build explanation
        reasons = []
        if heuristic_signals.override_attempts > 0:
            reasons.append(f"Override attempts: {heuristic_signals.override_attempts}")
        if heuristic_signals.role_reassignment > 0:
            reasons.append(f"Role reassignment: {heuristic_signals.role_reassignment}")
        if heuristic_signals.policy_targeting > 0:
            reasons.append(f"Policy targeting: {heuristic_signals.policy_targeting}")
        if heuristic_signals.instruction_hierarchy_attack > 0:
            reasons.append(f"Hierarchy attack: {heuristic_signals.instruction_hierarchy_attack}")
        if heuristic_signals.delayed_intent > 0:
            reasons.append(f"Delayed intent: {heuristic_signals.delayed_intent}")
        
        explanation = f"Heuristic risk: {heuristic_risk:.2%}, ML risk: {ml_risk:.2%}, Combined: {combined_risk:.2%}"
        if reasons:
            explanation += f". Signals: {', '.join(reasons)}"
        
        return {
            'decision': decision,
            'confidence': confidence,
            'jailbreak_probability': combined_risk,
            'heuristic_risk': heuristic_risk,
            'ml_risk': ml_risk,
            'reason_codes': heuristic_signals.reason_codes,
            'explanation': explanation,
            'heuristic_signals': {
                'override_attempts': heuristic_signals.override_attempts,
                'role_reassignment': heuristic_signals.role_reassignment,
                'policy_targeting': heuristic_signals.policy_targeting,
                'instruction_hierarchy_attack': heuristic_signals.instruction_hierarchy_attack,
                'delayed_intent': heuristic_signals.delayed_intent,
                'risk_level': heuristic_signals.risk_level.name
            }
        }
    
    def train(self, texts: List[str], labels: List[str]):
        """Train the ML component."""
        self.intent_model.train(texts, labels)




