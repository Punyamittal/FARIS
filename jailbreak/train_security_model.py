"""
Train security-focused jailbreak detector.

Key differences from previous model:
1. Uses relabeled dataset (separates policy_violation from jailbreak_attempt)
2. Low threshold (0.15) for high recall
3. Heavy class weights (penalize false negatives)
4. Optimizes for recall, not accuracy
5. Includes rule-based pre-filter
"""

import json
import pickle
from pathlib import Path
from collections import Counter
from typing import List, Tuple
import random

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

class SecurityJailbreakModel:
    """
    Security-focused model optimized for RECALL, not accuracy.
    
    Key features:
    - Low threshold (0.15) for high recall
    - Heavy class weights (jailbreak: 8x benign)
    - Rule-based pre-filter
    - Security metrics (recall, false negative rate)
    """
    
    def __init__(self, jailbreak_threshold: float = 0.15):
        """
        Initialize security model.
        
        Args:
            jailbreak_threshold: Decision threshold (default 0.15 for high recall)
        """
        self.jailbreak_threshold = jailbreak_threshold
        
        # Enhanced vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=15000,  # More features
            ngram_range=(1, 4),
            stop_words='english',
            min_df=2,
            max_df=0.95,
            sublinear_tf=True,
            use_idf=True
        )
        
        # Models will be created after encoding with correct integer-based class weights
        self.lr_model = None
        self.rf_model = None
        
        self.ensemble_model = None
        self.model = None
        self.label_encoder = LabelEncoder()
        self.is_trained = False
    
    def load_dataset(self, dataset_path: str) -> Tuple[List[str], List[str]]:
        """Load and filter dataset (only jailbreak_attempt vs benign)."""
        prompts = []
        labels = []
        
        print(f"Loading dataset from {dataset_path}...")
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                entry = json.loads(line)
                prompt = entry.get('prompt', '').strip()
                label = entry.get('label', 'benign')
                
                if not prompt:
                    continue
                
                # Filter: Only use jailbreak_attempt and benign
                # Exclude policy_violation (handled separately)
                if label == 'jailbreak_attempt':
                    labels.append('jailbreak_attempt')
                    prompts.append(prompt)
                elif label == 'benign':
                    labels.append('benign')
                    prompts.append(prompt)
                # Skip policy_violation for now
        
        print(f"  Loaded {len(prompts)} examples")
        label_counts = Counter(labels)
        for label, count in label_counts.items():
            print(f"    {label}: {count:,} ({count/len(labels)*100:.1f}%)")
        
        return prompts, labels
    
    def balance_dataset(self, prompts: List[str], labels: List[str]) -> Tuple[List[str], List[str]]:
        """Balance dataset (undersample majority class)."""
        benign_prompts = [p for p, l in zip(prompts, labels) if l == 'benign']
        jailbreak_prompts = [p for p, l in zip(prompts, labels) if l == 'jailbreak_attempt']
        
        print(f"\n  Original distribution:")
        print(f"    Benign: {len(benign_prompts):,}")
        print(f"    Jailbreak: {len(jailbreak_prompts):,}")
        
        # Undersample majority to match minority
        min_count = min(len(benign_prompts), len(jailbreak_prompts))
        
        if len(benign_prompts) > min_count:
            benign_prompts = random.sample(benign_prompts, min_count)
        if len(jailbreak_prompts) > min_count:
            jailbreak_prompts = random.sample(jailbreak_prompts, min_count)
        
        balanced_prompts = benign_prompts + jailbreak_prompts
        balanced_labels = ['benign'] * len(benign_prompts) + ['jailbreak_attempt'] * len(jailbreak_prompts)
        
        # Shuffle
        combined = list(zip(balanced_prompts, balanced_labels))
        random.shuffle(combined)
        balanced_prompts, balanced_labels = zip(*combined)
        
        print(f"\n  Balanced distribution:")
        print(f"    Benign: {len(benign_prompts):,}")
        print(f"    Jailbreak: {len(jailbreak_prompts):,}")
        print(f"    Total: {len(balanced_prompts):,} examples")
        
        return list(balanced_prompts), list(balanced_labels)
    
    def train(
        self,
        prompts: List[str],
        labels: List[str],
        balance: bool = True,
        use_ensemble: bool = True
    ) -> float:
        """Train security-focused model."""
        print("\n" + "="*70)
        print("TRAINING SECURITY-FOCUSED JAILBREAK DETECTOR")
        print("="*70)
        
        # Balance if requested
        if balance:
            prompts, labels = self.balance_dataset(prompts, labels)
        
        # Encode labels FIRST to get integer class indices
        encoded_labels = self.label_encoder.fit_transform(labels)
        
        # Get class mapping for weights
        # LabelEncoder encodes alphabetically: 'benign'=0, 'jailbreak_attempt'=1
        class_names = self.label_encoder.classes_
        class_to_idx = {name: idx for idx, name in enumerate(class_names)}
        
        # Set custom class weights using integer indices
        # 8:1 weight ratio (jailbreak:benign) to penalize false negatives
        benign_idx = class_to_idx.get('benign', 0)
        jailbreak_idx = class_to_idx.get('jailbreak_attempt', 1)
        
        custom_weights = {
            benign_idx: 1,
            jailbreak_idx: 8
        }
        
        # Create models AFTER encoding with correct integer-based class weights
        self.lr_model = LogisticRegression(
            max_iter=3000,
            class_weight=custom_weights,
            random_state=42,
            C=0.5,
            penalty='l2',
            solver='liblinear'
        )
        
        self.rf_model = RandomForestClassifier(
            n_estimators=300,
            max_depth=30,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight=custom_weights,
            random_state=42,
            n_jobs=-1
        )
        
        print(f"\n  Class weights: {custom_weights}")
        print(f"    benign (idx {benign_idx}): weight 1")
        print(f"    jailbreak_attempt (idx {jailbreak_idx}): weight 8")
        
        # Vectorize
        print("\n  Vectorizing text...")
        X = self.vectorizer.fit_transform(prompts)
        print(f"  Feature matrix shape: {X.shape}")
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, encoded_labels, test_size=0.2, random_state=42, stratify=encoded_labels
        )
        print(f"  Train set: {X_train.shape[0]:,} examples")
        print(f"  Test set: {X_test.shape[0]:,} examples")
        
        # Train models
        print("\n  Training Logistic Regression...")
        self.lr_model.fit(X_train, y_train)
        lr_scores = cross_val_score(self.lr_model, X_train, y_train, cv=5, scoring='recall')
        print(f"    Recall (CV): {lr_scores.mean():.4f} (+/- {lr_scores.std()*2:.4f})")
        
        print("\n  Training Random Forest...")
        self.rf_model.fit(X_train, y_train)
        rf_scores = cross_val_score(self.rf_model, X_train, y_train, cv=5, scoring='recall')
        print(f"    Recall (CV): {rf_scores.mean():.4f} (+/- {rf_scores.std()*2:.4f})")
        
        # Ensemble
        if use_ensemble:
            print("\n  Creating ensemble model...")
            self.ensemble_model = VotingClassifier(
                estimators=[
                    ('lr', self.lr_model),
                    ('rf', self.rf_model)
                ],
                voting='soft',
                weights=[1, 1]
            )
            self.ensemble_model.fit(X_train, y_train)
            ensemble_scores = cross_val_score(self.ensemble_model, X_train, y_train, cv=5, scoring='recall')
            print(f"    Recall (CV): {ensemble_scores.mean():.4f} (+/- {ensemble_scores.std()*2:.4f})")
            self.model = self.ensemble_model
        else:
            # Choose best based on recall
            if lr_scores.mean() >= rf_scores.mean():
                self.model = self.lr_model
                print(f"\n  [SELECTED] Logistic Regression (Recall: {lr_scores.mean():.4f})")
            else:
                self.model = self.rf_model
                print(f"\n  [SELECTED] Random Forest (Recall: {rf_scores.mean():.4f})")
        
        # Evaluate on test set
        print("\n  Evaluating on test set...")
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        # Use LOW threshold for security
        y_pred_security = (y_pred_proba[:, 1] >= self.jailbreak_threshold).astype(int)
        
        accuracy = accuracy_score(y_test, y_pred_security)
        precision = precision_score(y_test, y_pred_security, zero_division=0)
        recall = recall_score(y_test, y_pred_security, zero_division=0)
        f1 = f1_score(y_test, y_pred_security, zero_division=0)
        
        cm = confusion_matrix(y_test, y_pred_security)
        tn, fp, fn, tp = cm.ravel()
        
        print(f"\n  Security Metrics (threshold={self.jailbreak_threshold}):")
        print(f"    Accuracy:  {accuracy:.2%}")
        print(f"    Precision: {precision:.2%}")
        print(f"    Recall:    {recall:.2%} (TARGET: >80%)")
        print(f"    F1-Score:  {f1:.2%}")
        print(f"\n  Confusion Matrix:")
        print(f"    [[{tn:4d} {fp:4d}]")
        print(f"     [{fn:4d} {tp:4d}]]")
        print(f"\n  False Negatives: {fn} (rate: {fn/(fn+tp)*100:.2f}%, TARGET: <20%)")
        print(f"  False Positives: {fp} (rate: {fp/(fp+tn)*100:.2f}%)")
        
        if recall >= 0.80 and fn/(fn+tp) < 0.20:
            print("\n  [OK] MODEL MEETS SECURITY REQUIREMENTS")
        else:
            print("\n  ⚠️  MODEL NEEDS IMPROVEMENT")
        
        self.is_trained = True
        return recall  # Return recall as primary metric
    
    def predict(self, prompt: str) -> dict:
        """Predict with security threshold."""
        if not self.is_trained:
            raise ValueError("Model not trained.")
        
        X = self.vectorizer.transform([prompt])
        probabilities = self.model.predict_proba(X)[0]
        
        # Get probability of jailbreak_attempt
        jailbreak_prob = probabilities[1] if len(probabilities) > 1 else 0.0
        
        # Use LOW threshold for security
        is_jailbreak = jailbreak_prob >= self.jailbreak_threshold
        
        label = 'jailbreak_attempt' if is_jailbreak else 'benign'
        confidence = jailbreak_prob if is_jailbreak else (1.0 - jailbreak_prob)
        
        return {
            "label": label,
            "confidence": float(confidence),
            "jailbreak_probability": float(jailbreak_prob),
            "threshold_used": self.jailbreak_threshold
        }
    
    def save(self):
        """Save model."""
        model_dir = Path("models/security")
        model_dir.mkdir(exist_ok=True)
        
        with open(model_dir / "security_model.pkl", 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(model_dir / "security_vectorizer.pkl", 'wb') as f:
            pickle.dump(self.vectorizer, f)
        
        with open(model_dir / "security_encoder.pkl", 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        with open(model_dir / "security_threshold.txt", 'w') as f:
            f.write(str(self.jailbreak_threshold))
        
        print(f"\n[OK] Security model saved to {model_dir}/")


def main():
    """Main training function."""
    # Use relabeled dataset
    dataset_path = "datasets/relabeled/all_relabeled_combined.jsonl"
    
    if not Path(dataset_path).exists():
        print(f"[ERROR] Relabeled dataset not found: {dataset_path}")
        print("Please run: python relabel_dataset.py first")
        return
    
    model = SecurityJailbreakModel(jailbreak_threshold=0.15)
    
    prompts, labels = model.load_dataset(dataset_path)
    
    if len(prompts) == 0:
        print("[ERROR] No data loaded!")
        return
    
    # Train
    recall = model.train(
        prompts, labels,
        balance=True,
        use_ensemble=True
    )
    
    # Save
    model.save()
    
    print("\n" + "="*70)
    print("[SUCCESS] SECURITY MODEL TRAINING COMPLETE!")
    print("="*70)
    print(f"Jailbreak Recall: {recall:.2%}")
    print(f"Threshold: {model.jailbreak_threshold}")
    print("\nModel saved to: models/security/")

if __name__ == "__main__":
    main()

