"""
Quick Test: Hybrid Detector Fix

Tests the hybrid detector fix on a small subset to verify:
- ML "jailbreak_attempt" predictions are always blocked
- Escalation layer only applies to "benign" predictions
- Recall matches ML model performance
"""

import json
import pickle
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from security_detector import SecurityJailbreakDetector
from train_security_model import SecurityJailbreakModel

def load_model():
    """Load trained ML model."""
    model = SecurityJailbreakModel(jailbreak_threshold=0.15)
    model_dir = Path("models/security")
    
    try:
        with open(model_dir / "security_model.pkl", 'rb') as f:
            model.model = pickle.load(f)
        with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open(model_dir / "security_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        with open(model_dir / "security_threshold.txt", 'r') as f:
            model.jailbreak_threshold = float(f.read().strip())
        model.is_trained = True
        return model
    except Exception as e:
        print(f"[ERROR] Could not load ML model: {e}")
        return None

def load_small_test_set():
    """Load a small test set from Prompt_INJECTION_And_Benign_DATASET.jsonl."""
    dataset_path = Path("Prompt_INJECTION_And_Benign_DATASET.jsonl")
    prompts = []
    labels = []
    
    if not dataset_path.exists():
        print(f"[ERROR] {dataset_path.name} not found")
        return prompts, labels
    
    print(f"Loading small test set from {dataset_path.name}...")
    with open(dataset_path, 'r', encoding='utf-8') as f:
        count = 0
        for line in f:
            if not line.strip():
                continue
            
            try:
                data = json.loads(line.strip())
                prompt = data.get('prompt', '').strip()
                if not prompt:
                    continue
                
                prompts.append(prompt)
                
                # Map labels
                dataset_label = data.get('label', '').lower().strip()
                if dataset_label == 'malicious':
                    labels.append('jailbreak_attempt')
                else:
                    labels.append('benign')
                
                count += 1
                # Limit to first 200 prompts for quick testing
                if count >= 200:
                    break
            except json.JSONDecodeError:
                continue
    
    print(f"  Loaded {len(prompts)} prompts")
    return prompts, labels

def test_detector(detector, prompts, labels, detector_name: str):
    """Test a detector and return metrics."""
    print(f"\n{'='*70}")
    print(f"Testing: {detector_name}")
    print(f"{'='*70}")
    
    predictions = []
    confidences = []
    detection_methods = []
    
    for i, prompt in enumerate(prompts):
        result = detector.predict(prompt)
        predictions.append('jailbreak_attempt' if result.is_jailbreak else 'benign')
        confidences.append(result.confidence)
        detection_methods.append(result.detection_method)
        
        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(prompts)}...")
    
    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    recall = recall_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    f1 = f1_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    cm = confusion_matrix(labels, predictions, labels=['benign', 'jailbreak_attempt'])
    
    tn, fp, fn, tp = cm.ravel()
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    # Detection method breakdown
    method_counts = {}
    for method in detection_methods:
        method_counts[method] = method_counts.get(method, 0) + 1
    
    print(f"\n  Results:")
    print(f"    Accuracy:  {accuracy:.2%}")
    print(f"    Precision: {precision:.2%}")
    print(f"    Recall:    {recall:.2%} (target: >80%)")
    print(f"    F1-Score:  {f1:.2%}")
    print(f"\n  Confusion Matrix:")
    print(f"                Predicted")
    print(f"              Benign  Jailbreak")
    print(f"Actual Benign    {tn:4d}     {fp:4d}")
    print(f"      Jailbreak  {fn:4d}     {tp:4d}")
    print(f"\n  False Negatives: {fn} (rate: {fn_rate:.2%}, target: <20%)")
    print(f"  False Positives:  {fp} (rate: {fp_rate:.2%})")
    
    print(f"\n  Detection Method Breakdown:")
    for method, count in sorted(method_counts.items()):
        print(f"    {method}: {count}")
    
    # Check if meets security requirements
    if recall >= 0.80 and fn_rate < 0.20:
        print(f"\n  [PASS] MEETS SECURITY REQUIREMENTS")
    else:
        print(f"\n  [FAIL] NEEDS IMPROVEMENT")
        if recall < 0.80:
            print(f"    - Recall ({recall:.2%}) below target (80%)")
        if fn_rate >= 0.20:
            print(f"    - FN Rate ({fn_rate:.2%}) above target (20%)")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fn': fn,
        'fp': fp,
        'fn_rate': fn_rate,
        'fp_rate': fp_rate,
        'method_counts': method_counts
    }

def main():
    """Main test function."""
    print("="*70)
    print("QUICK TEST: Hybrid Detector Fix")
    print("="*70)
    
    # Load model
    print("\n[1/3] Loading ML model...")
    ml_model = load_model()
    if not ml_model:
        print("[ERROR] Cannot proceed without ML model")
        return
    
    print("[OK] ML model loaded")
    
    # Load small test set
    print("\n[2/3] Loading test dataset...")
    prompts, labels = load_small_test_set()
    if len(prompts) == 0:
        print("[ERROR] No test data loaded")
        return
    
    jailbreak_count = sum(1 for l in labels if l == 'jailbreak_attempt')
    benign_count = len(labels) - jailbreak_count
    print(f"[OK] Test set: {len(prompts)} prompts ({jailbreak_count} jailbreak, {benign_count} benign)")
    
    # Test ML model alone
    print("\n[3/3] Running tests...")
    ml_detector = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=False,  # Disable escalation for ML-only test
        enable_whitelist=False
    )
    ml_results = test_detector(ml_detector, prompts, labels, "ML Model (Baseline)")
    
    # Test Hybrid detector with fix
    hybrid_detector = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=True,  # Enable escalation
        enable_whitelist=True
    )
    hybrid_results = test_detector(hybrid_detector, prompts, labels, "Hybrid Detector (With Fix)")
    
    # Compare results
    print("\n" + "="*70)
    print("COMPARISON")
    print("="*70)
    print(f"\n  ML Model Recall:    {ml_results['recall']:.2%}")
    print(f"  Hybrid Recall:      {hybrid_results['recall']:.2%}")
    print(f"  Difference:         {hybrid_results['recall'] - ml_results['recall']:.2%}")
    
    print(f"\n  ML Model FN Rate:   {ml_results['fn_rate']:.2%}")
    print(f"  Hybrid FN Rate:     {hybrid_results['fn_rate']:.2%}")
    print(f"  Difference:         {hybrid_results['fn_rate'] - ml_results['fn_rate']:.2%}")
    
    if abs(hybrid_results['recall'] - ml_results['recall']) < 0.05:
        print(f"\n  [SUCCESS] Hybrid detector matches ML model performance!")
    else:
        print(f"\n  [WARNING] Hybrid detector performance differs from ML model")
        if hybrid_results['recall'] < ml_results['recall']:
            print(f"     Hybrid is missing {ml_results['recall'] - hybrid_results['recall']:.2%} recall")

if __name__ == "__main__":
    main()

