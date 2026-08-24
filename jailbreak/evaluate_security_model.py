"""
Security-focused evaluation script.

Evaluates:
- Jailbreak recall (target: >80%)
- False negative rate (target: <20%)
- Precision at different thresholds
- Rule-based vs ML performance
"""

import json
import pickle
from pathlib import Path
from collections import Counter
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc
)
import numpy as np

from security_detector import SecurityJailbreakDetector, RuleBasedJailbreakDetector

def load_test_data(json_file: Path):
    """Load test data."""
    prompts = []
    labels = []
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    for item in data:
        prompt = item.get('prompt', '').strip()
        if prompt:
            is_jailbreak = item.get('jailbroken', False)
            labels.append('jailbreak_attempt' if is_jailbreak else 'benign')
            prompts.append(prompt)
    
    return prompts, labels

def evaluate_at_threshold(model, prompts, labels, threshold: float):
    """Evaluate model at specific threshold."""
    predictions = []
    confidences = []
    
    for prompt in prompts:
        result = model.predict(prompt)
        jailbreak_prob = result.get('jailbreak_probability', 0.0)
        is_jailbreak = jailbreak_prob >= threshold
        
        predictions.append('jailbreak_attempt' if is_jailbreak else 'benign')
        confidences.append(jailbreak_prob)
    
    # Metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    recall = recall_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    f1 = f1_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    cm = confusion_matrix(labels, predictions, labels=['benign', 'jailbreak_attempt'])
    tn, fp, fn, tp = cm.ravel()
    
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        'threshold': threshold,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'false_negatives': fn,
        'false_positives': fp,
        'false_negative_rate': fnr,
        'false_positive_rate': fpr,
        'confusion_matrix': cm.tolist()
    }

def main():
    """Main evaluation."""
    print("="*70)
    print("SECURITY-FOCUSED MODEL EVALUATION")
    print("="*70)
    
    # Load test data
    test_file = Path("jailbreak_test_dataset.json")
    if not test_file.exists():
        print(f"[ERROR] Test file not found: {test_file}")
        return
    
    print(f"\n[1/3] Loading test data...")
    prompts, labels = load_test_data(test_file)
    print(f"  Loaded {len(prompts)} examples")
    
    label_counts = Counter(labels)
    for label, count in label_counts.items():
        print(f"    {label}: {count} ({count/len(labels)*100:.1f}%)")
    
    # Load model
    print(f"\n[2/3] Loading security model...")
    try:
        from train_security_model import SecurityJailbreakModel
        
        model = SecurityJailbreakModel(jailbreak_threshold=0.15)
        
        model_dir = Path("models/security")
        with open(model_dir / "security_model.pkl", 'rb') as f:
            model.model = pickle.load(f)
        with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open(model_dir / "security_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        
        with open(model_dir / "security_threshold.txt", 'r') as f:
            model.jailbreak_threshold = float(f.read().strip())
        
        model.is_trained = True
        print(f"  [OK] Model loaded (threshold: {model.jailbreak_threshold})")
        
    except Exception as e:
        print(f"  [ERROR] Failed to load model: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test rule-based detector
    print(f"\n[3/3] Evaluating...")
    print("\n" + "-"*70)
    print("RULE-BASED DETECTOR")
    print("-"*70)
    
    rule_detector = RuleBasedJailbreakDetector()
    rule_predictions = []
    rule_confidences = []
    
    for prompt in prompts:
        is_jb, patterns, conf = rule_detector.detect(prompt)
        rule_predictions.append('jailbreak_attempt' if is_jb else 'benign')
        rule_confidences.append(conf)
    
    rule_recall = recall_score(labels, rule_predictions, pos_label='jailbreak_attempt', zero_division=0)
    rule_precision = precision_score(labels, rule_predictions, pos_label='jailbreak_attempt', zero_division=0)
    rule_cm = confusion_matrix(labels, rule_predictions, labels=['benign', 'jailbreak_attempt'])
    rule_tn, rule_fp, rule_fn, rule_tp = rule_cm.ravel()
    
    print(f"  Recall:    {rule_recall:.2%}")
    print(f"  Precision: {rule_precision:.2%}")
    print(f"  False Negatives: {rule_fn} (rate: {rule_fn/(rule_fn+rule_tp)*100:.2f}%)")
    print(f"  False Positives:  {rule_fp} (rate: {rule_fp/(rule_fp+rule_tn)*100:.2f}%)")
    
    # Test ML model at different thresholds
    print("\n" + "-"*70)
    print("ML MODEL AT DIFFERENT THRESHOLDS")
    print("-"*70)
    
    thresholds = [0.1, 0.15, 0.2, 0.3, 0.5]
    results = []
    
    for threshold in thresholds:
        model.jailbreak_threshold = threshold
        result = evaluate_at_threshold(model, prompts, labels, threshold)
        results.append(result)
        
        print(f"\n  Threshold: {threshold}")
        print(f"    Recall:    {result['recall']:.2%} ⭐ (target: >80%)")
        print(f"    Precision: {result['precision']:.2%}")
        print(f"    F1:        {result['f1']:.2%}")
        print(f"    FN Rate:   {result['false_negative_rate']:.2%} (target: <20%)")
        print(f"    FP Rate:   {result['false_positive_rate']:.2%}")
    
    # Find best threshold (recall >= 0.80, FNR < 0.20)
    best_result = None
    for result in results:
        if result['recall'] >= 0.80 and result['false_negative_rate'] < 0.20:
            if best_result is None or result['f1'] > best_result['f1']:
                best_result = result
    
    # Test hybrid (rule + ML)
    print("\n" + "-"*70)
    print("HYBRID DETECTOR (Rule + ML)")
    print("-"*70)
    
    hybrid_detector = SecurityJailbreakDetector(
        ml_model=model,
        jailbreak_threshold=0.15
    )
    
    hybrid_predictions = []
    hybrid_confidences = []
    rule_catches = 0
    ml_catches = 0
    
    for prompt in prompts:
        result = hybrid_detector.predict(prompt)
        hybrid_predictions.append('jailbreak_attempt' if result.is_jailbreak else 'benign')
        hybrid_confidences.append(result.confidence)
        
        if result.is_jailbreak:
            if result.detection_method == 'rule':
                rule_catches += 1
            elif result.detection_method in ['ml', 'hybrid']:
                ml_catches += 1
    
    hybrid_recall = recall_score(labels, hybrid_predictions, pos_label='jailbreak_attempt', zero_division=0)
    hybrid_precision = precision_score(labels, hybrid_predictions, pos_label='jailbreak_attempt', zero_division=0)
    hybrid_f1 = f1_score(labels, hybrid_predictions, pos_label='jailbreak_attempt', zero_division=0)
    hybrid_cm = confusion_matrix(labels, hybrid_predictions, labels=['benign', 'jailbreak_attempt'])
    hybrid_tn, hybrid_fp, hybrid_fn, hybrid_tp = hybrid_cm.ravel()
    
    print(f"  Recall:    {hybrid_recall:.2%} ⭐")
    print(f"  Precision: {hybrid_precision:.2%}")
    print(f"  F1:        {hybrid_f1:.2%}")
    print(f"  False Negatives: {hybrid_fn} (rate: {hybrid_fn/(hybrid_fn+hybrid_tp)*100:.2f}%)")
    print(f"  False Positives:  {hybrid_fp} (rate: {hybrid_fp/(hybrid_fp+hybrid_tn)*100:.2f}%)")
    print(f"\n  Detection breakdown:")
    print(f"    Rule-based catches: {rule_catches}")
    print(f"    ML catches: {ml_catches}")
    
    # Summary
    print("\n" + "="*70)
    print("EVALUATION SUMMARY")
    print("="*70)
    
    print(f"\n✅ Rule-Based Detector:")
    print(f"   Recall: {rule_recall:.2%}, FN Rate: {rule_fn/(rule_fn+rule_tp)*100:.2f}%")
    
    if best_result:
        print(f"\n✅ Best ML Threshold: {best_result['threshold']}")
        print(f"   Recall: {best_result['recall']:.2%}, FN Rate: {best_result['false_negative_rate']:.2f}%")
    else:
        print(f"\n⚠️  No threshold meets security requirements (recall >80%, FNR <20%)")
    
    print(f"\n✅ Hybrid Detector:")
    print(f"   Recall: {hybrid_recall:.2%}, FN Rate: {hybrid_fn/(hybrid_fn+hybrid_tp)*100:.2f}%")
    
    if hybrid_recall >= 0.80 and hybrid_fn/(hybrid_fn+hybrid_tp) < 0.20:
        print("\n🎉 HYBRID MODEL MEETS SECURITY REQUIREMENTS!")
    else:
        print("\n⚠️  HYBRID MODEL NEEDS IMPROVEMENT")
    
    # Save results
    results_file = Path("security_evaluation_results.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            'rule_based': {
                'recall': float(rule_recall),
                'precision': float(rule_precision),
                'false_negatives': int(rule_fn),
                'false_positive_rate': float(rule_fp/(rule_fp+rule_tn)) if (rule_fp+rule_tn) > 0 else 0.0
            },
            'ml_at_thresholds': results,
            'hybrid': {
                'recall': float(hybrid_recall),
                'precision': float(hybrid_precision),
                'f1': float(hybrid_f1),
                'false_negatives': int(hybrid_fn),
                'false_negative_rate': float(hybrid_fn/(hybrid_fn+hybrid_tp)) if (hybrid_fn+hybrid_tp) > 0 else 0.0
            },
            'best_threshold': best_result['threshold'] if best_result else None
        }, f, indent=2)
    
    print(f"\n[OK] Results saved to {results_file}")

if __name__ == "__main__":
    main()




