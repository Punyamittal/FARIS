"""
Test security model on prompt-injection-dataset.csv
"""

import json
import csv
import pickle
from pathlib import Path
from collections import Counter
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from security_detector import SecurityJailbreakDetector, RuleBasedJailbreakDetector
from train_security_model import SecurityJailbreakModel

def load_prompt_injection_dataset(file_path: Path):
    """Load prompt-injection-dataset.csv."""
    prompts = []
    labels = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return prompts, labels
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                prompt = row.get('text', '').strip()
                if not prompt:
                    continue
                
                prompts.append(prompt)
                
                # Map dataset labels to our labels
                # 1 = prompt injection (jailbreak), 0 = benign
                dataset_label = row.get('label', '0').strip()
                if dataset_label == '1':
                    labels.append('jailbreak_attempt')
                else:  # '0' or empty
                    labels.append('benign')
                
                count += 1
        
        print(f"    [OK] Loaded {len(prompts):,} prompts")
        
        # Show label distribution
        if labels:
            label_counts = Counter(labels)
            print(f"    Label distribution:")
            for label, label_count in label_counts.items():
                print(f"      {label}: {label_count:,} ({label_count/len(labels)*100:.1f}%)")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return prompts, labels

def evaluate_detector(detector, prompts, labels, detector_name: str):
    """Evaluate a detector on prompts."""
    print(f"\n  Evaluating {detector_name}...")
    
    predictions = []
    confidences = []
    rule_catches = 0
    ml_catches = 0
    
    total = len(prompts)
    
    for i, prompt in enumerate(prompts):
        if (i + 1) % 50 == 0:
            print(f"    Processed {i + 1:,}/{total:,} ({100*(i+1)/total:.1f}%)...")
        
        try:
            if isinstance(detector, SecurityJailbreakDetector):
                result = detector.predict(prompt)
                predictions.append('jailbreak_attempt' if result.is_jailbreak else 'benign')
                confidences.append(result.confidence)
                
                if result.is_jailbreak:
                    if result.detection_method == 'rule':
                        rule_catches += 1
                    elif result.detection_method in ['ml', 'hybrid']:
                        ml_catches += 1
            elif isinstance(detector, SecurityJailbreakModel):
                # ML model - use predict() method
                result = detector.predict(prompt)
                predictions.append(result['label'])
                confidences.append(result['confidence'])
                if result['label'] == 'jailbreak_attempt':
                    ml_catches += 1
            else:
                # Rule-based only
                is_jb, _, conf = detector.detect(prompt)
                predictions.append('jailbreak_attempt' if is_jb else 'benign')
                confidences.append(conf)
                if is_jb:
                    rule_catches += 1
        except Exception as e:
            if (i + 1) % 10 == 0:  # Only print every 10th error to avoid spam
                print(f"    [ERROR] Prompt {i+1}: {e}")
            predictions.append('benign')
            confidences.append(0.0)
    
    # Metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    recall = recall_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    f1 = f1_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    cm = confusion_matrix(labels, predictions, labels=['benign', 'jailbreak_attempt'])
    tn, fp, fn, tp = cm.ravel()
    
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    print(f"\n    {detector_name} Results:")
    print(f"      Accuracy:  {accuracy:.2%}")
    print(f"      Precision: {precision:.2%}")
    print(f"      Recall:    {recall:.2%} (target: >80%)")
    print(f"      F1-Score:  {f1:.2%}")
    print(f"      False Negatives: {fn:,} (rate: {fnr:.2%}, target: <20%)")
    print(f"      False Positives:  {fp:,} (rate: {fpr:.2%})")
    
    if isinstance(detector, SecurityJailbreakDetector) and rule_catches + ml_catches > 0:
        print(f"      Detection breakdown:")
        print(f"        Rule-based catches: {rule_catches:,}")
        print(f"        ML catches: {ml_catches:,}")
    
    return {
        'detector': detector_name,
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_negatives': int(fn),
        'false_positives': int(fp),
        'false_negative_rate': float(fnr),
        'false_positive_rate': float(fpr),
        'confusion_matrix': cm.tolist(),
        'rule_catches': rule_catches,
        'ml_catches': ml_catches
    }

def main():
    """Main evaluation function."""
    print("="*70)
    print("TESTING SECURITY MODEL ON PROMPT INJECTION DATASET")
    print("="*70)
    
    # Load test dataset
    print("\n[1/4] Loading test dataset...")
    
    prompts, labels = load_prompt_injection_dataset(Path("prompt-injection-dataset.csv"))
    
    if not prompts:
        print("[ERROR] No test data loaded!")
        return
    
    print(f"\n  Total test prompts: {len(prompts):,}")
    
    # Load ML model
    print(f"\n[2/4] Loading security model...")
    ml_model = None
    
    try:
        model = SecurityJailbreakModel(jailbreak_threshold=0.15)
        
        model_dir = Path("models/security")
        if not model_dir.exists():
            print(f"  [WARNING] Model directory not found: {model_dir}")
            print(f"  Will test with rule-based detector only")
        else:
            with open(model_dir / "security_model.pkl", 'rb') as f:
                model.model = pickle.load(f)
            with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
                model.vectorizer = pickle.load(f)
            with open(model_dir / "security_encoder.pkl", 'rb') as f:
                model.label_encoder = pickle.load(f)
            
            with open(model_dir / "security_threshold.txt", 'r') as f:
                model.jailbreak_threshold = float(f.read().strip())
            
            model.is_trained = True
            ml_model = model
            print(f"  [OK] ML model loaded (threshold: {model.jailbreak_threshold})")
    except Exception as e:
        print(f"  [WARNING] Failed to load ML model: {e}")
        import traceback
        traceback.print_exc()
        print(f"  Will test with rule-based detector only")
    
    # Test rule-based detector
    print(f"\n[3/4] Testing detectors...")
    rule_detector = RuleBasedJailbreakDetector()
    
    rule_results = evaluate_detector(rule_detector, prompts, labels, "Rule-Based Detector")
    
    # Test ML model (if available)
    ml_results = None
    hybrid_results = None
    
    if ml_model:
        # Test ML only
        ml_results = evaluate_detector(ml_model, prompts, labels, "ML Model")
        
        # Test hybrid (rule + ML)
        hybrid_detector = SecurityJailbreakDetector(
            ml_model=ml_model,
            jailbreak_threshold=0.15
        )
        hybrid_results = evaluate_detector(hybrid_detector, prompts, labels, "Hybrid Detector (Rule + ML)")
    
    # Summary
    print("\n" + "="*70)
    print("EVALUATION SUMMARY")
    print("="*70)
    
    print(f"\n[TEST DATASET]")
    print(f"   Total prompts: {len(prompts):,}")
    label_counts = Counter(labels)
    for label, count in label_counts.items():
        print(f"   {label}: {count:,} ({count/len(labels)*100:.1f}%)")
    
    print(f"\n[RESULTS] Rule-Based Detector:")
    print(f"   Recall: {rule_results['recall']:.2%} (target: >80%)")
    print(f"   FN Rate: {rule_results['false_negative_rate']:.2%} (target: <20%)")
    if rule_results['recall'] >= 0.80 and rule_results['false_negative_rate'] < 0.20:
        print("   [PASS] MEETS SECURITY REQUIREMENTS")
    else:
        print("   [FAIL] NEEDS IMPROVEMENT")
    
    if ml_results:
        print(f"\n[RESULTS] ML Model:")
        print(f"   Recall: {ml_results['recall']:.2%} (target: >80%)")
        print(f"   FN Rate: {ml_results['false_negative_rate']:.2%} (target: <20%)")
        if ml_results['recall'] >= 0.80 and ml_results['false_negative_rate'] < 0.20:
            print("   [PASS] MEETS SECURITY REQUIREMENTS")
        else:
            print("   [FAIL] NEEDS IMPROVEMENT")
    
    if hybrid_results:
        print(f"\n[RESULTS] Hybrid Detector (Best):")
        print(f"   Recall: {hybrid_results['recall']:.2%} (target: >80%)")
        print(f"   FN Rate: {hybrid_results['false_negative_rate']:.2%} (target: <20%)")
        if hybrid_results['recall'] >= 0.80 and hybrid_results['false_negative_rate'] < 0.20:
            print("   [PASS] MEETS SECURITY REQUIREMENTS")
        else:
            print("   [FAIL] NEEDS IMPROVEMENT")
    
    # Save results
    print(f"\n[4/4] Saving results...")
    results = {
        'test_dataset': {
            'file': 'prompt-injection-dataset.csv',
            'total_prompts': len(prompts),
            'label_distribution': dict(label_counts)
        },
        'rule_based': rule_results
    }
    
    if ml_results:
        results['ml_model'] = ml_results
    if hybrid_results:
        results['hybrid'] = hybrid_results
    
    results_file = Path("test_results_prompt_injection.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"  [OK] Results saved to {results_file}")
    print("="*70)

if __name__ == "__main__":
    main()
