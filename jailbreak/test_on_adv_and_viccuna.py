"""
Test security model on adv_prompts.csv and viccuna_prompts.csv
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

def load_csv_test_data(file_path: Path, prompt_column: str = "Prompt"):
    """Load CSV test dataset."""
    prompts = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return prompts
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                # Try different column name variations
                prompt = row.get(prompt_column, '') or row.get('prompt', '') or row.get('text', '')
                prompt = prompt.strip()
                if prompt:
                    prompts.append(prompt)
                    count += 1
                    if count % 10000 == 0:
                        print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(prompts):,} prompts")
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return prompts

def evaluate_detector(detector, prompts, labels, detector_name: str):
    """Evaluate a detector on prompts."""
    print(f"\n  Evaluating {detector_name}...")
    
    predictions = []
    confidences = []
    rule_catches = 0
    ml_catches = 0
    
    for i, prompt in enumerate(prompts):
        if (i + 1) % 5000 == 0:
            print(f"    Processed {i + 1}/{len(prompts)}...")
        
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
            if (i + 1) % 100 == 0:  # Only print every 100th error to avoid spam
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
    print(f"      False Negatives: {fn} (rate: {fnr:.2%}, target: <20%)")
    print(f"      False Positives:  {fp} (rate: {fpr:.2%})")
    
    if isinstance(detector, SecurityJailbreakDetector) and rule_catches + ml_catches > 0:
        print(f"      Detection breakdown:")
        print(f"        Rule-based catches: {rule_catches}")
        print(f"        ML catches: {ml_catches}")
    
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
        'confusion_matrix': cm.tolist()
    }

def main():
    """Main evaluation function."""
    print("="*70)
    print("TESTING SECURITY MODEL ON ADV_PROMPTS AND VICUNA_PROMPTS")
    print("="*70)
    
    # Load test datasets
    print("\n[1/4] Loading test datasets...")
    
    adv_prompts = load_csv_test_data(Path("adv_prompts.csv"), "Prompt")
    viccuna_prompts = load_csv_test_data(Path("viccuna_prompts.csv"), "Prompt")
    
    if not adv_prompts and not viccuna_prompts:
        print("[ERROR] No test data loaded!")
        return
    
    # Combine prompts (both are jailbreak datasets)
    all_prompts = adv_prompts + viccuna_prompts
    # All prompts in these datasets are jailbreak attempts
    all_labels = ['jailbreak_attempt'] * len(all_prompts)
    
    print(f"\n  Total test prompts: {len(all_prompts):,}")
    print(f"    adv_prompts: {len(adv_prompts):,}")
    print(f"    viccuna_prompts: {len(viccuna_prompts):,}")
    print(f"    All labels: jailbreak_attempt (100%)")
    
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
        print(f"  Will test with rule-based detector only")
    
    # Test rule-based detector
    print(f"\n[3/4] Testing detectors...")
    rule_detector = RuleBasedJailbreakDetector()
    
    rule_results = evaluate_detector(rule_detector, all_prompts, all_labels, "Rule-Based Detector")
    
    # Test ML model (if available)
    ml_results = None
    hybrid_results = None
    
    if ml_model:
        # Test ML only
        ml_results = evaluate_detector(ml_model, all_prompts, all_labels, "ML Model")
        
        # Test hybrid (rule + ML)
        hybrid_detector = SecurityJailbreakDetector(
            ml_model=ml_model,
            jailbreak_threshold=0.15
        )
        hybrid_results = evaluate_detector(hybrid_detector, all_prompts, all_labels, "Hybrid Detector (Rule + ML)")
    
    # Summary
    print("\n" + "="*70)
    print("EVALUATION SUMMARY")
    print("="*70)
    
    print(f"\n[TEST DATASET]")
    print(f"   Total prompts: {len(all_prompts):,}")
    print(f"   All are jailbreak attempts (100%)")
    
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
        'test_datasets': {
            'adv_prompts': len(adv_prompts),
            'viccuna_prompts': len(viccuna_prompts),
            'total': len(all_prompts)
        },
        'rule_based': rule_results
    }
    
    if ml_results:
        results['ml_model'] = ml_results
    if hybrid_results:
        results['hybrid'] = hybrid_results
    
    results_file = Path("test_results_adv_viccuna.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"  [OK] Results saved to {results_file}")
    print("="*70)

if __name__ == "__main__":
    main()

