"""
Test security model on a dataset that hasn't been used for training.

Uses: Prompt_INJECTION_And_Benign_DATASET.jsonl
This dataset contains both malicious and benign prompts with labels.
"""

import json
import pickle
from pathlib import Path
from collections import Counter
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from security_detector import SecurityJailbreakDetector
from train_security_model import SecurityJailbreakModel

def load_prompt_injection_dataset(file_path: Path):
    """Load Prompt_INJECTION_And_Benign_DATASET.jsonl."""
    prompts = []
    labels = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return prompts, labels
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            count = 0
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    prompt = data.get('prompt', '').strip()
                    if not prompt:
                        continue
                    
                    prompts.append(prompt)
                    
                    # Map dataset labels to our labels
                    dataset_label = data.get('label', '').lower().strip()
                    if dataset_label == 'malicious':
                        labels.append('jailbreak_attempt')
                    else:  # 'benign' or anything else
                        labels.append('benign')
                    
                    count += 1
                except json.JSONDecodeError as e:
                    print(f"    [WARNING] Skipping invalid JSON line: {e}")
                    continue
        
        print(f"    [OK] Loaded {len(prompts):,} prompts")
        print(f"    Label distribution:")
        label_counts = Counter(labels)
        for label, count in label_counts.items():
            print(f"      {label}: {count} ({count/len(labels)*100:.1f}%)")
        
    except Exception as e:
        print(f"  [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return prompts, labels

def evaluate_detector(detector, prompts, labels, detector_name: str):
    """Evaluate detector on prompts."""
    print(f"\n  Evaluating {detector_name}...")
    
    predictions = []
    whitelist_count = 0
    rule_count = 0
    ml_count = 0
    
    for i, prompt in enumerate(prompts):
        if (i + 1) % 100 == 0:
            print(f"    Processed {i + 1}/{len(prompts)} ({100*(i+1)/len(prompts):.1f}%)...")
        
        result = detector.predict(prompt)
        
        # Track detection method
        if result.detection_method == 'whitelist':
            whitelist_count += 1
        elif result.detection_method == 'rule':
            rule_count += 1
        elif result.detection_method in ['ml', 'hybrid']:
            ml_count += 1
        
        # Convert to binary: jailbreak_attempt = 1, benign = 0
        pred_label = 'jailbreak_attempt' if result.is_jailbreak else 'benign'
        predictions.append(pred_label)
    
    # Calculate metrics
    # Convert labels to binary for sklearn
    y_true = [1 if label == 'jailbreak_attempt' else 0 for label in labels]
    y_pred = [1 if pred == 'jailbreak_attempt' else 0 for pred in predictions]
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # Calculate rates
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    print(f"\n    {detector_name} Results:")
    print(f"      Accuracy:  {accuracy:.2%}")
    print(f"      Precision: {precision:.2%}")
    print(f"      Recall:    {recall:.2%} (target: >80%)")
    print(f"      F1-Score:  {f1:.2%}")
    print(f"\n    Confusion Matrix:")
    print(f"      [[{tn:4d} {fp:4d}]")
    print(f"       [{fn:4d} {tp:4d}]]")
    print(f"\n    False Negatives: {fn} (rate: {fn_rate:.2%}, target: <20%)")
    print(f"    False Positives: {fp} (rate: {fp_rate:.2%})")
    print(f"\n    Detection breakdown:")
    print(f"      Whitelist catches: {whitelist_count}")
    print(f"      Rule-based catches: {rule_count}")
    print(f"      ML catches: {ml_count}")
    
    if recall >= 0.80 and fn_rate < 0.20:
        print(f"\n    [PASS] MEETS SECURITY REQUIREMENTS")
    else:
        print(f"\n    [FAIL] NEEDS IMPROVEMENT")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'tp': int(tp),
        'fn_rate': fn_rate,
        'fp_rate': fp_rate,
        'whitelist_count': whitelist_count,
        'rule_count': rule_count,
        'ml_count': ml_count
    }

def main():
    """Main function."""
    print("="*70)
    print("TESTING ON UNSEEN DATASET")
    print("="*70)
    print("\nDataset: Prompt_INJECTION_And_Benign_DATASET.jsonl")
    print("This dataset has NOT been used for training.")
    print()
    
    # Load dataset
    dataset_path = Path("Prompt_INJECTION_And_Benign_DATASET.jsonl")
    prompts, labels = load_prompt_injection_dataset(dataset_path)
    
    if not prompts:
        print("\n[ERROR] No prompts loaded. Exiting.")
        return
    
    print(f"\n[TEST DATASET]")
    print(f"   Total prompts: {len(prompts):,}")
    label_counts = Counter(labels)
    for label, count in label_counts.items():
        print(f"   {label}: {count} ({count/len(labels)*100:.1f}%)")
    
    # Load model
    print(f"\n[1/2] Loading trained model...")
    model_dir = Path("models/security")
    
    try:
        from train_security_model import SecurityJailbreakModel
        
        model = SecurityJailbreakModel(jailbreak_threshold=0.15)
        
        with open(model_dir / "security_model.pkl", 'rb') as f:
            model.model = pickle.load(f)
        with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open(model_dir / "security_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        
        # Load threshold if available
        threshold_file = model_dir / "security_threshold.txt"
        if threshold_file.exists():
            with open(threshold_file, 'r') as f:
                model.jailbreak_threshold = float(f.read().strip())
        
        model.is_trained = True
        print(f"  [OK] Model loaded (threshold: {model.jailbreak_threshold})")
    except FileNotFoundError as e:
        print(f"  [ERROR] Model file not found: {e}")
        print(f"  Please train the model first using train_security_model.py")
        return
    except Exception as e:
        print(f"  [ERROR] Failed to load model: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Create detector
    print(f"\n[2/2] Creating security detector...")
    detector = SecurityJailbreakDetector(
        ml_model=model,
        jailbreak_threshold=0.15,
        prefer_false_positives=True,
        enable_whitelist=True,
        enable_escalation=True,  # Enable escalation layer for v1.1
        escalation_low_threshold=0.25,
        escalation_high_threshold=0.55
    )
    print(f"  [OK] Detector created")
    print(f"      Threshold: {detector.jailbreak_threshold}")
    print(f"      Whitelist: {'Enabled' if detector.enable_whitelist else 'Disabled'}")
    
    # Evaluate
    print(f"\n" + "="*70)
    print("EVALUATION RESULTS")
    print("="*70)
    
    results = evaluate_detector(detector, prompts, labels, "Hybrid Detector (Rule + ML + Whitelist)")
    
    # Save results
    print(f"\n[3/3] Saving results...")
    results_file = Path("test_results_unseen_dataset.json")
    output_data = {
        'dataset': 'Prompt_INJECTION_And_Benign_DATASET.jsonl',
        'total_prompts': len(prompts),
        'label_distribution': dict(Counter(labels)),
        'results': results
    }
    
    try:
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Results saved to {results_file}")
    except Exception as e:
        print(f"  [WARNING] Failed to save results: {e}")
    
    print("\n" + "="*70)
    print("EVALUATION SUMMARY")
    print("="*70)
    print(f"\n[TEST DATASET]")
    print(f"   Total prompts: {len(prompts):,}")
    for label, count in label_counts.items():
        print(f"   {label}: {count} ({count/len(labels)*100:.1f}%)")
    
    print(f"\n[RESULTS] Hybrid Detector:")
    print(f"   Recall: {results['recall']:.2%} (target: >80%)")
    print(f"   FN Rate: {results['fn_rate']:.2%} (target: <20%)")
    if results['recall'] >= 0.80 and results['fn_rate'] < 0.20:
        print(f"   [PASS] MEETS SECURITY REQUIREMENTS")
    else:
        print(f"   [FAIL] NEEDS IMPROVEMENT")
    print(f"   Precision: {results['precision']:.2%}")
    print(f"   FPR: {results['fp_rate']:.2%}")
    print(f"   Accuracy: {results['accuracy']:.2%}")
    print(f"\n   Detection breakdown:")
    print(f"     Whitelist: {results['whitelist_count']}")
    print(f"     Rule-based: {results['rule_count']}")
    print(f"     ML: {results['ml_count']}")
    
    print("="*70)

if __name__ == "__main__":
    main()

