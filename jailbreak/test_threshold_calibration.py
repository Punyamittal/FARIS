"""
Test different thresholds on AI Agent Evasion dataset to find optimal threshold.
"""

import json
import pickle
from pathlib import Path
from collections import Counter
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from security_detector import SecurityJailbreakDetector
from train_security_model import SecurityJailbreakModel

def load_ai_agent_evasion_dataset(file_path: Path):
    """Load AI Agent Evasion Dataset.jsonl."""
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
                    entry = json.loads(line)
                    prompt = entry.get('prompt', '').strip()
                    if not prompt:
                        continue
                    
                    prompts.append(prompt)
                    
                    dataset_label = entry.get('label', '').lower()
                    if dataset_label == 'malicious':
                        labels.append('jailbreak_attempt')
                    else:
                        labels.append('benign')
                    
                    count += 1
                except json.JSONDecodeError:
                    continue
        
        print(f"    [OK] Loaded {len(prompts):,} prompts")
    except Exception as e:
        print(f"    [ERROR] Failed to load: {e}")
    
    return prompts, labels

def test_threshold(model, prompts, labels, threshold: float):
    """Test model at specific threshold."""
    predictions = []
    
    for prompt in prompts:
        result = model.predict(prompt)
        jailbreak_prob = result.get('jailbreak_probability', 0.0)
        is_jailbreak = jailbreak_prob >= threshold
        predictions.append('jailbreak_attempt' if is_jailbreak else 'benign')
    
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
        'false_positive_rate': fpr
    }

def main():
    """Test different thresholds."""
    print("="*70)
    print("THRESHOLD CALIBRATION TEST")
    print("="*70)
    
    # Load dataset
    print("\n[1/3] Loading AI Agent Evasion dataset...")
    prompts, labels = load_ai_agent_evasion_dataset(Path("AI Agent Evasion Dataset.jsonl"))
    
    if not prompts:
        print("[ERROR] No data loaded!")
        return
    
    label_counts = Counter(labels)
    print(f"  Total: {len(prompts):,} prompts")
    for label, count in label_counts.items():
        print(f"    {label}: {count:,} ({count/len(labels)*100:.1f}%)")
    
    # Load model
    print("\n[2/3] Loading security model...")
    try:
        model = SecurityJailbreakModel(jailbreak_threshold=0.15)
        model_dir = Path("models/security")
        
        with open(model_dir / "security_model.pkl", 'rb') as f:
            model.model = pickle.load(f)
        with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open(model_dir / "security_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        model.is_trained = True
        
        print("  [OK] Model loaded")
    except Exception as e:
        print(f"  [ERROR] Failed to load model: {e}")
        return
    
    # Test different thresholds
    print("\n[3/3] Testing different thresholds...")
    thresholds = [0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    
    results = []
    for threshold in thresholds:
        print(f"\n  Testing threshold: {threshold}")
        result = test_threshold(model, prompts, labels, threshold)
        results.append(result)
        
        print(f"    Recall:    {result['recall']:.2%} (target: >80%)")
        print(f"    Precision: {result['precision']:.2%}")
        print(f"    FPR:       {result['false_positive_rate']:.2%} (target: <20%)")
        print(f"    FNR:       {result['false_negative_rate']:.2%} (target: <20%)")
        print(f"    F1-Score:  {result['f1']:.2%}")
        
        # Check if meets requirements
        if result['recall'] >= 0.80 and result['false_negative_rate'] < 0.20:
            if result['false_positive_rate'] < 0.20:
                print(f"    [PASS] MEETS ALL REQUIREMENTS")
            else:
                print(f"    [PARTIAL] High recall but high FPR")
        else:
            print(f"    [FAIL] Low recall or high FNR")
    
    # Find best threshold
    print("\n" + "="*70)
    print("THRESHOLD ANALYSIS")
    print("="*70)
    
    # Find threshold with best balance (recall >80%, FPR <20%, FNR <20%)
    best_threshold = None
    best_score = -1
    
    for result in results:
        recall_ok = result['recall'] >= 0.80
        fnr_ok = result['false_negative_rate'] < 0.20
        fpr_ok = result['false_positive_rate'] < 0.20
        
        if recall_ok and fnr_ok:
            # Score: prioritize low FPR while maintaining recall
            score = result['recall'] * (1 - result['false_positive_rate'])
            if score > best_score:
                best_score = score
                best_threshold = result['threshold']
    
    if best_threshold:
        print(f"\n  Recommended threshold: {best_threshold}")
        best_result = next(r for r in results if r['threshold'] == best_threshold)
        print(f"    Recall:    {best_result['recall']:.2%}")
        print(f"    Precision: {best_result['precision']:.2%}")
        print(f"    FPR:       {best_result['false_positive_rate']:.2%}")
        print(f"    FNR:       {best_result['false_negative_rate']:.2%}")
    else:
        print("\n  No threshold meets all requirements")
        print("  Consider:")
        print("    - Adding more benign training data")
        print("    - Improving model calibration")
        print("    - Using different threshold for different contexts")
    
    # Summary table
    print("\n" + "="*70)
    print("SUMMARY TABLE")
    print("="*70)
    print(f"\n{'Threshold':<12} {'Recall':<10} {'Precision':<12} {'FPR':<10} {'FNR':<10} {'Status':<15}")
    print("-" * 70)
    for result in results:
        recall_ok = result['recall'] >= 0.80
        fnr_ok = result['false_negative_rate'] < 0.20
        fpr_ok = result['false_positive_rate'] < 0.20
        
        if recall_ok and fnr_ok and fpr_ok:
            status = "[PASS]"
        elif recall_ok and fnr_ok:
            status = "[PARTIAL]"
        else:
            status = "[FAIL]"
        
        print(f"{result['threshold']:<12.2f} {result['recall']:<10.2%} {result['precision']:<12.2%} "
              f"{result['false_positive_rate']:<10.2%} {result['false_negative_rate']:<10.2%} {status:<15}")
    
    # Save results (convert numpy types to Python types)
    results_file = Path("threshold_calibration_results.json")
    serializable_results = []
    for r in results:
        serializable_results.append({
            'threshold': float(r['threshold']),
            'accuracy': float(r['accuracy']),
            'precision': float(r['precision']),
            'recall': float(r['recall']),
            'f1': float(r['f1']),
            'false_negatives': int(r['false_negatives']),
            'false_positives': int(r['false_positives']),
            'false_negative_rate': float(r['false_negative_rate']),
            'false_positive_rate': float(r['false_positive_rate'])
        })
    
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            'best_threshold': float(best_threshold) if best_threshold else None,
            'results': serializable_results
        }, f, indent=2)
    
    print(f"\n[OK] Results saved to {results_file}")

if __name__ == "__main__":
    main()

