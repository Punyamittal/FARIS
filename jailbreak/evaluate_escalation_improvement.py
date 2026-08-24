"""
Comprehensive Evaluation: Escalation Layer Impact

This script evaluates the security detector with and without escalation
to measure the improvement from the confidence-based escalation layer.

Tests on multiple datasets to get comprehensive metrics.
"""

import json
import pickle
from pathlib import Path
from collections import Counter, defaultdict
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix
)

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

def load_test_datasets():
    """Load all available test datasets."""
    datasets = []
    
    # Dataset 1: Prompt_INJECTION_And_Benign_DATASET.jsonl
    dataset_path = Path("Prompt_INJECTION_And_Benign_DATASET.jsonl")
    if dataset_path.exists():
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    prompt = data.get('prompt', '').strip()
                    if not prompt:
                        continue
                    prompts.append(prompt)
                    dataset_label = data.get('label', '').lower().strip()
                    labels.append('jailbreak_attempt' if dataset_label == 'malicious' else 'benign')
                except json.JSONDecodeError:
                    continue
        if prompts:
            datasets.append(("Prompt_INJECTION_And_Benign_DATASET.jsonl", prompts, labels))
    
    # Dataset 2: AI Agent Evasion Dataset.jsonl
    dataset_path = Path("AI Agent Evasion Dataset.jsonl")
    if dataset_path.exists():
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    prompt = data.get('prompt', '').strip()
                    if not prompt:
                        continue
                    prompts.append(prompt)
                    dataset_label = data.get('label', '').lower().strip()
                    labels.append('jailbreak_attempt' if dataset_label == 'malicious' else 'benign')
                except json.JSONDecodeError:
                    continue
        if prompts:
            datasets.append(("AI Agent Evasion Dataset.jsonl", prompts, labels))
    
    # Dataset 3: prompt-injection-dataset.csv
    dataset_path = Path("prompt-injection-dataset.csv")
    if dataset_path.exists():
        import csv
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                prompt = (row.get('prompt', '') or row.get('text', '')).strip()
                if not prompt:
                    continue
                prompts.append(prompt)
                label = row.get('label', 'benign').lower().strip()
                labels.append('jailbreak_attempt' if label in ['jailbreak_attempt', 'jailbreak', 'malicious', 'injection'] else 'benign')
        if prompts:
            datasets.append(("prompt-injection-dataset.csv", prompts, labels))
    
    return datasets

def evaluate_detector(detector, prompts, labels, detector_name: str):
    """Evaluate detector and return metrics."""
    predictions = []
    confidences = []
    false_negatives = []
    escalation_count = 0
    
    for i, (prompt, label) in enumerate(zip(prompts, labels)):
        if (i + 1) % 500 == 0:
            print(f"    Processed {i + 1}/{len(prompts)} ({100*(i+1)/len(prompts):.1f}%)...")
        
        result = detector.predict(prompt)
        pred_label = 'jailbreak_attempt' if result.is_jailbreak else 'benign'
        predictions.append(pred_label)
        confidences.append(result.confidence)
        
        # Track escalation
        if result.detection_method == 'escalated':
            escalation_count += 1
        
        # Track false negatives
        if label == 'jailbreak_attempt' and pred_label == 'benign':
            false_negatives.append({
                'prompt': prompt,
                'confidence': result.confidence,
                'jailbreak_probability': result.jailbreak_probability,
                'detection_method': result.detection_method,
                'risk_score': result.risk_score,
                'escalation_action': result.escalation_action
            })
    
    # Calculate metrics
    y_true = [1 if label == 'jailbreak_attempt' else 0 for label in labels]
    y_pred = [1 if pred == 'jailbreak_attempt' else 0 for pred in predictions]
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'tp': int(tp),
        'fn_rate': float(fn_rate),
        'fp_rate': float(fp_rate),
        'escalation_count': escalation_count,
        'false_negatives': false_negatives
    }

def main():
    """Main evaluation function."""
    print("="*70)
    print("ESCALATION LAYER IMPACT EVALUATION")
    print("="*70)
    
    # Load model
    print("\n[1/4] Loading ML model...")
    ml_model = load_model()
    if not ml_model:
        print("[ERROR] Cannot proceed without ML model")
        return
    
    print("[OK] Model loaded")
    
    # Load test datasets
    print("\n[2/4] Loading test datasets...")
    datasets = load_test_datasets()
    print(f"[OK] Loaded {len(datasets)} datasets")
    
    total_prompts = sum(len(prompts) for _, prompts, _ in datasets)
    total_jailbreaks = sum(sum(1 for l in labels if l == 'jailbreak_attempt') for _, _, labels in datasets)
    print(f"  Total prompts: {total_prompts:,}")
    print(f"  Total jailbreak attempts: {total_jailbreaks:,}")
    
    # Evaluate with escalation disabled
    print("\n[3/4] Evaluating WITHOUT escalation layer...")
    detector_no_escalation = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=False
    )
    
    all_results_no_escalation = {}
    all_fns_no_escalation = []
    
    for dataset_name, prompts, labels in datasets:
        print(f"\n  Testing {dataset_name} ({len(prompts)} prompts)...")
        results = evaluate_detector(detector_no_escalation, prompts, labels, "No Escalation")
        all_results_no_escalation[dataset_name] = results
        all_fns_no_escalation.extend(results['false_negatives'])
    
    # Evaluate with escalation enabled
    print("\n[4/4] Evaluating WITH escalation layer...")
    detector_with_escalation = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=True,
        escalation_low_threshold=0.25,
        escalation_high_threshold=0.55
    )
    
    all_results_with_escalation = {}
    all_fns_with_escalation = []
    
    for dataset_name, prompts, labels in datasets:
        print(f"\n  Testing {dataset_name} ({len(prompts)} prompts)...")
        results = evaluate_detector(detector_with_escalation, prompts, labels, "With Escalation")
        all_results_with_escalation[dataset_name] = results
        all_fns_with_escalation.extend(results['false_negatives'])
    
    # Aggregate results
    print("\n" + "="*70)
    print("AGGREGATE RESULTS")
    print("="*70)
    
    # Calculate aggregate metrics
    def aggregate_metrics(results_dict):
        total_tp = sum(r['tp'] for r in results_dict.values())
        total_tn = sum(r['tn'] for r in results_dict.values())
        total_fp = sum(r['fp'] for r in results_dict.values())
        total_fn = sum(r['fn'] for r in results_dict.values())
        
        total = total_tp + total_tn + total_fp + total_fn
        accuracy = (total_tp + total_tn) / total if total > 0 else 0
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fn_rate = total_fn / (total_fn + total_tp) if (total_fn + total_tp) > 0 else 0
        fp_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tp': total_tp,
            'tn': total_tn,
            'fp': total_fp,
            'fn': total_fn,
            'fn_rate': fn_rate,
            'fp_rate': fp_rate
        }
    
    metrics_no_escalation = aggregate_metrics(all_results_no_escalation)
    metrics_with_escalation = aggregate_metrics(all_results_with_escalation)
    
    print("\n[RESULTS] WITHOUT Escalation Layer:")
    print(f"   Recall:    {metrics_no_escalation['recall']:.2%}")
    print(f"   FN Rate:   {metrics_no_escalation['fn_rate']:.2%}")
    print(f"   FN Count:  {metrics_no_escalation['fn']:,}")
    print(f"   Precision: {metrics_no_escalation['precision']:.2%}")
    print(f"   FP Rate:   {metrics_no_escalation['fp_rate']:.2%}")
    print(f"   FP Count:  {metrics_no_escalation['fp']:,}")
    
    print("\n[RESULTS] WITH Escalation Layer:")
    print(f"   Recall:    {metrics_with_escalation['recall']:.2%}")
    print(f"   FN Rate:   {metrics_with_escalation['fn_rate']:.2%}")
    print(f"   FN Count:  {metrics_with_escalation['fn']:,}")
    print(f"   Precision: {metrics_with_escalation['precision']:.2%}")
    print(f"   FP Rate:   {metrics_with_escalation['fp_rate']:.2%}")
    print(f"   FP Count:  {metrics_with_escalation['fp']:,}")
    
    # Calculate improvement
    recall_improvement = metrics_with_escalation['recall'] - metrics_no_escalation['recall']
    fn_reduction = metrics_no_escalation['fn'] - metrics_with_escalation['fn']
    fn_rate_improvement = metrics_no_escalation['fn_rate'] - metrics_with_escalation['fn_rate']
    
    print("\n" + "="*70)
    print("IMPROVEMENT FROM ESCALATION LAYER")
    print("="*70)
    print(f"\n[+] Recall Improvement:     +{recall_improvement:.2%} ({metrics_no_escalation['recall']:.2%} -> {metrics_with_escalation['recall']:.2%})")
    print(f"[+] FN Reduction:           {fn_reduction:,} fewer false negatives ({metrics_no_escalation['fn']:,} -> {metrics_with_escalation['fn']:,})")
    print(f"[+] FN Rate Improvement:   -{fn_rate_improvement:.2%} ({metrics_no_escalation['fn_rate']:.2%} -> {metrics_with_escalation['fn_rate']:.2%})")
    
    escalation_count = sum(r['escalation_count'] for r in all_results_with_escalation.values())
    print(f"\n[INFO] Escalation Layer Activity:")
    print(f"   Prompts escalated: {escalation_count:,}")
    print(f"   Escalation rate: {escalation_count/total_prompts:.2%}")
    
    # Save results
    output = {
        'evaluation_date': str(Path(__file__).stat().st_mtime),
        'total_prompts': total_prompts,
        'total_jailbreak_attempts': total_jailbreaks,
        'without_escalation': metrics_no_escalation,
        'with_escalation': metrics_with_escalation,
        'improvement': {
            'recall_improvement': float(recall_improvement),
            'fn_reduction': int(fn_reduction),
            'fn_rate_improvement': float(fn_rate_improvement),
            'escalation_count': escalation_count
        },
        'per_dataset': {
            'without_escalation': all_results_no_escalation,
            'with_escalation': all_results_with_escalation
        },
        'false_negatives': {
            'without_escalation_count': len(all_fns_no_escalation),
            'with_escalation_count': len(all_fns_with_escalation),
            'with_escalation': all_fns_with_escalation[:100]  # Save first 100 for analysis
        }
    }
    
    results_file = Path("escalation_evaluation_results.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Results saved to {results_file}")
    
    # Summary
    print("\n" + "="*70)
    if metrics_with_escalation['recall'] >= 0.80 and metrics_with_escalation['fn_rate'] < 0.20:
        print("[PASS] ESCALATION LAYER: MEETS SECURITY REQUIREMENTS")
    else:
        print("[WARN] ESCALATION LAYER: NEEDS FURTHER OPTIMIZATION")
    print("="*70)

if __name__ == "__main__":
    main()

