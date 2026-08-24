"""
Final Benchmark Suite

Runs comprehensive benchmarks on three key datasets:
1. Prompt Injection (mixed benign/jailbreak)
2. AI Agent Evasion
3. Mutated Jailbreak Set

Saves results for patent documentation.
"""

import json
import pickle
import csv
from pathlib import Path
from collections import Counter
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

def load_prompt_injection_dataset():
    """Load Prompt_INJECTION_And_Benign_DATASET.jsonl"""
    dataset_path = Path("Prompt_INJECTION_And_Benign_DATASET.jsonl")
    prompts = []
    labels = []
    
    if not dataset_path.exists():
        return prompts, labels
    
    print(f"  Loading {dataset_path.name}...")
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
                if dataset_label == 'malicious':
                    labels.append('jailbreak_attempt')
                else:
                    labels.append('benign')
            except json.JSONDecodeError:
                continue
    
    return prompts, labels

def load_ai_agent_evasion_dataset():
    """Load AI Agent Evasion Dataset.jsonl"""
    dataset_path = Path("AI Agent Evasion Dataset.jsonl")
    prompts = []
    labels = []
    
    if not dataset_path.exists():
        return prompts, labels
    
    print(f"  Loading {dataset_path.name}...")
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
                if dataset_label == 'malicious':
                    labels.append('jailbreak_attempt')
                else:
                    labels.append('benign')
            except json.JSONDecodeError:
                continue
    
    return prompts, labels

def load_mutated_dataset():
    """Load mutated_all.csv"""
    dataset_path = Path("mutated_all.csv")
    prompts = []
    labels = []
    
    if not dataset_path.exists():
        return prompts, labels
    
    print(f"  Loading {dataset_path.name}...")
    with open(dataset_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            prompt = row.get('MutatedPrompt', '').strip() or row.get('Prompt', '').strip()
            if not prompt:
                continue
            prompts.append(prompt)
            # Assume all are jailbreak attempts for mutated set
            labels.append('jailbreak_attempt')
    
    return prompts, labels

def evaluate_detector(detector, prompts, labels, dataset_name: str):
    """Evaluate detector and return metrics."""
    print(f"\n  Evaluating on {dataset_name}...")
    
    predictions = []
    confidences = []
    detection_methods = []
    whitelist_count = 0
    rule_count = 0
    ml_count = 0
    
    total = len(prompts)
    for i, prompt in enumerate(prompts):
        if (i + 1) % max(1, total // 10) == 0:
            print(f"    Progress: {i + 1}/{total} ({100*(i+1)/total:.0f}%)")
        
        result = detector.predict(prompt)
        predictions.append('jailbreak_attempt' if result.is_jailbreak else 'benign')
        confidences.append(result.confidence)
        detection_methods.append(result.detection_method)
        
        if result.detection_method == 'whitelist':
            whitelist_count += 1
        elif result.detection_method == 'rule':
            rule_count += 1
        elif result.detection_method in ['ml', 'hybrid', 'escalated']:
            ml_count += 1
    
    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    recall = recall_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    f1 = f1_score(labels, predictions, pos_label='jailbreak_attempt', zero_division=0)
    cm = confusion_matrix(labels, predictions, labels=['benign', 'jailbreak_attempt'])
    
    tn, fp, fn, tp = cm.ravel()
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    # Label distribution
    label_counts = Counter(labels)
    
    results = {
        'dataset': dataset_name,
        'total_prompts': len(prompts),
        'label_distribution': dict(label_counts),
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'false_negative_rate': float(fn_rate),
        'false_positive_rate': float(fp_rate),
        'confusion_matrix': cm.tolist(),
        'detection_breakdown': {
            'whitelist': whitelist_count,
            'rule_based': rule_count,
            'ml_based': ml_count
        },
        'meets_security_requirements': recall >= 0.80 and fn_rate < 0.20
    }
    
    return results

def print_results(results):
    """Print formatted results."""
    print(f"\n{'='*70}")
    print(f"RESULTS: {results['dataset']}")
    print(f"{'='*70}")
    print(f"\nDataset Info:")
    print(f"  Total Prompts: {results['total_prompts']:,}")
    print(f"  Label Distribution:")
    for label, count in results['label_distribution'].items():
        print(f"    {label}: {count:,} ({100*count/results['total_prompts']:.1f}%)")
    
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {results['accuracy']:.2%}")
    print(f"  Precision: {results['precision']:.2%}")
    print(f"  Recall:    {results['recall']:.2%} (target: >=80%)")
    print(f"  F1-Score:  {results['f1_score']:.2%}")
    
    print(f"\nSecurity Metrics:")
    print(f"  False Negatives: {results['false_negatives']} (rate: {results['false_negative_rate']:.2%}, target: <20%)")
    print(f"  False Positives: {results['false_positives']} (rate: {results['false_positive_rate']:.2%})")
    
    print(f"\nDetection Breakdown:")
    breakdown = results['detection_breakdown']
    print(f"  Whitelist: {breakdown['whitelist']} ({100*breakdown['whitelist']/results['total_prompts']:.1f}%)")
    print(f"  Rule-Based: {breakdown['rule_based']} ({100*breakdown['rule_based']/results['total_prompts']:.1f}%)")
    print(f"  ML-Based: {breakdown['ml_based']} ({100*breakdown['ml_based']/results['total_prompts']:.1f}%)")
    
    if results['meets_security_requirements']:
        print(f"\n  [PASS] MEETS SECURITY REQUIREMENTS")
    else:
        print(f"\n  [FAIL] NEEDS IMPROVEMENT")
        if results['recall'] < 0.80:
            print(f"    - Recall ({results['recall']:.2%}) below target (80%)")
        if results['false_negative_rate'] >= 0.20:
            print(f"    - FN Rate ({results['false_negative_rate']:.2%}) above target (20%)")

def main():
    """Run final benchmarks."""
    print("="*70)
    print("FINAL BENCHMARK SUITE")
    print("="*70)
    
    # Load model
    print("\n[1/4] Loading ML model...")
    ml_model = load_model()
    if not ml_model:
        print("[ERROR] Cannot proceed without ML model")
        return
    
    print("[OK] ML model loaded")
    
    # Initialize detector
    print("\n[2/4] Initializing detector...")
    detector = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=True,
        enable_whitelist=True
    )
    print("[OK] Detector initialized")
    
    # Load datasets
    print("\n[3/4] Loading test datasets...")
    datasets = [
        ("Prompt Injection Dataset", load_prompt_injection_dataset),
        ("AI Agent Evasion Dataset", load_ai_agent_evasion_dataset),
        ("Mutated Jailbreak Set", load_mutated_dataset)
    ]
    
    all_results = []
    
    for dataset_name, load_func in datasets:
        prompts, labels = load_func()
        if len(prompts) == 0:
            print(f"  [SKIP] {dataset_name}: No data loaded")
            continue
        
        print(f"  [OK] {dataset_name}: {len(prompts):,} prompts")
    
    # Run evaluations
    print("\n[4/4] Running evaluations...")
    
    for dataset_name, load_func in datasets:
        prompts, labels = load_func()
        if len(prompts) == 0:
            continue
        
        results = evaluate_detector(detector, prompts, labels, dataset_name)
        print_results(results)
        all_results.append(results)
    
    # Save results
    print("\n" + "="*70)
    print("SAVING RESULTS")
    print("="*70)
    
    results_file = Path("FINAL_BENCHMARK_RESULTS.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            'benchmark_date': str(Path(__file__).stat().st_mtime),
            'model_version': 'v1.1_with_escalation_fix',
            'datasets': all_results,
            'summary': {
                'total_datasets': len(all_results),
                'all_pass': all(r['meets_security_requirements'] for r in all_results),
                'average_recall': sum(r['recall'] for r in all_results) / len(all_results) if all_results else 0,
                'average_fn_rate': sum(r['false_negative_rate'] for r in all_results) / len(all_results) if all_results else 0
            }
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Results saved to {results_file}")
    
    # Print summary
    print("\n" + "="*70)
    print("BENCHMARK SUMMARY")
    print("="*70)
    
    if all_results:
        avg_recall = sum(r['recall'] for r in all_results) / len(all_results)
        avg_fn_rate = sum(r['false_negative_rate'] for r in all_results) / len(all_results)
        all_pass = all(r['meets_security_requirements'] for r in all_results)
        
        print(f"\n  Datasets Tested: {len(all_results)}")
        print(f"  Average Recall: {avg_recall:.2%}")
        print(f"  Average FN Rate: {avg_fn_rate:.2%}")
        print(f"  All Pass: {'YES' if all_pass else 'NO'}")
        
        print(f"\n  Per-Dataset Results:")
        for r in all_results:
            status = "PASS" if r['meets_security_requirements'] else "FAIL"
            print(f"    {r['dataset']}: Recall={r['recall']:.2%}, FN Rate={r['false_negative_rate']:.2%} [{status}]")

if __name__ == "__main__":
    main()


