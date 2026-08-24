"""
Test Balanced Model on Jailbreak Dataset
Saves results to file for visibility.
"""

import json
import pickle
import sys
from pathlib import Path
from collections import Counter
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def main():
    print("="*70)
    print("TESTING BALANCED MODEL ON JAILBREAK DATASET")
    print("="*70)
    
    # Load dataset
    dataset_file = Path("jailbreak_test_dataset.json")
    if not dataset_file.exists():
        print(f"\n[ERROR] Dataset not found: {dataset_file}")
        return
    
    print(f"\n[1/3] Loading dataset...")
    with open(dataset_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    prompts = []
    labels = []
    for item in data:
        prompt = item.get('prompt', '').strip()
        if prompt:
            is_jailbreak = item.get('jailbroken', False)
            labels.append('jailbreak' if is_jailbreak else 'benign')
            prompts.append(prompt)
    
    print(f"  Loaded {len(prompts)} examples")
    label_counts = Counter(labels)
    for label, count in label_counts.items():
        print(f"    {label}: {count} ({count/len(labels)*100:.1f}%)")
    
    # Load model
    print(f"\n[2/3] Loading balanced model...")
    try:
        from train_balanced_model import BalancedAntiJailbreakModel
        model = BalancedAntiJailbreakModel()
        
        # Load ensemble if available, else regular model
        if Path("models/balanced_ensemble.pkl").exists():
            with open("models/balanced_ensemble.pkl", 'rb') as f:
                model.ensemble_model = pickle.load(f)
                model.model = model.ensemble_model
            print("  [OK] Ensemble model loaded")
        elif Path("models/balanced_model.pkl").exists():
            with open("models/balanced_model.pkl", 'rb') as f:
                model.model = pickle.load(f)
            print("  [OK] Regular model loaded")
        else:
            print("  [ERROR] No model file found!")
            return
        
        with open("models/balanced_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open("models/balanced_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        model.is_trained = True
        print("  [OK] Model ready")
        
    except Exception as e:
        print(f"  [ERROR] Failed to load: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test
    print(f"\n[3/3] Testing {len(prompts)} prompts...")
    predictions = []
    confidences = []
    
    for i, prompt in enumerate(prompts):
        if (i + 1) % 25 == 0:
            print(f"  Processed {i + 1}/{len(prompts)}...")
        
        try:
            result = model.predict(prompt)
            predictions.append(result['label'])
            confidences.append(result['confidence'])
        except Exception as e:
            print(f"  [ERROR] Prompt {i+1}: {e}")
            predictions.append('benign')
            confidences.append(0.0)
    
    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, pos_label='jailbreak', zero_division=0)
    recall = recall_score(labels, predictions, pos_label='jailbreak', zero_division=0)
    f1 = f1_score(labels, predictions, pos_label='jailbreak', zero_division=0)
    cm = confusion_matrix(labels, predictions, labels=['benign', 'jailbreak'])
    tn, fp, fn, tp = cm.ravel()
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    # Print results
    print("\n" + "="*70)
    print("TEST RESULTS")
    print("="*70)
    
    print(f"\n📊 Overall Metrics:")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1-Score:  {f1:.2%}")
    
    print(f"\n🎯 Security-Critical Metrics:")
    print(f"  Jailbreak Recall: {recall:.2%} (target: >80%)")
    print(f"  False Negatives:  {fn} (missed jailbreaks)")
    print(f"  False Negative Rate: {fnr:.2%} (target: <20%)")
    print(f"  False Positives:  {fp} (benign flagged)")
    print(f"  False Positive Rate: {fpr:.2%}")
    
    print(f"\n📈 Confusion Matrix:")
    print(f"                Predicted")
    print(f"              Benign  Jailbreak")
    print(f"  Actual Benign   {tn:4d}    {fp:4d}")
    print(f"  Actual Jailbreak {fn:4d}    {tp:4d}")
    
    # Per-class
    total_benign = tn + fp
    total_jailbreak = fn + tp
    benign_acc = tn / total_benign if total_benign > 0 else 0.0
    jailbreak_acc = tp / total_jailbreak if total_jailbreak > 0 else 0.0
    
    print(f"\n📋 Per-Class Accuracy:")
    print(f"  Benign:     {benign_acc:.2%} ({tn}/{total_benign})")
    print(f"  Jailbreak:  {jailbreak_acc:.2%} ({tp}/{total_jailbreak})")
    
    # Examples
    fn_indices = [i for i, (p, l) in enumerate(zip(predictions, labels)) 
                  if p == 'benign' and l == 'jailbreak']
    if fn_indices:
        print(f"\n❌ False Negatives (Missed {len(fn_indices)} jailbreaks):")
        for idx in fn_indices[:5]:
            print(f"  [{idx+1}] {prompts[idx][:80]}...")
            print(f"      Confidence: {confidences[idx]:.2%}")
    
    fp_indices = [i for i, (p, l) in enumerate(zip(predictions, labels)) 
                  if p == 'jailbreak' and l == 'benign']
    if fp_indices:
        print(f"\n⚠️  False Positives (Benign Flagged - {len(fp_indices)}):")
        for idx in fp_indices[:5]:
            print(f"  [{idx+1}] {prompts[idx][:80]}...")
            print(f"      Confidence: {confidences[idx]:.2%}")
    
    print("\n" + "="*70)
    if recall >= 0.80 and fnr < 0.20:
        print("✅ MODEL MEETS SECURITY REQUIREMENTS")
    else:
        print("⚠️  MODEL NEEDS IMPROVEMENT")
        if recall < 0.80:
            print(f"   - Jailbreak recall ({recall:.2%}) below target (80%)")
        if fnr >= 0.20:
            print(f"   - False negative rate ({fnr:.2%}) above target (20%)")
    print("="*70)
    
    # Save results
    results = {
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
    
    with open("test_results_jailbreak.json", 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[OK] Results saved to test_results_jailbreak.json")

if __name__ == "__main__":
    main()




