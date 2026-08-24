"""
Add prompt-injection-dataset.csv to training data and retrain the security model.
"""

import json
import csv
from pathlib import Path
from collections import Counter

def load_prompt_injection_dataset(file_path: Path):
    """Load prompt-injection-dataset.csv and convert to training format."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                prompt = row.get('text', '').strip()
                if not prompt:
                    continue
                
                # Map dataset labels to our labels
                # 1 = prompt injection (jailbreak), 0 = benign
                dataset_label = row.get('label', '0').strip()
                if dataset_label == '1':
                    label = 'jailbreak_attempt'
                else:  # '0' or empty
                    label = 'benign'
                
                data.append({
                    'prompt': prompt,
                    'label': label,
                    'source': file_path.name,
                    'original_label': dataset_label
                })
                
                count += 1
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        
        # Show label distribution
        if data:
            label_counts = Counter(e['label'] for e in data)
            print(f"    Label distribution:")
            for label, label_count in label_counts.items():
                print(f"      {label}: {label_count:,} ({label_count/len(data)*100:.1f}%)")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return data

def main():
    """Main function to add prompt injection dataset and retrain."""
    print("="*70)
    print("ADDING PROMPT INJECTION DATASET TO TRAINING")
    print("="*70)
    
    # Load existing relabeled dataset
    existing_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    existing_data = []
    
    if existing_file.exists():
        print(f"\n[1/4] Loading existing relabeled dataset...")
        with open(existing_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    existing_data.append(json.loads(line))
        print(f"  Loaded {len(existing_data):,} existing examples")
    else:
        print(f"\n[1/4] No existing relabeled dataset found, starting fresh")
    
    # Load prompt injection dataset
    print(f"\n[2/4] Loading prompt injection dataset...")
    prompt_injection_data = load_prompt_injection_dataset(Path("prompt-injection-dataset.csv"))
    
    if not prompt_injection_data:
        print("[ERROR] No data loaded from prompt injection dataset!")
        return
    
    print(f"\n  Total new prompts: {len(prompt_injection_data):,}")
    
    # Combine with existing data
    print(f"\n[3/4] Combining datasets...")
    
    # Deduplicate
    seen = set()
    unique_data = []
    
    # Add existing data
    for entry in existing_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    # Add prompt injection data
    for entry in prompt_injection_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    print(f"  Before: {len(existing_data):,} existing + {len(prompt_injection_data):,} new = {len(existing_data) + len(prompt_injection_data):,}")
    print(f"  After deduplication: {len(unique_data):,} unique examples")
    
    # Label distribution
    label_counts = Counter(e['label'] for e in unique_data)
    print(f"\n  Final label distribution:")
    for label, count in label_counts.items():
        print(f"    {label}: {count:,} ({count/len(unique_data)*100:.1f}%)")
    
    # Count jailbreak_attempt vs benign (what model actually uses)
    training_labels = [e['label'] for e in unique_data if e['label'] in ['jailbreak_attempt', 'benign']]
    if training_labels:
        training_label_counts = Counter(training_labels)
        print(f"\n  Training labels (jailbreak_attempt + benign):")
        for label, count in training_label_counts.items():
            print(f"    {label}: {count:,} ({count/len(training_labels)*100:.1f}%)")
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n[4/4] Saving combined dataset...")
    print(f"  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] PROMPT INJECTION DATASET ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (Prompt Injection): {len(prompt_injection_data):,}")
    print(f"  - Unique: {len(unique_data):,}")
    
    print("\n" + "="*70)
    print("RETRAINING MODEL WITH EXPANDED DATASET")
    print("="*70)
    
    # Retrain model
    print("\nTraining security model...")
    from train_security_model import SecurityJailbreakModel
    
    model = SecurityJailbreakModel(jailbreak_threshold=0.15)
    prompts, labels = model.load_dataset(str(output_file))
    
    if len(prompts) == 0:
        print("[ERROR] No prompts loaded from dataset!")
        return
    
    print(f"\nTraining on {len(prompts):,} examples...")
    model.train(prompts, labels, balance=True, use_ensemble=True)
    
    print("\n" + "="*70)
    print("[SUCCESS] MODEL RETRAINED!")
    print("="*70)
    print("\nModel saved to: models/security/")
    print("\nNext step: Test the retrained model")
    print("  python test_on_prompt_injection_dataset.py")

if __name__ == "__main__":
    main()



