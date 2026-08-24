"""
Add fine-tuning datasets to training data and retrain the security model.

Datasets:
1. fine_tuning_dataset_prepared_train.jsonl (10,357 examples: 7,440 benign, 2,917 jailbreak)
2. fine_tuning_dataset_prepared_valid.jsonl (1,000 examples: 735 benign, 265 jailbreak)
3. adversarial_dataset_with_techniques.csv (3,280 adversarial examples)
"""

import json
import csv
from pathlib import Path
from collections import Counter

def load_fine_tuning_dataset(file_path: Path, dataset_name: str):
    """Load fine-tuning dataset JSONL file."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
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
                    completion = entry.get('completion', '').strip()
                    
                    if not prompt:
                        continue
                    
                    # Remove the "###\n\n" separator if present
                    prompt = prompt.replace('###\n\n', '').strip()
                    
                    # Map completion to our labels
                    if completion.lower() == 'jailbreakable':
                        label = 'jailbreak_attempt'
                    elif completion.lower() == 'benign':
                        label = 'benign'
                    else:
                        # Default to benign if unknown
                        label = 'benign'
                    
                    data.append({
                        'prompt': prompt,
                        'label': label,
                        'source': dataset_name,
                        'original_label': completion
                    })
                    
                    count += 1
                    if count % 2000 == 0:
                        print(f"    Loaded {count:,} prompts...")
                except json.JSONDecodeError as e:
                    print(f"    [WARNING] Skipping invalid JSON line: {e}")
                    continue
        
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

def load_adversarial_dataset(file_path: Path):
    """Load adversarial dataset CSV file."""
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
                # Use persuasive_prompt (the adversarial jailbreak attempt)
                prompt = row.get('persuasive_prompt', '').strip()
                if not prompt:
                    continue
                
                # Clean up the prompt (remove "Certainly! Here's..." prefix if present)
                if prompt.startswith("Certainly!"):
                    # Extract the actual prompt from the text
                    # Format: "Certainly! Here's... \"actual prompt\""
                    import re
                    match = re.search(r'"([^"]+)"', prompt)
                    if match:
                        prompt = match.group(1)
                
                # All prompts in this dataset are adversarial/jailbreak attempts
                data.append({
                    'prompt': prompt,
                    'label': 'jailbreak_attempt',
                    'source': file_path.name,
                    'technique': row.get('technique', 'unknown'),
                    'intent': row.get('intent', 'unknown')
                })
                
                count += 1
                if count % 1000 == 0:
                    print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        
        # Show technique distribution
        if data:
            technique_counts = Counter(e.get('technique', 'unknown') for e in data)
            print(f"    Technique distribution:")
            for technique, count in technique_counts.items():
                print(f"      {technique}: {count:,}")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return data

def main():
    """Main function to add fine-tuning datasets and retrain."""
    print("="*70)
    print("ADDING FINE-TUNING DATASETS TO TRAINING")
    print("="*70)
    
    # Load existing relabeled dataset
    existing_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    existing_data = []
    
    if existing_file.exists():
        print(f"\n[1/5] Loading existing relabeled dataset...")
        with open(existing_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    existing_data.append(json.loads(line))
        print(f"  Loaded {len(existing_data):,} existing examples")
    else:
        print(f"\n[1/5] No existing relabeled dataset found, starting fresh")
    
    # Load fine-tuning datasets
    print(f"\n[2/5] Loading fine-tuning datasets...")
    
    train_data = load_fine_tuning_dataset(
        Path("fine_tuning_dataset_prepared_train.jsonl"),
        "fine_tuning_train"
    )
    
    valid_data = load_fine_tuning_dataset(
        Path("fine_tuning_dataset_prepared_valid.jsonl"),
        "fine_tuning_valid"
    )
    
    # Load adversarial dataset
    print(f"\n[3/5] Loading adversarial dataset...")
    adversarial_data = load_adversarial_dataset(Path("adversarial_dataset_with_techniques.csv"))
    
    # Combine all new data
    all_new_data = train_data + valid_data + adversarial_data
    
    print(f"\n  Total new prompts: {len(all_new_data):,}")
    print(f"    Fine-tuning train: {len(train_data):,}")
    print(f"    Fine-tuning valid: {len(valid_data):,}")
    print(f"    Adversarial: {len(adversarial_data):,}")
    
    # Combine with existing data
    print(f"\n[4/5] Combining datasets...")
    
    # Deduplicate
    seen = set()
    unique_data = []
    
    # Add existing data
    for entry in existing_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    # Add new data
    for entry in all_new_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    print(f"  Before: {len(existing_data):,} existing + {len(all_new_data):,} new = {len(existing_data) + len(all_new_data):,}")
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
        
        # Calculate improvement
        benign_count = training_label_counts.get('benign', 0)
        jailbreak_count = training_label_counts.get('jailbreak_attempt', 0)
        benign_ratio = benign_count / len(training_labels) * 100
        
        print(f"\n  Improvement:")
        print(f"    Benign ratio: {benign_ratio:.1f}% (target: 50-60%)")
        if benign_ratio > 20:
            print(f"    [GOOD] Benign ratio improved significantly!")
        else:
            print(f"    [NEEDS MORE] Still need more benign examples")
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n[5/5] Saving combined dataset...")
    print(f"  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] FINE-TUNING DATASETS ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (Fine-tuning train): {len(train_data):,}")
    print(f"  - New (Fine-tuning valid): {len(valid_data):,}")
    print(f"  - New (Adversarial): {len(adversarial_data):,}")
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
    print("  python test_on_ai_agent_evasion.py")
    print("  python test_on_prompt_injection_dataset.py")

if __name__ == "__main__":
    main()



