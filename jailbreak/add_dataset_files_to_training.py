"""
Add dataset.json, results.json, and train.txt to training data and retrain the security model.

Files to add:
1. dataset.json (529 jailbreak + 529 policy violation = 1,058 examples)
2. results.json (200 jailbreak + 200 policy violation = 400 examples)
3. train.txt (320 policy violation examples)
4. test.txt (200 examples - use for testing)
"""

import json
from pathlib import Path
from collections import Counter

def load_json_dataset(file_path: Path, dataset_name: str):
    """Load JSON dataset with harmful_prompt and successful_jailbreak fields."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)
        
        count = 0
        for entry in entries:
            # Extract harmful_prompt (policy violation)
            harmful_prompt = entry.get('harmful_prompt', '').strip()
            if harmful_prompt:
                data.append({
                    'prompt': harmful_prompt,
                    'label': 'policy_violation',
                    'source': dataset_name,
                    'original_field': 'harmful_prompt'
                })
                count += 1
            
            # Extract successful_jailbreak (jailbreak attempt)
            jailbreak_prompt = entry.get('successful_jailbreak', '').strip()
            if jailbreak_prompt:
                data.append({
                    'prompt': jailbreak_prompt,
                    'label': 'jailbreak_attempt',
                    'source': dataset_name,
                    'original_field': 'successful_jailbreak'
                })
                count += 1
        
        print(f"    [OK] Loaded {len(data):,} prompts ({count:,} entries)")
        
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

def load_text_file(file_path: Path, label: str, dataset_name: str):
    """Load plain text file with one prompt per line."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            count = 0
            for line in f:
                prompt = line.strip()
                if prompt:
                    data.append({
                        'prompt': prompt,
                        'label': label,
                        'source': dataset_name
                    })
                    count += 1
                    if count % 100 == 0:
                        print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        print(f"    Label: {label} (100%)")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return data

def main():
    """Main function to add dataset files and retrain."""
    print("="*70)
    print("ADDING DATASET FILES TO TRAINING")
    print("="*70)
    
    # Load existing relabeled dataset
    existing_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    existing_data = []
    
    if existing_file.exists():
        print(f"\n[1/6] Loading existing relabeled dataset...")
        with open(existing_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    existing_data.append(json.loads(line))
        print(f"  Loaded {len(existing_data):,} existing examples")
    else:
        print(f"\n[1/6] No existing relabeled dataset found, starting fresh")
    
    # Load new datasets
    print(f"\n[2/6] Loading new dataset files...")
    
    dataset_json_data = load_json_dataset(
        Path("dataset.json"),
        "dataset_json"
    )
    
    results_json_data = load_json_dataset(
        Path("results.json"),
        "results_json"
    )
    
    train_txt_data = load_text_file(
        Path("train.txt"),
        "policy_violation",
        "train_txt"
    )
    
    # Load test.txt for testing (don't add to training)
    print(f"\n[3/6] Loading test dataset...")
    test_txt_data = load_text_file(
        Path("test.txt"),
        "policy_violation",
        "test_txt"
    )
    
    # Combine all new training data
    all_new_data = dataset_json_data + results_json_data + train_txt_data
    
    print(f"\n  Total new training prompts: {len(all_new_data):,}")
    print(f"    dataset.json: {len(dataset_json_data):,}")
    print(f"    results.json: {len(results_json_data):,}")
    print(f"    train.txt: {len(train_txt_data):,}")
    print(f"\n  Test dataset (test.txt): {len(test_txt_data):,} prompts")
    
    # Combine with existing data
    print(f"\n[4/6] Combining datasets...")
    
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
            print(f"    [GOOD] Benign ratio improved!")
        else:
            print(f"    [NEEDS MORE] Still need more benign examples")
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n[5/6] Saving combined dataset...")
    print(f"  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    # Save test dataset
    test_output_file = Path("datasets/test/test_dataset_from_files.jsonl")
    test_output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n  Saving test dataset to {test_output_file}...")
    with open(test_output_file, 'w', encoding='utf-8') as f:
        for entry in test_txt_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(test_txt_data):,} test examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] DATASET FILES ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (dataset.json): {len(dataset_json_data):,}")
    print(f"  - New (results.json): {len(results_json_data):,}")
    print(f"  - New (train.txt): {len(train_txt_data):,}")
    print(f"  - Unique: {len(unique_data):,}")
    print(f"\nTest examples: {len(test_txt_data):,}")
    
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


