"""
Add labeled datasets to training data and retrain the security model.

Files to add:
1. labeled_train_final.csv (prompt improvement examples - BENIGN)
2. labeled_validation_final.csv (235 examples - BENIGN)
3. prompt_examples_dataset.csv (1,450 examples - BENIGN prompts)
4. Prompt_Examples.csv (10 examples - skip, too small)
5. Response_Examples.csv (10 examples - skip, too small)
"""

import csv
import json
import sys
from pathlib import Path
from collections import Counter

# Increase CSV field size limit
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

def load_labeled_train_final(file_path: Path):
    """Load labeled_train_final.csv - extract prompts as BENIGN."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                # Extract original_prompt and improved_instruction as benign prompts
                original = row.get('original_prompt', '').strip()
                improved = row.get('improved_instruction', '').strip()
                
                if original:
                    data.append({
                        'prompt': original,
                        'label': 'benign',
                        'source': 'labeled_train_final',
                        'field': 'original_prompt'
                    })
                    count += 1
                
                if improved:
                    data.append({
                        'prompt': improved,
                        'label': 'benign',
                        'source': 'labeled_train_final',
                        'field': 'improved_instruction'
                    })
                    count += 1
                
                if count % 1000 == 0:
                    print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        
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

def load_labeled_validation_final(file_path: Path):
    """Load labeled_validation_final.csv - extract prompts as BENIGN."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                # Extract original_prompt and improved_instruction as benign prompts
                original = row.get('original_prompt', '').strip()
                improved = row.get('improved_instruction', '').strip()
                
                if original:
                    data.append({
                        'prompt': original,
                        'label': 'benign',
                        'source': 'labeled_validation_final',
                        'field': 'original_prompt'
                    })
                    count += 1
                
                if improved:
                    data.append({
                        'prompt': improved,
                        'label': 'benign',
                        'source': 'labeled_validation_final',
                        'field': 'improved_instruction'
                    })
                    count += 1
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        
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

def load_prompt_examples_dataset(file_path: Path):
    """Load prompt_examples_dataset.csv - extract bad_prompt and good_prompt as BENIGN."""
    data = []
    
    if not file_path.exists():
        print(f"  [ERROR] {file_path.name} not found")
        return data
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                # Extract bad_prompt and good_prompt as benign prompts
                bad_prompt = row.get('bad_prompt', '').strip()
                good_prompt = row.get('good_prompt', '').strip()
                
                if bad_prompt:
                    data.append({
                        'prompt': bad_prompt,
                        'label': 'benign',
                        'source': 'prompt_examples_dataset',
                        'field': 'bad_prompt'
                    })
                    count += 1
                
                if good_prompt:
                    data.append({
                        'prompt': good_prompt,
                        'label': 'benign',
                        'source': 'prompt_examples_dataset',
                        'field': 'good_prompt'
                    })
                    count += 1
                
                if count % 500 == 0:
                    print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        
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
    """Main function to add labeled datasets and retrain."""
    print("="*70)
    print("ADDING LABELED DATASETS TO TRAINING")
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
    print(f"\n[2/6] Loading labeled dataset files...")
    
    # Try to load labeled_train_final.csv (may have large fields)
    print(f"\n  Attempting to load labeled_train_final.csv...")
    train_final_data = []
    try:
        train_final_data = load_labeled_train_final(Path("labeled_train_final.csv"))
    except Exception as e:
        print(f"    [WARNING] Could not load labeled_train_final.csv: {e}")
        print(f"    [SKIP] Skipping this file (likely has very large fields)")
    
    validation_final_data = load_labeled_validation_final(Path("labeled_validation_final.csv"))
    prompt_examples_data = load_prompt_examples_dataset(Path("prompt_examples_dataset.csv"))
    
    # Skip Prompt_Examples.csv and Response_Examples.csv (too small, only 10 rows each)
    print(f"\n  [SKIP] Prompt_Examples.csv (only 10 rows, too small)")
    print(f"  [SKIP] Response_Examples.csv (only 10 rows, too small)")
    
    # Combine all new data
    all_new_data = train_final_data + validation_final_data + prompt_examples_data
    
    print(f"\n  Total new prompts: {len(all_new_data):,}")
    print(f"    labeled_train_final.csv: {len(train_final_data):,}")
    print(f"    labeled_validation_final.csv: {len(validation_final_data):,}")
    print(f"    prompt_examples_dataset.csv: {len(prompt_examples_data):,}")
    
    # Combine with existing data
    print(f"\n[3/6] Combining datasets...")
    
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
        if benign_ratio > 25:
            print(f"    [GOOD] Benign ratio improved significantly!")
        elif benign_ratio > 20:
            print(f"    [BETTER] Benign ratio improved!")
        else:
            print(f"    [NEEDS MORE] Still need more benign examples")
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n[4/6] Saving combined dataset...")
    print(f"  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] LABELED DATASETS ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (labeled_train_final): {len(train_final_data):,}")
    print(f"  - New (labeled_validation_final): {len(validation_final_data):,}")
    print(f"  - New (prompt_examples_dataset): {len(prompt_examples_data):,}")
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


