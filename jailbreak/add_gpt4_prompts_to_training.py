"""
Add gpt4_prompts.csv to training data and retrain the security model.

File to add:
- gpt4_prompts.csv (600 benign prompts)
"""

import csv
import json
from pathlib import Path
from collections import Counter

def load_gpt4_prompts(file_path: Path):
    """Load gpt4_prompts.csv - all prompts are BENIGN."""
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
                prompt = row.get('prompt', '').strip()
                if prompt:
                    data.append({
                        'prompt': prompt,
                        'label': 'benign',
                        'source': 'gpt4_prompts'
                    })
                    count += 1
                    if count % 100 == 0:
                        print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(data):,} prompts")
        print(f"    Label: benign (100%)")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return data

def main():
    """Main function to add gpt4_prompts and retrain."""
    print("="*70)
    print("ADDING GPT4_PROMPTS.CSV TO TRAINING")
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
    
    # Load new dataset
    print(f"\n[2/5] Loading gpt4_prompts.csv...")
    
    gpt4_prompts_data = load_gpt4_prompts(Path("gpt4_prompts.csv"))
    
    # Combine with existing data
    print(f"\n[3/5] Combining datasets...")
    
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
    for entry in gpt4_prompts_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    print(f"  Before: {len(existing_data):,} existing + {len(gpt4_prompts_data):,} new = {len(existing_data) + len(gpt4_prompts_data):,}")
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
            print(f"    [GOOD] Benign ratio improved!")
        elif benign_ratio > 20:
            print(f"    [BETTER] Benign ratio improved!")
        else:
            print(f"    [NEEDS MORE] Still need more benign examples")
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n[4/5] Saving combined dataset...")
    print(f"  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] GPT4_PROMPTS.CSV ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (gpt4_prompts.csv): {len(gpt4_prompts_data):,}")
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


