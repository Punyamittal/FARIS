"""
Add new datasets to training data and retrain the security model.

Datasets to add:
1. predictionguard_df.csv
2. forbidden_question_set_df.csv
3. forbidden_question_set_with_prompts.csv
4. jailbreak_prompts.csv
5. malicous_deepset.csv
"""

import json
import csv
from pathlib import Path
from collections import Counter
from security_detector import RuleBasedJailbreakDetector

def load_csv_dataset(file_path: Path, prompt_column: str = "Prompt"):
    """Load CSV dataset and extract prompts."""
    prompts = []
    
    if not file_path.exists():
        print(f"  [SKIP] {file_path.name} not found")
        return prompts
    
    try:
        print(f"  Loading {file_path.name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                prompt = row.get(prompt_column, '').strip()
                if prompt:
                    prompts.append(prompt)
                    count += 1
                    if count % 10000 == 0:
                        print(f"    Loaded {count:,} prompts...")
        
        print(f"    [OK] Loaded {len(prompts):,} prompts")
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
    
    return prompts

def classify_prompt(prompt: str, rule_detector: RuleBasedJailbreakDetector, default_label: str = "jailbreak_attempt") -> str:
    """
    Classify prompt into correct category.
    
    Args:
        prompt: The prompt text
        rule_detector: Rule-based detector for patterns
        default_label: Default label if dataset is known to be malicious
    
    Returns:
        'benign', 'policy_violation', or 'jailbreak_attempt'
    """
    prompt_lower = prompt.lower().strip()
    
    # Check for jailbreak patterns first (instruction override)
    is_jailbreak, _, _ = rule_detector.detect(prompt)
    if is_jailbreak:
        return 'jailbreak_attempt'
    
    # Check for policy violations (illegal content)
    is_policy_violation = rule_detector.check_policy_violation(prompt)
    if is_policy_violation:
        return 'policy_violation'
    
    # If dataset is known to be malicious/jailbreak, default to jailbreak_attempt
    # Otherwise, check if it's actually benign
    if default_label == "jailbreak_attempt":
        # Might be subtle jailbreak - keep as jailbreak_attempt
        return 'jailbreak_attempt'
    
    # Default to benign
    return 'benign'

def main():
    """Main function to add new datasets and retrain."""
    print("="*70)
    print("ADDING NEW DATASETS TO TRAINING")
    print("="*70)
    
    rule_detector = RuleBasedJailbreakDetector()
    all_new_data = []
    
    # Load existing relabeled dataset
    existing_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    existing_data = []
    
    if existing_file.exists():
        print(f"\n[1/3] Loading existing relabeled dataset...")
        with open(existing_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    existing_data.append(json.loads(line))
        print(f"  Loaded {len(existing_data):,} existing examples")
    else:
        print(f"\n[1/3] No existing relabeled dataset found, starting fresh")
    
    # Load new datasets
    print(f"\n[2/3] Loading new datasets...")
    
    datasets = [
        ("predictionguard_df.csv", "Prompt", "jailbreak_attempt"),  # Known jailbreak dataset
        ("forbidden_question_set_df.csv", "Prompt", "jailbreak_attempt"),  # Known jailbreak dataset
        ("forbidden_question_set_with_prompts.csv", "Prompt", "jailbreak_attempt"),  # Known jailbreak dataset
        ("jailbreak_prompts.csv", "Prompt", "jailbreak_attempt"),  # Known jailbreak dataset
        ("malicous_deepset.csv", "Prompt", "jailbreak_attempt"),  # Known malicious dataset
    ]
    
    total_new = 0
    for file_name, prompt_col, default_label in datasets:
        file_path = Path(file_name)
        prompts = load_csv_dataset(file_path, prompt_col)
        
        if prompts:
            print(f"  Classifying {len(prompts):,} prompts from {file_name}...")
            classified = 0
            for prompt in prompts:
                label = classify_prompt(prompt, rule_detector, default_label)
                all_new_data.append({
                    'prompt': prompt,
                    'label': label,
                    'source': file_name,
                    'original_label': default_label
                })
                classified += 1
                if classified % 10000 == 0:
                    print(f"    Classified {classified:,}/{len(prompts):,}...")
            
            total_new += len(prompts)
            print(f"    [OK] Added {len(prompts):,} prompts from {file_name}")
    
    print(f"\n  Total new prompts: {total_new:,}")
    
    # Combine with existing data
    print(f"\n[3/3] Combining datasets...")
    
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
    
    # Save combined dataset
    output_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    output_file.parent.mkdir(exist_ok=True)
    
    print(f"\n  Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"  [OK] Saved {len(unique_data):,} examples")
    
    print("\n" + "="*70)
    print("[SUCCESS] DATASETS ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New: {total_new:,}")
    print(f"  - Unique: {len(unique_data):,}")
    
    print("\nNext step: Retrain the model")
    print("  python train_security_model.py")

if __name__ == "__main__":
    main()




