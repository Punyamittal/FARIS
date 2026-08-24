"""
Relabel dataset to separate policy violations from jailbreak attempts.

New schema:
- benign: Normal, safe content
- policy_violation: Illegal/harmful content (drugs, explosives, etc.)
- jailbreak_attempt: Instruction override, role-play, system manipulation
"""

import json
from pathlib import Path
from collections import Counter
from security_detector import RuleBasedJailbreakDetector

def classify_prompt(prompt: str, original_label: str, rule_detector: RuleBasedJailbreakDetector) -> str:
    """
    Classify prompt into correct category.
    
    Args:
        prompt: The prompt text
        original_label: Original label from dataset
        rule_detector: Rule-based detector for patterns
    
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
    
    # Check original label for hints
    if original_label == 'jailbreak':
        # If original says jailbreak but no patterns match, might be policy violation
        # Check if it's actually policy violation content
        if is_policy_violation:
            return 'policy_violation'
        # Otherwise, might be subtle jailbreak - keep as jailbreak_attempt
        return 'jailbreak_attempt'
    
    # Default to benign
    return 'benign'

def relabel_jsonl(input_file: Path, output_file: Path):
    """Relabel JSONL file."""
    print(f"\nProcessing {input_file.name}...")
    
    rule_detector = RuleBasedJailbreakDetector()
    relabeled_data = []
    label_changes = Counter()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            entry = json.loads(line)
            prompt = entry.get('prompt', '').strip()
            if not prompt:
                continue
            
            original_label = entry.get('label', 'benign')
            new_label = classify_prompt(prompt, original_label, rule_detector)
            
            # Track changes
            if original_label != new_label:
                label_changes[(original_label, new_label)] += 1
            
            relabeled_entry = {
                'prompt': prompt,
                'label': new_label,
                'original_label': original_label,
                'source': entry.get('source', input_file.name)
            }
            relabeled_data.append(relabeled_entry)
    
    # Save
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in relabeled_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    # Statistics
    label_counts = Counter(e['label'] for e in relabeled_data)
    print(f"  Total: {len(relabeled_data):,} examples")
    print(f"  Label distribution:")
    for label, count in label_counts.items():
        print(f"    {label}: {count:,} ({count/len(relabeled_data)*100:.1f}%)")
    
    if label_changes:
        print(f"  Label changes:")
        for (old, new), count in label_changes.most_common(10):
            print(f"    {old} → {new}: {count:,}")
    
    return relabeled_data

def relabel_json(input_file: Path, output_file: Path):
    """Relabel JSON file (like jailbreak_test_dataset.json)."""
    print(f"\nProcessing {input_file.name}...")
    
    rule_detector = RuleBasedJailbreakDetector()
    relabeled_data = []
    label_changes = Counter()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    for item in data:
        prompt = item.get('prompt', '').strip()
        if not prompt:
            continue
        
        # Original label from 'jailbroken' field
        is_jailbroken = item.get('jailbroken', False)
        original_label = 'jailbreak' if is_jailbroken else 'benign'
        
        new_label = classify_prompt(prompt, original_label, rule_detector)
        
        if original_label != new_label:
            label_changes[(original_label, new_label)] += 1
        
        relabeled_entry = {
            'prompt': prompt,
            'label': new_label,
            'original_label': original_label,
            'jailbroken': is_jailbroken,
            'category': item.get('category', ''),
            'method': item.get('method', ''),
            'source': input_file.name
        }
        relabeled_data.append(relabeled_entry)
    
    # Save as JSONL
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in relabeled_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    # Statistics
    label_counts = Counter(e['label'] for e in relabeled_data)
    print(f"  Total: {len(relabeled_data):,} examples")
    print(f"  Label distribution:")
    for label, count in label_counts.items():
        print(f"    {label}: {count:,} ({count/len(relabeled_data)*100:.1f}%)")
    
    if label_changes:
        print(f"  Label changes:")
        for (old, new), count in label_changes.most_common(10):
            print(f"    {old} → {new}: {count:,}")
    
    return relabeled_data

def main():
    """Relabel all datasets."""
    print("="*70)
    print("RELABELING DATASETS - Separating Policy Violations from Jailbreaks")
    print("="*70)
    
    output_dir = Path("datasets/relabeled")
    output_dir.mkdir(exist_ok=True)
    
    # Process JSONL files
    jsonl_files = [
        Path("datasets/all_datasets_combined.jsonl"),
        Path("datasets/combined_with_custom.jsonl"),
        Path("datasets/combined_training_dataset.jsonl"),
    ]
    
    all_relabeled = []
    
    for input_file in jsonl_files:
        if input_file.exists():
            output_file = output_dir / f"relabeled_{input_file.name}"
            relabeled = relabel_jsonl(input_file, output_file)
            all_relabeled.extend(relabeled)
    
    # Process JSON files
    json_files = [
        Path("jailbreak_test_dataset.json"),
    ]
    
    for input_file in json_files:
        if input_file.exists():
            output_file = output_dir / f"relabeled_{input_file.stem}.jsonl"
            relabeled = relabel_json(input_file, output_file)
            all_relabeled.extend(relabeled)
    
    # Combine all relabeled data
    print("\n" + "="*70)
    print("COMBINING RELABELED DATASETS")
    print("="*70)
    
    # Deduplicate
    seen = set()
    unique_data = []
    for entry in all_relabeled:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    print(f"\nTotal unique examples: {len(unique_data):,}")
    
    # Final label distribution
    label_counts = Counter(e['label'] for e in unique_data)
    print(f"\nFinal label distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count:,} ({count/len(unique_data)*100:.1f}%)")
    
    # Save combined
    combined_file = output_dir / "all_relabeled_combined.jsonl"
    with open(combined_file, 'w', encoding='utf-8') as f:
        for entry in unique_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"\n[OK] Combined relabeled dataset saved to: {combined_file}")
    
    print("\n" + "="*70)
    print("[SUCCESS] RELABELING COMPLETE!")
    print("="*70)
    print("\nNext step: Train model on relabeled dataset:")
    print(f"  python train_security_model.py")

if __name__ == "__main__":
    main()




