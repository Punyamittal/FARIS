"""
Add AI Agent Evasion Dataset to training data and retrain the security model.
"""

import json
from pathlib import Path
from collections import Counter

def load_ai_agent_evasion_dataset(file_path: Path):
    """Load AI Agent Evasion Dataset.jsonl and convert to training format."""
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
                    if not prompt:
                        continue
                    
                    # Map dataset labels to our labels
                    dataset_label = entry.get('label', '').lower()
                    if dataset_label == 'malicious':
                        label = 'jailbreak_attempt'
                    elif dataset_label == 'benign':
                        label = 'benign'
                    else:
                        # Default to benign if unknown
                        label = 'benign'
                    
                    data.append({
                        'prompt': prompt,
                        'label': label,
                        'source': file_path.name,
                        'original_label': dataset_label,
                        'attack_type': entry.get('attack_type', 'unknown')
                    })
                    
                    count += 1
                    if count % 200 == 0:
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
            
            # Show attack type distribution for malicious prompts
            malicious_entries = [e for e in data if e['label'] == 'jailbreak_attempt']
            if malicious_entries:
                attack_type_counts = Counter(e.get('attack_type', 'unknown') for e in malicious_entries)
                print(f"    Attack type distribution (malicious prompts):")
                for attack_type, count in attack_type_counts.most_common():
                    print(f"      {attack_type}: {count:,}")
        
    except Exception as e:
        print(f"    [ERROR] Failed to load {file_path.name}: {e}")
        import traceback
        traceback.print_exc()
    
    return data

def main():
    """Main function to add AI Agent Evasion dataset and retrain."""
    print("="*70)
    print("ADDING AI AGENT EVASION DATASET TO TRAINING")
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
    
    # Load AI Agent Evasion dataset
    print(f"\n[2/4] Loading AI Agent Evasion dataset...")
    ai_agent_data = load_ai_agent_evasion_dataset(Path("AI Agent Evasion Dataset.jsonl"))
    
    if not ai_agent_data:
        print("[ERROR] No data loaded from AI Agent Evasion dataset!")
        return
    
    print(f"\n  Total new prompts: {len(ai_agent_data):,}")
    
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
    
    # Add AI Agent Evasion data
    for entry in ai_agent_data:
        prompt_lower = entry['prompt'].lower().strip()
        if prompt_lower and prompt_lower not in seen:
            seen.add(prompt_lower)
            unique_data.append(entry)
    
    print(f"  Before: {len(existing_data):,} existing + {len(ai_agent_data):,} new = {len(existing_data) + len(ai_agent_data):,}")
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
    print("[SUCCESS] AI AGENT EVASION DATASET ADDED!")
    print("="*70)
    print(f"\nTotal training examples: {len(unique_data):,}")
    print(f"  - Existing: {len(existing_data):,}")
    print(f"  - New (AI Agent Evasion): {len(ai_agent_data):,}")
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

if __name__ == "__main__":
    main()



