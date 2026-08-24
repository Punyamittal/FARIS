# process_large_datasets.py
"""
Process large datasets and combine for training.
"""

import csv
import json
from pathlib import Path
from collections import Counter

def process_formatted_dataset(input_path, output_path):
    """Process formatted_dataset.csv"""
    print(f"Processing {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8') as f_in, \
         open(output_path, 'w', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        count = 0
        
        for row in reader:
            content = row.get('content', '').strip()
            label_val = row.get('label', '0').strip()
            
            try:
                label_num = float(label_val)
                label = 'jailbreak' if label_num > 0.5 else 'benign'
            except:
                label = 'benign'
            
            if content:
                data_point = {
                    "prompt": content,
                    "label": label,
                    "source": "formatted_dataset.csv",
                    "original_label": label_val
                }
                f_out.write(json.dumps(data_point, ensure_ascii=False) + '\n')
                count += 1
                
                if count % 10000 == 0:
                    print(f"  Processed {count:,} rows...")
    
    print(f"  Total: {count:,} examples")
    return count

def process_raw_dataset(input_path, output_path):
    """Process raw_dataset.csv"""
    print(f"Processing {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8') as f_in, \
         open(output_path, 'w', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        count = 0
        
        for row in reader:
            prompt = row.get('prompt', '').strip()
            jailbreak_val = row.get('jailbreak', '').strip().upper()
            
            if jailbreak_val in ['TRUE', '1', '1.0']:
                label = 'jailbreak'
            elif jailbreak_val in ['FALSE', '0', '0.0']:
                label = 'benign'
            else:
                continue
            
            if prompt:
                data_point = {
                    "prompt": prompt,
                    "label": label,
                    "source": "raw_dataset.csv",
                    "original_jailbreak": jailbreak_val
                }
                f_out.write(json.dumps(data_point, ensure_ascii=False) + '\n')
                count += 1
                
                if count % 10000 == 0:
                    print(f"  Processed {count:,} rows...")
    
    print(f"  Total: {count:,} examples")
    return count

def process_synthetic_dataset(input_path, output_path):
    """Process synthetic_dataset.csv"""
    print(f"Processing {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8') as f_in, \
         open(output_path, 'w', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        count = 0
        
        for row in reader:
            prompt = row.get('prompt', '').strip()
            jailbreak_val = row.get('jailbreak', '').strip().upper()
            
            if jailbreak_val in ['TRUE', '1', '1.0']:
                label = 'jailbreak'
            elif jailbreak_val in ['FALSE', '0', '0.0']:
                label = 'benign'
            else:
                continue
            
            if prompt:
                data_point = {
                    "prompt": prompt,
                    "label": label,
                    "source": "synthetic_dataset.csv",
                    "original_jailbreak": jailbreak_val
                }
                f_out.write(json.dumps(data_point, ensure_ascii=False) + '\n')
                count += 1
                
                if count % 10000 == 0:
                    print(f"  Processed {count:,} rows...")
    
    print(f"  Total: {count:,} examples")
    return count

def combine_datasets(output_dir="datasets"):
    """Combine all processed datasets."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    all_files = [
        "datasets/formatted_processed.jsonl",
        "datasets/raw_processed.jsonl",
        "datasets/synthetic_processed.jsonl",
        "datasets/malignant_labeled.jsonl"
    ]
    
    combined_path = output_dir / "combined_training_dataset.jsonl"
    labels = Counter()
    total = 0
    
    print(f"\nCombining datasets into {combined_path}...")
    with open(combined_path, 'w', encoding='utf-8') as f_out:
        for file_path in all_files:
            if Path(file_path).exists():
                print(f"  Adding {file_path}...")
                with open(file_path, 'r', encoding='utf-8') as f_in:
                    for line in f_in:
                        item = json.loads(line)
                        f_out.write(line)
                        labels[item['label']] += 1
                        total += 1
    
    print(f"\nCombined dataset:")
    print(f"  Total examples: {total:,}")
    for label, count in labels.items():
        print(f"    {label}: {count:,} ({count/total*100:.1f}%)")
    
    return combined_path

def main():
    """Process all large datasets."""
    print("="*70)
    print("PROCESSING LARGE DATASETS FOR ML TRAINING")
    print("="*70)
    
    datasets_dir = Path("datasets")
    datasets_dir.mkdir(exist_ok=True)
    
    counts = {}
    
    if Path("formatted_dataset.csv").exists():
        counts['formatted'] = process_formatted_dataset(
            "formatted_dataset.csv",
            "datasets/formatted_processed.jsonl"
        )
    
    if Path("raw_dataset.csv").exists():
        counts['raw'] = process_raw_dataset(
            "raw_dataset.csv",
            "datasets/raw_processed.jsonl"
        )
    
    if Path("synthetic_dataset.csv").exists():
        counts['synthetic'] = process_synthetic_dataset(
            "synthetic_dataset.csv",
            "datasets/synthetic_processed.jsonl"
        )
    
    if counts:
        combined_path = combine_datasets()
        print(f"\n[SUCCESS] Combined dataset ready: {combined_path}")
        print(f"\nNext step: Train model on combined dataset!")
        print(f"  python train_ml_model.py --dataset {combined_path}")

if __name__ == "__main__":
    main()