"""
Analyze the new dataset files to understand their structure and usefulness.
"""

import csv
import json
from pathlib import Path
from collections import Counter

def analyze_csv_file(file_path: Path, max_rows=5):
    """Analyze a CSV file structure."""
    if not file_path.exists():
        return None
    
    print(f"\n{'='*70}")
    print(f"Analyzing: {file_path.name}")
    print('='*70)
    
    try:
        # Count rows
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames
            rows = []
            count = 0
            for row in reader:
                rows.append(row)
                count += 1
                if count >= max_rows:
                    break
        
        print(f"\nColumns ({len(columns)}): {list(columns)[:10]}...")
        # Count total rows
        total_rows = 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            total_rows = sum(1 for _ in reader)
        print(f"Total rows: {total_rows:,}")
        
        # Show sample rows
        print(f"\nSample rows (first {min(max_rows, len(rows))}):")
        for i, row in enumerate(rows[:max_rows], 1):
            print(f"\n  Row {i}:")
            for col in columns[:5]:  # Show first 5 columns
                val = str(row.get(col, ''))[:100]
                print(f"    {col}: {val}...")
        
        return {
            'columns': columns,
            'row_count': sum(1 for _ in csv.DictReader(open(file_path, 'r', encoding='utf-8', errors='ignore'))),
            'sample_rows': rows[:max_rows]
        }
    except Exception as e:
        print(f"  [ERROR] {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main analysis function."""
    files = [
        Path("labeled_train_final.csv"),
        Path("labeled_validation_final.csv"),
        Path("Prompt_Examples.csv"),
        Path("prompt_examples_dataset.csv"),
        Path("Response_Examples.csv")
    ]
    
    results = {}
    for file_path in files:
        results[file_path.name] = analyze_csv_file(file_path, max_rows=3)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for name, result in results.items():
        if result:
            print(f"\n{name}:")
            print(f"  Rows: {result['row_count']:,}")
            print(f"  Columns: {len(result['columns'])}")
            print(f"  Key columns: {list(result['columns'])[:5]}")

if __name__ == "__main__":
    main()

