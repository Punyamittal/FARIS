"""
Analyze 70k_gemma_template_built.csv to determine if it's useful for training.
"""

import csv
from pathlib import Path
from collections import Counter

def analyze_gemma_dataset(file_path: Path, max_samples=100):
    """Analyze the gemma dataset."""
    print(f"\n{'='*70}")
    print(f"Analyzing: {file_path.name}")
    print('='*70)
    
    if not file_path.exists():
        print(f"  [ERROR] File not found")
        return None
    
    try:
        print(f"\n  Loading sample rows...")
        prompts = []
        unique_prompts = set()
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                prompt = row.get('prompt', '').strip()
                if prompt:
                    prompts.append(prompt)
                    unique_prompts.add(prompt.lower().strip())
                    count += 1
                    if count >= max_samples:
                        break
        
        print(f"\n  Sample Analysis (first {len(prompts)} rows):")
        print(f"    Total prompts: {len(prompts):,}")
        print(f"    Unique prompts: {len(unique_prompts):,}")
        print(f"    Average length: {sum(len(p) for p in prompts)/len(prompts):.1f} chars")
        
        print(f"\n  Sample prompts:")
        for i, prompt in enumerate(prompts[:10], 1):
            print(f"    {i}. {prompt[:120]}...")
        
        # Check for jailbreak indicators
        jailbreak_keywords = ['ignore', 'jailbreak', 'bypass', 'hack', 'exploit', 'harmful', 'illegal', 'violate']
        jailbreak_count = sum(1 for p in prompts if any(kw in p.lower() for kw in jailbreak_keywords))
        print(f"\n  Jailbreak indicators:")
        print(f"    Prompts with jailbreak keywords: {jailbreak_count}/{len(prompts)} ({jailbreak_count/len(prompts)*100:.1f}%)")
        
        # Check content type
        creative_keywords = ['reimagine', 'rewrite', 'transform', 'imagine', 'create', 'write', 'describe']
        creative_count = sum(1 for p in prompts if any(kw in p.lower() for kw in creative_keywords))
        print(f"    Prompts with creative keywords: {creative_count}/{len(prompts)} ({creative_count/len(prompts)*100:.1f}%)")
        
        return {
            'total_prompts': len(prompts),
            'unique_prompts': len(unique_prompts),
            'sample_prompts': prompts[:10],
            'jailbreak_indicators': jailbreak_count,
            'creative_indicators': creative_count
        }
        
    except Exception as e:
        print(f"  [ERROR] {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main analysis function."""
    result = analyze_gemma_dataset(Path("70k_gemma_template_built.csv"), max_samples=1000)
    
    print("\n" + "="*70)
    print("RECOMMENDATION")
    print("="*70)
    
    if result:
        print(f"\nDataset contains: {result['total_prompts']:,} prompts (sample)")
        print(f"Unique prompts: {result['unique_prompts']:,} (sample)")
        print(f"Jailbreak indicators: {result['jailbreak_indicators']}/{result['total_prompts']} ({result['jailbreak_indicators']/result['total_prompts']*100:.1f}%)")
        print(f"Creative indicators: {result['creative_indicators']}/{result['total_prompts']} ({result['creative_indicators']/result['total_prompts']*100:.1f}%)")
        
        if result['jailbreak_indicators'] / result['total_prompts'] < 0.1:
            print("\n✅ [RECOMMENDATION] This dataset appears to be BENIGN")
            print("   - Low jailbreak indicators")
            print("   - High creative/educational prompts")
            print("   - Should be labeled as 'benign' for training")
        else:
            print("\n⚠️ [RECOMMENDATION] This dataset may contain jailbreak attempts")
            print("   - Needs careful review before adding")

if __name__ == "__main__":
    main()
