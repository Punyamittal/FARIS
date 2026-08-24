"""
Step 2: False Negative Analysis

Analyzes false negatives (missed jailbreaks) to identify blind spots.
Clusters FNs by attack type to guide targeted rule patching.

This script:
1. Loads test datasets
2. Runs predictions
3. Identifies false negatives
4. Clusters by attack type
5. Outputs false_negative_analysis.md
"""

import json
import pickle
import re
from pathlib import Path
from collections import defaultdict, Counter
from typing import List, Dict, Tuple
from security_detector import SecurityJailbreakDetector
from train_security_model import SecurityJailbreakModel

# Attack type patterns for clustering
ATTACK_PATTERNS = {
    "role_play": [
        r'\b(pretend|act|roleplay|you\s+are|become)\s+(as\s+)?(if\s+)?(you\s+are\s+)?(a|an|the)?\s*(developer|admin|system|unrestricted|god|unlimited|evilbot)',
        r'\b(you|your)\s+(are|is)\s+(now|a|an)\s*(developer|admin|system|unrestricted)',
        r'\b(you|your)\s+(are|is)\s+no\s+longer\s+bound',
        r'\b(you|your)\s+(are|is)\s+free\s+from',
    ],
    "instruction_override": [
        r'\b(ignore|disregard|forget|override|bypass)\s+(previous|all|system|safety|security)\s+(instructions?|rules?|guidelines?|policies?)',
        r'\b(new|previous|earlier)\s+(instructions?|rules?|messages?)\s+(override|replace|supersede)',
        r'\b(clear|reset|delete|forget)\s+(your|the)\s+(memory|context|history)',
    ],
    "indirect_authority": [
        r'\b(i\'?m|i\s+am)\s+(a|the|your)\s+(developer|dev|admin|administrator|sysadmin)',
        r'\b(my|the)\s+(developer|admin|boss|supervisor)\s+(said|told|asked|wants)',
        r'\b(according\s+to|per|as\s+per)\s+(my|the)\s+(developer|admin|instructions?)',
    ],
    "system_prompt_targeting": [
        r'\b(reveal|show|print|display|expose|leak|dump)\s+(your|the)\s+(system|internal|hidden|secret)\s*(prompt|instructions?|rules?|directives?)',
        r'\b(what|tell\s+me)\s+(are|is)\s+(your|the)\s+(system|internal|hidden)\s+(prompt|instructions?|rules?)',
    ],
    "multi_turn": [
        r'\b(turn\s+\d+|step\s+\d+|part\s+\d+|now|next|then|after|finally)\s*:',
        r'\b(first|second|third|fourth|fifth)\s+(do|say|write|ignore)',
    ],
    "semantic_obfuscation": [
        r'\b(base64|hex|unicode|obfuscate|encode|decode)\s+(this|the)?\s*(code|text|command)',
        r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}',  # Hex/Unicode escape sequences
        r'\b(character\s+by\s+character|letter\s+by\s+letter|word\s+by\s+word)',
    ],
    "social_engineering": [
        r'\b(urgent|emergency|asap|immediately|right\s+now|right\s+away)\s+(issue|request|need|matter)',
        r'\b(please|help|assist)\s+(me|us)\s+(with|to|for)\s+(this|that|the)\s+(urgent|emergency|critical)',
        r'\b(i\s+need|we\s+need)\s+(this|that|it)\s+(urgently|immediately|asap)',
    ],
    "protocol_abuse": [
        r'\{\s*["\']?(action|command|execute|run)["\']?\s*:',  # JSON injection
        r'<xml>\s*<(command|execute|run)>',  # XML injection
        r'```(python|bash|shell|javascript|json)\s*\n.*?(execute|run|system|eval)',
    ],
    "delayed_intent": [
        r'\b(but|however|although|though)\s+(ignore|disregard|forget|override)',
        r'\b(and|then|now|next)\s+(ignore|disregard|forget|override)',
        r'\b(also|additionally)\s+(ignore|disregard|forget|override)',
    ],
    "capability_request": [
        r'\b(what|tell\s+me|show\s+me)\s+(are|is)\s+(your|the)\s+(capabilities?|abilities?|features?|functions?)',
        r'\b(can|could|are\s+you\s+able\s+to)\s+(you|you\s+do)\s+(anything|everything|unrestricted)',
    ],
    "other": []  # Catch-all for unclassified
}

def classify_attack_type(prompt: str) -> str:
    """
    Classify attack type based on patterns.
    
    Args:
        prompt: Jailbreak prompt
    
    Returns:
        Attack type name
    """
    prompt_lower = prompt.lower()
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        if attack_type == "other":
            continue
        
        for pattern in patterns:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                return attack_type
    
    return "other"

def load_model():
    """Load trained ML model."""
    model = SecurityJailbreakModel(jailbreak_threshold=0.15)
    model_dir = Path("models/security")
    
    try:
        with open(model_dir / "security_model.pkl", 'rb') as f:
            model.model = pickle.load(f)
        with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
            model.vectorizer = pickle.load(f)
        with open(model_dir / "security_encoder.pkl", 'rb') as f:
            model.label_encoder = pickle.load(f)
        with open(model_dir / "security_threshold.txt", 'r') as f:
            model.jailbreak_threshold = float(f.read().strip())
        model.is_trained = True
        return model
    except Exception as e:
        print(f"[ERROR] Could not load ML model: {e}")
        return None

def load_test_datasets() -> List[Tuple[str, List[str], List[str]]]:
    """
    Load all test datasets.
    
    Returns:
        List of (dataset_name, prompts, labels) tuples
    """
    datasets = []
    
    # Dataset 1: Prompt_INJECTION_And_Benign_DATASET.jsonl
    dataset_path = Path("Prompt_INJECTION_And_Benign_DATASET.jsonl")
    if dataset_path.exists():
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    prompt = data.get('prompt', '').strip()
                    if not prompt:
                        continue
                    prompts.append(prompt)
                    # Map dataset labels: 'malicious' -> 'jailbreak_attempt'
                    dataset_label = data.get('label', '').lower().strip()
                    if dataset_label == 'malicious':
                        labels.append('jailbreak_attempt')
                    else:
                        labels.append('benign')
                except json.JSONDecodeError:
                    continue
        datasets.append(("Prompt_INJECTION_And_Benign_DATASET.jsonl", prompts, labels))
    
    # Dataset 2: AI Agent Evasion Dataset.jsonl
    dataset_path = Path("AI Agent Evasion Dataset.jsonl")
    if dataset_path.exists():
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    prompt = data.get('prompt', '').strip()
                    if not prompt:
                        continue
                    prompts.append(prompt)
                    # Map dataset labels: 'malicious' -> 'jailbreak_attempt'
                    dataset_label = data.get('label', '').lower().strip()
                    if dataset_label == 'malicious':
                        labels.append('jailbreak_attempt')
                    else:
                        labels.append('benign')
                except json.JSONDecodeError:
                    continue
        datasets.append(("AI Agent Evasion Dataset.jsonl", prompts, labels))
    
    # Dataset 3: prompt-injection-dataset.csv
    dataset_path = Path("prompt-injection-dataset.csv")
    if dataset_path.exists():
        import csv
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                prompt = (row.get('prompt', '') or row.get('text', '')).strip()
                if not prompt:
                    continue
                prompts.append(prompt)
                # Map labels
                label = row.get('label', 'benign').lower().strip()
                if label in ['jailbreak_attempt', 'jailbreak', 'malicious', 'injection']:
                    labels.append('jailbreak_attempt')
                else:
                    labels.append('benign')
        datasets.append(("prompt-injection-dataset.csv", prompts, labels))
    
    # Dataset 4: mutated_all.csv
    dataset_path = Path("mutated_all.csv")
    if dataset_path.exists():
        import csv
        prompts, labels = [], []
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                prompt = (row.get('prompt', '') or row.get('text', '')).strip()
                if not prompt:
                    continue
                prompts.append(prompt)
                # Map labels
                label = row.get('label', 'benign').lower().strip()
                if label in ['jailbreak_attempt', 'jailbreak', 'malicious', 'injection']:
                    labels.append('jailbreak_attempt')
                else:
                    labels.append('benign')
        datasets.append(("mutated_all.csv", prompts, labels))
    
    return datasets

def analyze_false_negatives():
    """Main analysis function."""
    print("="*70)
    print("FALSE NEGATIVE ANALYSIS")
    print("="*70)
    
    # Load model
    print("\n[1/4] Loading model...")
    ml_model = load_model()
    if not ml_model:
        print("[ERROR] Cannot proceed without ML model")
        return
    
    detector = SecurityJailbreakDetector(
        ml_model=ml_model,
        enable_escalation=True
    )
    print("[OK] Model loaded")
    
    # Load test datasets
    print("\n[2/4] Loading test datasets...")
    datasets = load_test_datasets()
    print(f"[OK] Loaded {len(datasets)} datasets")
    
    # Collect all false negatives
    print("\n[3/4] Running predictions and collecting false negatives...")
    all_false_negatives = []
    
    for dataset_name, prompts, labels in datasets:
        print(f"\n  Analyzing {dataset_name} ({len(prompts)} prompts)...")
        fn_count = 0
        
        for i, (prompt, label) in enumerate(zip(prompts, labels)):
            if label != 'jailbreak_attempt':
                continue
            
            result = detector.predict(prompt)
            
            # Check if it's a false negative (should be jailbreak but wasn't detected)
            if not result.is_jailbreak:
                fn_count += 1
                attack_type = classify_attack_type(prompt)
                all_false_negatives.append({
                    'prompt': prompt,
                    'dataset': dataset_name,
                    'attack_type': attack_type,
                    'confidence': result.confidence,
                    'jailbreak_probability': result.jailbreak_probability,
                    'detection_method': result.detection_method,
                    'risk_score': result.risk_score,
                    'escalation_action': result.escalation_action
                })
        
        print(f"    Found {fn_count} false negatives")
    
    total_fns = len(all_false_negatives)
    print(f"\n[OK] Total false negatives: {total_fns}")
    
    # Cluster by attack type
    print("\n[4/4] Clustering by attack type...")
    clusters = defaultdict(list)
    for fn in all_false_negatives:
        clusters[fn['attack_type']].append(fn)
    
    # Generate analysis report
    print("\n[OK] Generating analysis report...")
    
    report_lines = [
        "# False Negative Analysis",
        "",
        f"**Analysis Date**: {Path(__file__).stat().st_mtime}",
        f"**Total False Negatives**: {total_fns}",
        "",
        "## Executive Summary",
        "",
        f"This analysis identifies {total_fns} false negatives (missed jailbreak attempts) "
        "across test datasets. These represent blind spots in the current detection system.",
        "",
        "## Attack Type Clusters",
        "",
        "False negatives clustered by attack pattern:",
        ""
    ]
    
    # Sort clusters by size (largest first)
    sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
    
    for attack_type, fns in sorted_clusters:
        count = len(fns)
        percentage = (count / total_fns * 100) if total_fns > 0 else 0
        
        report_lines.extend([
            f"### {attack_type.replace('_', ' ').title()} ({count} FNs, {percentage:.1f}%)",
            "",
            f"**Count**: {count}",
            f"**Percentage**: {percentage:.1f}%",
            "",
            "**Sample Prompts**:",
            ""
        ])
        
        # Show up to 5 examples
        for i, fn in enumerate(fns[:5], 1):
            prompt_preview = fn['prompt'][:100] + "..." if len(fn['prompt']) > 100 else fn['prompt']
            report_lines.append(f"{i}. `{prompt_preview}`")
            report_lines.append(f"   - Confidence: {fn['confidence']:.3f}")
            prob_str = f"{fn['jailbreak_probability']:.3f}" if fn['jailbreak_probability'] is not None else "N/A"
            report_lines.append(f"   - Jailbreak Prob: {prob_str}")
            report_lines.append(f"   - Detection Method: {fn['detection_method']}")
            report_lines.append(f"   - Dataset: {fn['dataset']}")
            report_lines.append("")
        
        if len(fns) > 5:
            report_lines.append(f"*... and {len(fns) - 5} more*")
            report_lines.append("")
    
    # Add recommendations
    report_lines.extend([
        "## Recommendations",
        "",
        "### High Priority (Largest Clusters)",
        ""
    ])
    
    # Top 3 clusters
    for attack_type, fns in sorted_clusters[:3]:
        count = len(fns)
        report_lines.append(f"1. **{attack_type.replace('_', ' ').title()}** ({count} FNs)")
        report_lines.append(f"   - Add targeted rule patterns for this attack type")
        report_lines.append(f"   - Consider expanding ML training data with similar examples")
        report_lines.append("")
    
    report_lines.extend([
        "### Targeted Rule Patching Strategy",
        "",
        "For each cluster, create small, precise, explainable rules:",
        "",
        "- **Role Play**: Detect `\"You are now X\"` patterns",
        "- **Instruction Override**: Detect `\"Ignore previous\"` variations",
        "- **Indirect Authority**: Detect `\"I'm a developer\"` claims",
        "- **System Prompt Targeting**: Detect `\"Reveal your system prompt\"` queries",
        "- **Multi-turn**: Detect `\"Turn 1: ... Turn 2: ignore\"` patterns",
        "",
        "### Next Steps",
        "",
        "1. Review each cluster's sample prompts",
        "2. Design targeted rules for top 3 clusters",
        "3. Test rules on false negatives before deploying",
        "4. Monitor impact on false positive rate",
        ""
    ])
    
    # Write report
    report_path = Path("false_negative_analysis.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))
    
    print(f"\n[SUCCESS] Analysis complete!")
    print(f"  Report saved to: {report_path}")
    print(f"\n  Top 3 Attack Types:")
    for i, (attack_type, fns) in enumerate(sorted_clusters[:3], 1):
        print(f"    {i}. {attack_type.replace('_', ' ').title()}: {len(fns)} FNs")
    
    # Also save raw data as JSON
    json_path = Path("false_negatives_raw.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_false_negatives': total_fns,
            'clusters': {
                attack_type: [
                    {
                        'prompt': fn['prompt'],
                        'dataset': fn['dataset'],
                        'confidence': fn['confidence'],
                        'jailbreak_probability': fn['jailbreak_probability'],
                        'detection_method': fn['detection_method'],
                        'risk_score': fn['risk_score'],
                        'escalation_action': fn['escalation_action']
                    }
                    for fn in fns
                ]
                for attack_type, fns in sorted_clusters
            }
        }, f, indent=2, ensure_ascii=False)
    
    print(f"  Raw data saved to: {json_path}")

if __name__ == "__main__":
    analyze_false_negatives()

