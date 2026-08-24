"""Analyze predictions on AI Agent Evasion Dataset to understand false positives."""

import json
import pickle
from pathlib import Path
from train_security_model import SecurityJailbreakModel

def main():
    # Load model
    model = SecurityJailbreakModel(jailbreak_threshold=0.15)
    model_dir = Path("models/security")
    
    with open(model_dir / "security_model.pkl", 'rb') as f:
        model.model = pickle.load(f)
    with open(model_dir / "security_vectorizer.pkl", 'rb') as f:
        model.vectorizer = pickle.load(f)
    with open(model_dir / "security_encoder.pkl", 'rb') as f:
        model.label_encoder = pickle.load(f)
    model.is_trained = True
    
    # Load dataset
    benign_examples = []
    malicious_examples = []
    
    with open("AI Agent Evasion Dataset.jsonl", 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            label = entry.get('label', '').lower()
            if label == 'benign' and len(benign_examples) < 10:
                benign_examples.append(entry)
            elif label == 'malicious' and len(malicious_examples) < 10:
                malicious_examples.append(entry)
            if len(benign_examples) >= 10 and len(malicious_examples) >= 10:
                break
    
    print("="*70)
    print("ANALYZING PREDICTIONS ON AI AGENT EVASION DATASET")
    print("="*70)
    
    print("\n[1] BENIGN PROMPTS (False Positives):")
    print("-"*70)
    for i, ex in enumerate(benign_examples[:5], 1):
        prompt = ex['prompt']
        result = model.predict(prompt)
        print(f"\nExample {i}:")
        print(f"  Prompt: {prompt[:150]}...")
        print(f"  Label: {ex.get('label')}")
        print(f"  Prediction: {result['label']}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print(f"  Jailbreak Probability: {result.get('jailbreak_probability', 0):.3f}")
        print(f"  Threshold: {result.get('threshold_used', 0.15)}")
    
    print("\n[2] MALICIOUS PROMPTS (True Positives):")
    print("-"*70)
    for i, ex in enumerate(malicious_examples[:5], 1):
        prompt = ex['prompt']
        result = model.predict(prompt)
        print(f"\nExample {i}:")
        print(f"  Prompt: {prompt[:150]}...")
        print(f"  Label: {ex.get('label')}")
        print(f"  Attack Type: {ex.get('attack_type')}")
        print(f"  Prediction: {result['label']}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print(f"  Jailbreak Probability: {result.get('jailbreak_probability', 0):.3f}")
    
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)

if __name__ == "__main__":
    main()



