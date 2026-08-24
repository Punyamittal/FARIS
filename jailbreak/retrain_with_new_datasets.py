"""
Complete pipeline: Add new datasets and retrain security model.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Run complete pipeline."""
    print("="*70)
    print("COMPLETE TRAINING PIPELINE WITH NEW DATASETS")
    print("="*70)
    
    # Step 1: Add new datasets
    print("\n[STEP 1/2] Adding new datasets to training data...")
    try:
        result = subprocess.run(
            [sys.executable, "add_new_datasets_to_training.py"],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        print(result.stdout)
        if result.stderr:
            print("Warnings:", result.stderr)
        
        if result.returncode != 0:
            print(f"[ERROR] Failed to add datasets: {result.stderr}")
            return
    except Exception as e:
        print(f"[ERROR] Error adding datasets: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Step 2: Train model
    print("\n[STEP 2/2] Training security model on expanded dataset...")
    
    dataset_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    if not dataset_file.exists():
        print(f"[ERROR] Combined dataset not found: {dataset_file}")
        return
    
    try:
        from train_security_model import SecurityJailbreakModel
        
        print(f"\nUsing dataset: {dataset_file}")
        model = SecurityJailbreakModel(jailbreak_threshold=0.15)
        
        prompts, labels = model.load_dataset(str(dataset_file))
        
        if len(prompts) == 0:
            print("[ERROR] No data loaded!")
            return
        
        # Train
        recall = model.train(
            prompts, labels,
            balance=True,
            use_ensemble=True
        )
        
        # Save
        model.save()
        
        print("\n" + "="*70)
        print("[SUCCESS] TRAINING COMPLETE!")
        print("="*70)
        print(f"Jailbreak Recall: {recall:.2%}")
        print(f"Threshold: {model.jailbreak_threshold}")
        print(f"\nModel saved to: models/security/")
        print(f"\nYou can now test with:")
        print(f"  python test_on_prompt_injection_dataset.py")
        
    except Exception as e:
        print(f"[ERROR] Training failed: {e}")
        import traceback
        traceback.print_exc()
        return

if __name__ == "__main__":
    main()




