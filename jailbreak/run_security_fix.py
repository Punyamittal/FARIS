"""
Master script to run the complete security fix pipeline.

Steps:
1. Relabel datasets (separate policy violations from jailbreaks)
2. Train security-focused model
3. Evaluate on test dataset
"""

import subprocess
import sys
from pathlib import Path

def run_step(name: str, script: str):
    """Run a step and check for errors."""
    print("\n" + "="*70)
    print(f"STEP: {name}")
    print("="*70)
    
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        print(result.stdout)
        if result.stderr:
            print("Warnings/Errors:", result.stderr)
        
        if result.returncode != 0:
            print(f"\n[ERROR] Step failed: {name}")
            print(f"Error output: {result.stderr}")
            return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Exception in {name}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run complete security fix pipeline."""
    print("="*70)
    print("SECURITY FIX PIPELINE")
    print("="*70)
    print("\nThis will:")
    print("  1. Relabel datasets (separate policy violations from jailbreaks)")
    print("  2. Train security-focused model (low threshold, high recall)")
    print("  3. Evaluate on test dataset")
    print("\nStarting...")
    
    # Step 1: Relabel
    if not run_step("Relabel Datasets", "relabel_dataset.py"):
        print("\n[ERROR] Relabeling failed. Please check errors above.")
        return
    
    # Check if relabeled dataset exists
    relabeled_file = Path("datasets/relabeled/all_relabeled_combined.jsonl")
    if not relabeled_file.exists():
        print("\n[ERROR] Relabeled dataset not created!")
        return
    
    print(f"\n[OK] Relabeled dataset created: {relabeled_file}")
    
    # Step 2: Train
    if not run_step("Train Security Model", "train_security_model.py"):
        print("\n[ERROR] Training failed. Please check errors above.")
        return
    
    # Check if model exists
    model_file = Path("models/security/security_model.pkl")
    if not model_file.exists():
        print("\n[ERROR] Model not created!")
        return
    
    print(f"\n[OK] Security model created: {model_file}")
    
    # Step 3: Evaluate
    if not run_step("Evaluate Security Model", "evaluate_security_model.py"):
        print("\n[WARNING] Evaluation had issues, but model is trained.")
        print("You can run evaluate_security_model.py manually.")
    
    print("\n" + "="*70)
    print("[SUCCESS] SECURITY FIX PIPELINE COMPLETE!")
    print("="*70)
    print("\nNext steps:")
    print("  1. Review evaluation results in security_evaluation_results.json")
    print("  2. Test the model: python evaluate_security_model.py")
    print("  3. Integrate with your pipeline using SecurityJailbreakDetector")
    print("\nKey improvements:")
    print("  ✅ Separated policy violations from jailbreak attempts")
    print("  ✅ Low threshold (0.15) for high recall")
    print("  ✅ Rule-based pre-filter catches obvious cases")
    print("  ✅ Heavy class weights (8:1) penalize false negatives")
    print("  ✅ Optimized for recall, not accuracy")

if __name__ == "__main__":
    main()




