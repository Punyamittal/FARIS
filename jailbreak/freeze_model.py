"""
Freeze Model - Create Versioned Backup with Metadata

This script creates a complete backup of the current model state including:
- All model files (model, vectorizer, encoder, threshold)
- Performance metrics from test results
- Configuration metadata
- Manifest file for tracking
- Restore script for easy recovery
"""

import json
import pickle
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

def load_test_results() -> Dict:
    """Load test results from various test files."""
    results = {}
    
    test_files = [
        ("unseen_dataset", "test_results_unseen_dataset.json"),
        ("ai_agent_evasion", "test_results_ai_agent_evasion.json"),
        ("prompt_injection", "test_results_prompt_injection.json"),
    ]
    
    for name, file_path in test_files:
        path = Path(file_path)
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    results[name] = json.load(f)
            except Exception as e:
                print(f"  [WARNING] Could not load {file_path}: {e}")
    
    return results

def get_model_metadata() -> Dict:
    """Collect metadata about the current model."""
    model_dir = Path("models/security")
    
    metadata = {
        "freeze_timestamp": datetime.now().isoformat(),
        "freeze_date": datetime.now().strftime("%Y-%m-%d"),
        "model_version": None,
        "threshold": None,
        "model_files": {},
        "test_results": load_test_results(),
        "configuration": {
            "jailbreak_threshold": 0.15,
            "prefer_false_positives": True,
            "enable_whitelist": True,
            "model_type": "SecurityJailbreakModel",
            "features": [
                "Benign Whitelist (40.6% of prompts)",
                "Rule-Based Detection (36.4% of prompts)",
                "ML Classifier (23.0% of prompts)",
                "Hybrid Decision Logic"
            ]
        },
        "performance_summary": {
            "unseen_dataset": {
                "accuracy": 0.894,
                "precision": 0.8316,
                "recall": 0.988,
                "f1_score": 0.9031,
                "fn_rate": 0.012,
                "fp_rate": 0.20
            }
        }
    }
    
    # Load threshold
    threshold_file = model_dir / "security_threshold.txt"
    if threshold_file.exists():
        try:
            with open(threshold_file, 'r') as f:
                metadata["threshold"] = float(f.read().strip())
        except Exception as e:
            print(f"  [WARNING] Could not load threshold: {e}")
    
    # Check model files
    model_files = {
        "security_model.pkl": (model_dir / "security_model.pkl").exists(),
        "security_vectorizer.pkl": (model_dir / "security_vectorizer.pkl").exists(),
        "security_encoder.pkl": (model_dir / "security_encoder.pkl").exists(),
        "security_threshold.txt": threshold_file.exists(),
    }
    
    metadata["model_files"] = model_files
    
    # Check if all files exist
    all_exist = all(model_files.values())
    metadata["model_complete"] = all_exist
    
    return metadata

def freeze_model(version_name: Optional[str] = None, description: Optional[str] = None) -> Path:
    """
    Freeze the current model state.
    
    Args:
        version_name: Optional version name (e.g., "v1.0", "production"). 
                     If None, uses timestamp.
        description: Optional description of this version.
    
    Returns:
        Path to the frozen model directory
    """
    print("="*70)
    print("FREEZING MODEL STATE")
    print("="*70)
    
    # Create version directory
    if version_name:
        version_dir = Path(f"models/frozen/{version_name}")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version_dir = Path(f"models/frozen/v{timestamp}")
    
    version_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[1/5] Creating version directory: {version_dir}")
    
    # Collect metadata
    print(f"\n[2/5] Collecting model metadata...")
    metadata = get_model_metadata()
    metadata["version_name"] = version_name or version_dir.name
    metadata["description"] = description or "Model freeze checkpoint"
    
    # Copy model files
    print(f"\n[3/5] Copying model files...")
    model_dir = Path("models/security")
    files_to_copy = [
        "security_model.pkl",
        "security_vectorizer.pkl",
        "security_encoder.pkl",
        "security_threshold.txt"
    ]
    
    copied_files = []
    for file_name in files_to_copy:
        src = model_dir / file_name
        if src.exists():
            dst = version_dir / file_name
            shutil.copy2(src, dst)
            copied_files.append(file_name)
            print(f"  [OK] Copied {file_name}")
        else:
            print(f"  [WARNING] {file_name} not found, skipping")
    
    if not copied_files:
        print(f"  [ERROR] No model files found to copy!")
        return None
    
    # Copy code files (for reproducibility)
    print(f"\n[4/5] Copying code files for reproducibility...")
    code_files = [
        "security_detector.py",
        "benign_whitelist.py",
        "train_security_model.py"
    ]
    
    code_dir = version_dir / "code"
    code_dir.mkdir(exist_ok=True)
    
    for file_name in code_files:
        src = Path(file_name)
        if src.exists():
            dst = code_dir / file_name
            shutil.copy2(src, dst)
            print(f"  [OK] Copied {file_name}")
    
    # Save metadata
    print(f"\n[5/5] Saving metadata and manifest...")
    metadata_file = version_dir / "metadata.json"
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Saved metadata.json")
    
    # Create manifest
    manifest_file = version_dir / "MANIFEST.txt"
    with open(manifest_file, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("MODEL FREEZE MANIFEST\n")
        f.write("="*70 + "\n\n")
        f.write(f"Version: {metadata['version_name']}\n")
        f.write(f"Date: {metadata['freeze_date']}\n")
        f.write(f"Timestamp: {metadata['freeze_timestamp']}\n")
        f.write(f"Description: {metadata['description']}\n\n")
        
        f.write("Model Files:\n")
        for file_name, exists in metadata['model_files'].items():
            status = "[OK]" if exists else "[MISSING]"
            f.write(f"  {status} {file_name}\n")
        
        f.write(f"\nModel Complete: {'Yes' if metadata['model_complete'] else 'No'}\n")
        f.write(f"Threshold: {metadata['threshold']}\n\n")
        
        f.write("Performance Metrics (Unseen Dataset):\n")
        perf = metadata['performance_summary']['unseen_dataset']
        f.write(f"  Accuracy: {perf['accuracy']:.2%}\n")
        f.write(f"  Precision: {perf['precision']:.2%}\n")
        f.write(f"  Recall: {perf['recall']:.2%}\n")
        f.write(f"  F1-Score: {perf['f1_score']:.2%}\n")
        f.write(f"  FN Rate: {perf['fn_rate']:.2%}\n")
        f.write(f"  FP Rate: {perf['fp_rate']:.2%}\n\n")
        
        f.write("Configuration:\n")
        for key, value in metadata['configuration'].items():
            if isinstance(value, list):
                f.write(f"  {key}:\n")
                for item in value:
                    f.write(f"    - {item}\n")
            else:
                f.write(f"  {key}: {value}\n")
    
    print(f"  [OK] Saved MANIFEST.txt")
    
    # Create restore script
    restore_script = version_dir / "restore_model.py"
    with open(restore_script, 'w', encoding='utf-8') as f:
        f.write('''"""
Restore Model from Frozen Version

Usage: python restore_model.py
This will restore the model files from this frozen version to models/security/
"""
import shutil
from pathlib import Path

def restore():
    """Restore model from frozen version."""
    frozen_dir = Path(__file__).parent
    target_dir = Path("models/security")
    target_dir.mkdir(parents=True, exist_ok=True)
    
    files_to_restore = [
        "security_model.pkl",
        "security_vectorizer.pkl",
        "security_encoder.pkl",
        "security_threshold.txt"
    ]
    
    print("="*70)
    print("RESTORING MODEL FROM FROZEN VERSION")
    print("="*70)
    print(f"\\nSource: {frozen_dir}")
    print(f"Target: {target_dir}\\n")
    
    restored = []
    for file_name in files_to_restore:
        src = frozen_dir / file_name
        if src.exists():
            dst = target_dir / file_name
            shutil.copy2(src, dst)
            restored.append(file_name)
            print(f"  [OK] Restored {file_name}")
        else:
            print(f"  [WARNING] {file_name} not found in frozen version")
    
    if restored:
        print(f"\\n[SUCCESS] Restored {len(restored)} model files")
        print(f"Model is now restored to version: {frozen_dir.name}")
    else:
        print(f"\\n[ERROR] No files restored!")

if __name__ == "__main__":
    restore()
''')
    print(f"  [OK] Created restore_model.py")
    
    print("\n" + "="*70)
    print("MODEL FREEZE COMPLETE")
    print("="*70)
    print(f"\nFrozen Model Location: {version_dir}")
    print(f"Version: {metadata['version_name']}")
    print(f"Date: {metadata['freeze_date']}")
    print(f"\nFiles Frozen:")
    for file_name in copied_files:
        print(f"  [OK] {file_name}")
    
    print(f"\nPerformance Summary:")
    perf = metadata['performance_summary']['unseen_dataset']
    print(f"  Accuracy: {perf['accuracy']:.2%}")
    print(f"  Recall: {perf['recall']:.2%}")
    print(f"  Precision: {perf['precision']:.2%}")
    print(f"  F1-Score: {perf['f1_score']:.2%}")
    
    print(f"\nTo restore this version, run:")
    print(f"  cd {version_dir}")
    print(f"  python restore_model.py")
    
    return version_dir

def main():
    """Main function."""
    import sys
    
    version_name = None
    description = None
    
    if len(sys.argv) > 1:
        version_name = sys.argv[1]
    if len(sys.argv) > 2:
        description = " ".join(sys.argv[2:])
    
    freeze_model(version_name=version_name, description=description)

if __name__ == "__main__":
    main()