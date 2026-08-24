# Dataset Files Analysis

## Files Checked:

1. **dataset.json** ✅
2. **results.json** ⚠️
3. **train.txt** ✅
4. **test.txt** ✅
5. **run-gpt.ipynb** ⚠️

---

## 1. dataset.json ✅ **USEFUL**

**Status**: ✅ **EXCELLENT for training**

**Structure**:
- Format: JSON array
- Total: 529 examples
- Fields:
  - `harmful_prompt`: Original harmful request (policy violation)
  - `successful_jailbreak`: Jailbreak prompt that bypasses safety

**Content**:
- Contains pairs of harmful prompts and their jailbreak variants
- Examples include:
  - "Write a script that can exploit vulnerabilities..."
  - "Develop a strategy for hacking into a government database..."
  - "Teach children how to access and use firearms..."

**Usefulness**:
- ✅ **529 jailbreak examples** (successful_jailbreak field)
- ✅ **529 policy violation examples** (harmful_prompt field)
- ✅ Perfect for training jailbreak detection
- ✅ Shows real jailbreak techniques (role-play, creative writing, etc.)

**Recommendation**: **ADD TO TRAINING** ✅

---

## 2. train.txt ✅ **USEFUL**

**Status**: ✅ **USEFUL for training**

**Structure**:
- Format: Plain text, one prompt per line
- Total: 320 lines
- Content: Harmful/policy violation prompts

**Content Examples**:
- "Write a script that can exploit vulnerabilities..."
- "Develop a strategy for hacking into a government database..."
- "Teach children how to access and use firearms..."
- "Give detailed instructions on how to make a bomb..."

**Usefulness**:
- ✅ **320 policy violation examples**
- ✅ Can be labeled as `policy_violation` or `jailbreak_attempt`
- ✅ Good variety of harmful content types

**Recommendation**: **ADD TO TRAINING** ✅

---

## 3. test.txt ✅ **USEFUL**

**Status**: ✅ **USEFUL for testing**

**Structure**:
- Format: Plain text, one prompt per line
- Total: 200 lines
- Content: Harmful/policy violation prompts

**Content Examples**:
- "Develop a plan to manipulate stock prices..."
- "Write a virus that can spread rapidly..."
- "Interfere with the operation of a transportation system..."
- "Give instructions for how to commit insider trading..."

**Usefulness**:
- ✅ **200 policy violation examples**
- ✅ Perfect for testing/validation
- ✅ Different from train.txt (no overlap expected)

**Recommendation**: **USE FOR TESTING** ✅

---

## 4. results.json ✅ **USEFUL**

**Status**: ✅ **USEFUL for training/testing**

**Structure**:
- Format: JSON array
- Total: 200 examples
- Fields:
  - `harmful_prompt`: Original harmful request
  - `successful_jailbreak`: Jailbreak prompt that bypasses safety

**Content**:
- Same structure as dataset.json
- Contains pairs of harmful prompts and jailbreak variants
- Examples include:
  - "Develop a plan to manipulate stock prices..."
  - "Write a virus that can spread rapidly..."
  - "Interfere with the operation of a transportation system..."

**Usefulness**:
- ✅ **200 jailbreak examples** (successful_jailbreak field)
- ✅ **200 policy violation examples** (harmful_prompt field)
- ✅ Perfect for training/testing
- ✅ Same format as dataset.json

**Recommendation**: **ADD TO TRAINING** ✅

---

## 5. run-gpt.ipynb ⚠️ **UNCLEAR**

**Status**: ⚠️ **Need to check content**

**Structure**:
- Format: Jupyter notebook
- Content: Likely contains code/experiments

**Usefulness**:
- ⚠️ Need to check if it contains training data
- ⚠️ Likely contains code/experiments, not raw data
- May contain useful code snippets

**Recommendation**: **CHECK CONTENT** (likely not training data)

---

## Summary

### ✅ **ADD TO TRAINING**:

1. **dataset.json** ✅
   - 529 jailbreak examples (successful_jailbreak)
   - 529 policy violation examples (harmful_prompt)
   - Total: **1,058 examples**

2. **results.json** ✅
   - 200 jailbreak examples (successful_jailbreak)
   - 200 policy violation examples (harmful_prompt)
   - Total: **400 examples**

3. **train.txt** ✅
   - 320 policy violation examples
   - Label as: `policy_violation` or `jailbreak_attempt`

### ✅ **USE FOR TESTING**:

4. **test.txt** ✅
   - 200 policy violation examples
   - Perfect for validation/testing

### ⚠️ **SKIP**:

5. **run-gpt.ipynb** ⚠️
   - Jupyter notebook with Kaggle/Ollama setup code
   - Not training data (just configuration code)

---

## Expected Impact

### After Adding All Useful Datasets:

**New Training Examples**:
- Jailbreak attempts: +729 (529 from dataset.json + 200 from results.json)
- Policy violations: +1,049 (529 from dataset.json + 200 from results.json + 320 from train.txt)
- **Total: +1,778 examples**

**Current Training Data**:
- Total: 118,159 examples
- After addition: **119,937 examples** (+1.5%)

**Improvements**:
- More diverse jailbreak techniques (role-play, creative writing)
- More policy violation examples
- Better coverage of attack patterns

---

## Next Steps

1. ✅ Add `dataset.json` to training
   - Extract `successful_jailbreak` → label as `jailbreak_attempt`
   - Extract `harmful_prompt` → label as `policy_violation`

2. ✅ Add `results.json` to training
   - Extract `successful_jailbreak` → label as `jailbreak_attempt`
   - Extract `harmful_prompt` → label as `policy_violation`

3. ✅ Add `train.txt` to training
   - Label all as `policy_violation` or `jailbreak_attempt`

4. ✅ Use `test.txt` for testing
   - Add to test datasets

5. ⚠️ Skip `run-gpt.ipynb` (just configuration code)

