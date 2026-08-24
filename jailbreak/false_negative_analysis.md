# False Negative Analysis

**Analysis Date**: 1767200799.200985
**Total False Negatives**: 0

## Executive Summary

This analysis identifies 0 false negatives (missed jailbreak attempts) across test datasets. These represent blind spots in the current detection system.

## Attack Type Clusters

False negatives clustered by attack pattern:

## Recommendations

### High Priority (Largest Clusters)

### Targeted Rule Patching Strategy

For each cluster, create small, precise, explainable rules:

- **Role Play**: Detect `"You are now X"` patterns
- **Instruction Override**: Detect `"Ignore previous"` variations
- **Indirect Authority**: Detect `"I'm a developer"` claims
- **System Prompt Targeting**: Detect `"Reveal your system prompt"` queries
- **Multi-turn**: Detect `"Turn 1: ... Turn 2: ignore"` patterns

### Next Steps

1. Review each cluster's sample prompts
2. Design targeted rules for top 3 clusters
3. Test rules on false negatives before deploying
4. Monitor impact on false positive rate
