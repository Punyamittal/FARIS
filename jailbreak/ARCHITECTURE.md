# FARIS Architecture Notes

See [README.md](README.md) for the full product overview.

## Closed-loop controller

```
UNTRUSTED INPUT
→ PROVENANCE
→ ATTACK ANALYSIS
→ CONTEXTUAL RISK
→ RISK TRAJECTORY
→ CAPABILITY CONTROL
→ TOOL-CALL AUTHORIZATION
→ POLICY DECISION
→ AI EXECUTION (optional / mocked)
→ POST-EXECUTION RISK UPDATE
```

## Compatibility

- `AntiJailbreakPipeline.process()` remains available for prompt-only flows.
- `FARISPipeline` is the recommended entry point for agent + tool workflows.

## Policy version

Default policy version: `faris-1.0.0` (see `policy_engine.DEFAULT_POLICY`).
