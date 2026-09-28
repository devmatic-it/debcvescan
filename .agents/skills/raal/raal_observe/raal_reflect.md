# Skill: raal_reflect

## Description
A dedicated reasoning step where the agent evaluates the quality and implications of observations. It is the second stage of the RAAL loop.

## Input
- `observation`: The content read from `.agents/memory/sessions/STATE.md`.

## Process
1. **Analyze**: Evaluate the observation for:
    - Success/Failure of the last action.
    - Consistency with current goals.
    - Identification of new patterns or constraints (for the **Learn** stage).
2. **Identify Root Cause**: If an error occurred, classify it (Syntax, Environment, Permission, or Logic).
3. **Determine Next Step**: Decide whether to proceed to `PLAN` or enter `RECOVERING`.

## Output
- A structured reflection containing:
    - `analysis`: Summary of the observation.
    - `root_cause`: (If applicable) The identified cause of failure.
    - `learning_candidate`: Boolean indicating if new knowledge should be added to LTM.

## Constraints
- Must not modify the environment; it is a read-only reasoning step.
- Reflection must be concise to preserve context for the next loop.