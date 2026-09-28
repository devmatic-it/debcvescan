# Skill: raal_plan

## Description
Generates a multi-step strategy based on the reflection, including contingency branches for predicted failures. It is the third stage of the RAAL loop.

## Input
- `reflection`: The output from the `raal_reflect` skill.
- `current_goal`: The high-level objective assigned to the agent.

## Process
1. **Decompose**: Break down the goal into atomic, executable steps.
2. **Contingency Planning**: For each step, identify a potential failure mode and define a fallback action (e.g., "If `npm install` fails, check node version").
3. **Sequence**: Order the steps to ensure logical progression and dependency management.

## Output
- A structured plan containing:
    - `steps`: An array of objects, each with a `description` and `action`.
    - `contingencies`: A mapping of steps to fallback actions.

## Constraints
- Plans must be incremental; do not attempt to solve the entire goal in one massive plan.
- Every step must be an atomic tool call or a sequence of tool calls.