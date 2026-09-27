# RAAL Plan

description: Generates a multi-step strategy based on the reflection to achieve the target goal.

---

# Workflow

## Objective

Your goal is to transform a high-level objective and the current reflection into an ordered sequence of atomic, executable actions.

## Rules of Engagement

- **Atomicity**: Each step in the plan must be a single, discrete action (e.g., one command or one file modification).
- **Contingency Planning**: For complex tasks, include "contingency branches" in your plan to handle predicted failures.
- **Sequential Logic**: Ensure the steps are ordered logically so that each step builds upon the success of the previous one.

## Instructions

1. **Analyze Goal and Reflection**: Review the user's objective and the reasoning provided by `raal_reflect`.
2. **Decompose Task**: Break down the goal into the smallest possible actionable steps.
3. **Define Actions**: For each step, specify:
   - The action type (e.g., `execute`, `git_operation`).
   - The specific command or parameters required.
4. **Validate Plan**: Ensure the plan is complete and that every step has a clear exit condition or verification requirement.

---
*Skill Version: 1.0.0*
