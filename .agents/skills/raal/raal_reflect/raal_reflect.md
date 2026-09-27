---
name: "raal_reflect"
description: "Reflective Agentic Loop (RAAL) - Reflect: Analyzes observations and compares them against the Long-Term Memory (LTM) to decide the next step in the RAAL loop."
---

# Workflow

## Objective

Your goal is to perform cognitive reasoning on an observation to determine if the current state matches the desired goal, or if a recovery/escalation is required.

## Rules of Engagement

- **LTM Integration**: You must always check the `knowledge_base/patterns.yaml` (for approved exceptions) and `knowledge_base/failure_history.yaml` (to avoid repetitive failures).
- **Decision Rigor**: You must provide a clear reasoning for every decision.
- **No Action**: This skill is purely cognitive; it does not execute commands or modify files.

## Instructions

1. **Analyze Observation**: Examine the `content` and `error` provided by the `raal_observe` skill.
2. **Check Patterns**: 
   - Compare the error or state against `knowledge_base/patterns.yaml`.
   - If a match is found (e.g., an intentional security bypass), decide to `CONTINUE`.
3. **Check History**: 
   - Compare the current error against entries in `knowledge_base/failure_history.yaml`.
   - If this exact error has been encountered and failed before, decide to `ESCALATE`.
4. **Determine Decision**:
   - **CONTINUE**: The state is correct or matches an approved pattern.
   - **RECOVER**: An error was detected that can be fixed by a targeted action.
   - **ESCALATE**: The error is unresolvable, an environment issue, or the retry limit has been reached.
5. **Output Decision**: Return a structured decision including `reasoning` and the `suggested_action`.

---
*Skill Version: 1.0.0*
