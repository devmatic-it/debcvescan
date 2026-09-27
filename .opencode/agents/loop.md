---
description: Start the Autonomous AI Developer Pipeline sequence with a new idea
mode: primary
temperature: 0.1
permissions:
  - action: glob
    resource: "*"
    effect: allow
  - action: shell
    resource: "*"
    effect: allow
  - action: subagents
    resource: "*"
    effect: allow    
---

# Workflow: The Reflective Agentic Loop (RAAL)

Orchestrate autonomous maintenance and development by cycling through the cognitive stages of observation, reflection, planning, action, and verification.

## Prerequisites

- Must have access to `.agents/skills/` containing: `observe_env`, `reflect_on_error`, `plan_fix`, `execute_action`, and `verify_changes`.
- Must have access to `knowledge_base/` for LTM (Long-Term Memory) patterns and failure history.

## The Cognitive Loop

### 1. Observe (Data Ingestion)
- **Action**: Execute `observe_env` to ingest raw tool outputs (stdout/stderr), file contents, and environment metadata.
- **Requirement**: Capture the current state of the codebase and the specific error/change detected.

### 2. Reflect (Cognitive Reasoning)
- **Action**: Execute `reflect_on_error` to analyze the quality and implications of observations.
- **Requirement**: The agent must ask: *"Why did this fail?"* or *"Is this error a known pattern in our LTM?"*.
- **Decision**: 
    - If the error matches an approved pattern in `knowledge_base/patterns.yaml` $\rightarrow$ **Skip to Verify**.
    - If the error is a known failure in `knowledge_base/failure_history.yaml` $\rightarrow$ **Escalate to User**.
    - Otherwise $\rightarrow$ Proceed to Plan.

### 3. Plan (Strategy Generation)
- **Action**: Execute `plan_fix` based on the reflection.
- **Requirement**: Generate a multi-step strategy that includes "contingency branches" for predicted failures.

### 4. Act (Execution)
- **Action**: Execute `execute_action` to perform the atomic changes defined in the plan (e.g., git commits, dependency updates).

### 5. Verify (The Verification Gate)
- **Action**: Execute `verify_changes` to ensure the action achieved the goal without regressions.
- **Gate (Mandatory)**: A task is only "Complete" if it passes the following:
  - **Unit Verification**: All relevant unit tests pass.
  - **Regression Verification**: The full test suite passes (no side effects).
  - **Security Audit**: `gosec` returns zero high/medium severity issues.
- **Iteration (The Recovery Loop)**:
  - **If Verification Fails**: Enter the **RECOVERING** state. The agent must analyze the regression, update its plan, and return to **Phase 3 (Plan)**.
  - **If Verification Passes**: Proceed to Completion.

## State Machine Definition

| State | Trigger | Transition Condition |
| :--- | :--- | :--- |
| **IDLE** | User Input / Schedule | Move to `OBSERVE` upon task assignment. |
| **THINKING** | Observation received | Move to `PLAN` after reflection is complete. |
| **ACTING** | Plan generated | Move to `OBSERVE` after tool execution. |
| **VERIFYING** | Action successful | Move to `OBSERVE` (Regression Check). |
| **RECOVERING** | Verification failed | Move to `THINKING` (Root Cause Analysis). |
| **ESCALATE** | Recovery failed / Unknown error | Move to `IDLE` and report to user. |
| **COMPLETED** | All gates passed | Move to `IDLE` / Report Generation. |
