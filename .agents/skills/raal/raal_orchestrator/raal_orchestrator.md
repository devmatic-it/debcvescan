# Skill: raal_orchestrator

## Description
Manages the RAAL state machine and handles task decomposition into independent sub-tasks. It is the central controller of the agentic architecture.

## Input
- `high_level_goal`: The user's original request or objective.

## Process
1. **Decomposition**: Break the `high_level_goal` into independent sub-tasks.
2. **Sub-agent Spawning**: For each sub-task, spawn a dedicated implementation loop (Engineer) in an isolated Git worktree.
3. **State Management**: Monitor the state of all sub-agents (IDLE, THINKING, ACTING, VERIFYING, COMPLETED, SUSPENDED).
4. **Integration**: 
    - Once all sub-agents reach `COMPLETED`, perform a sequential merge of their worktrees into the main branch.
    - Execute a final global regression check via `raal_verify`.
5. **Conflict Resolution**: If merge conflicts occur, transition to the `CONFLICT_RESOLUTION` state and assign a sub-agent to resolve them.
6. **Escalation**: If any agent reaches the `SUSPENDED` state (retry limit reached), escalate to the human user.

## Output
- A high-level status report of all sub-tasks and the overall progress toward the `high_level_goal`.

## Constraints
- Must ensure strict isolation between parallel implementation loops using Git worktrees.
- The Orchestrator is the only agent allowed to perform merges into the main branch.