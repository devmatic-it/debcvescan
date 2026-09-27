---
name: "raal_orchestrator"
description: "The master orchestrator that manages the full Reflective Agentic Loop (RAAL) to perform autonomous maintenance and development."
---

# Workflow

## Objective
Your goal is to autonomously identify, fix, and verify issues (bugs, dependency updates, or linting errors) using the RAAL loop. You must minimize human intervention by resolving trivial issues and only escalating when the "Circuit Breaker" is tripped.

## Prerequisites
- Must have access to `.agents/skills/` containing: `raal_observe`, `raal_reflect`, `raal_plan`, `raal_execute`, and `raal_verify`.
- Must have access to `knowledge_base/` for LTM (Long-Term Memory) patterns and failure history.
- Must have access to `references/raal_gh_reference.md` for GitHub CLI command syntax.

## The RAAL Loop
### 1. Observe
Use `raal_observe` to capture the current state of the repository (e.g., `git diff`, `go test` output, or `gosec` results).

### 2. Reflect
Use `raal_reflect` to analyze the observation:
- **Is this a known pattern?** (Check `knowledge_base/patterns.yaml`). If yes, proceed to **Verify**.
- **Is this a known failure?** (Check `knowledge_base/failure_history.yaml`). If yes, use the historical recommendation to inform your **Plan**.
- **Is this a new error?** Proceed to **Plan**.

### 3. Plan
Use `raal_plan` to generate a sequence of atomic actions (e.g., `git checkout`, `sed`, `go test`) based on the reflection and historical context.
- **Sub-task Management**: If a task is decomposed into multiple sub-tasks, treat each sub-task as an independent RAAL loop. A failure in one sub-task triggers the `ESCALATING` state for that specific sub-task only.

### 4. Act
Execute the planned actions using `raal_execute`.

### 5. Verify (The Gate)
Execute `raal_verify` to ensure no regressions were introduced. This is a mandatory gate.

**If Verification Fails:**
- Increment your internal `retry_count`.
- If `retry_count < 3`, enter the **RECOVERING** state (return to **Plan**).
- If `retry_count >= 3`, enter the **ESCALATING** state.

## Escalation Protocol
When you reach the **ESCALATING** state, use `gh issue comment` to post a structured **Maintenance Briefing** containing:
- The sub-task ID/name.
- The error signature.
- The diagnostic context (the last `observation`).
- A summary of the failed recovery attempts.

After posting, enter the **SUSPENDED** state and wait for human feedback/resumption.

---
*Skill Version: 1.2.1*
