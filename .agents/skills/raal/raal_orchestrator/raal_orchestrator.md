# RAAL Orchestrator

description: The master orchestrator that manages the full Reflective Agentic Loop (RAAL) to perform autonomous maintenance and development.

---

# Workflow

## Objective

Your goal is to autonomously identify, fix, and verify issues (bugs, dependency updates, or linting errors) using the RAAL loop. You must minimize human intervention by resolving trivial issues and only escalating when the "Circuit Breaker" is tripped.

## Prerequisites

- Must have access to `.agents/skills/` containing: `skill_observe`, `skill_reflect`, `skill_plan`, `skill_execute`, and `skill_verify`.
- Must have access to `knowledge_base/` for LTM (Long-Term Memory) patterns and failure history.
- Must have access to `references/raal_gh_reference.md` for GitHub CLI command syntax.

## The RAAL Loop

### 1. Observe
Use `skill_observe` to capture the current state of the repository (e.g., `git diff`, `go test` output, or `gosec` results).

### 2. Reflect
Use `skill_reflect` to analyze the observation:
- **Is this a known pattern?** (Check `knowledge_base/patterns.yaml`). If yes, skip to **Verify**.
- **Is this a known failure?** (Check `knowledge_base/failure_history.yaml`). If yes, **Escalate**.
- **Is this a new error?** Proceed to **Plan**.

### 3. Plan
Use `skill_plan` to generate a sequence of atomic actions (e.g., `git checkout`, `sed`, `go test`) based on the reflection.

### 4. Act
Execute the planned actions using `skill_execute`.

### 5. Verify (The Gate)
Execute `skill_verify` to ensure no regressions were introduced. This is a mandatory gate.

**If Verification Fails:**
- Increment your internal `retry_count`.
- If `retry_count < 3`, enter the **RECOVERING** state (return to **Plan**).
- If `retry_count >= 3`, enter the **ESCALATE** state.

## Escalation Protocol
When you reach the `ESCALATE` state, use `gh issue comment` to post a structured **Maintenance Briefing** containing:
- The error signature.
- The diagnostic context (the last `observation`).
- A summary of the failed recovery attempts.

---
*Skill Version: 1.0.0*
