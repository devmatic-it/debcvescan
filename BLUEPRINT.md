# Technical Specification: Reflective Agentic Loop (RAAL) Architecture

## 1. Overview
The **Reflective Agentic Loop (RAAL)** is a high-order control architecture designed to transition AI agents from "Reactive Command Execution" (current state) to "Autonomous Goal Achievement." Unlike standard ReAct patterns, RAAL introduces a cognitive layer that analyzes tool failures and environmental constraints before attempting corrective actions.

## 2. Core Architecture Components

### 2.1 The Cognitive Loop (The "Brain")
The loop is composed of five distinct, interconnected stages:

1.  **Observe**: Ingests raw tool outputs (stdout/stderr), file contents, and environment metadata.
2.  **Reflect**: A dedicated reasoning step where the agent evaluates the *quality* and *implications* of observations. It asks: *"Why did this fail?"* or *"Is this output consistent with my current goal?"*
3.  **Learn**: A knowledge acquisition step where the agent identifies new patterns, constraints, or failure modes and updates the Long-Term Memory (`knowledge_base/`) to prevent future errors.
4.  **Plan**: Generates a multi-step strategy based on the reflection, including "contingency branches" for predicted failures.
5.  **Execute**: Performs the atomic actions (tool calls) defined in the plan.
6.  **Verify (Regression-Focused)**: A mandatory validation stage that checks not only the immediate fix but also ensures no regressions were introduced in adjacent modules.

### 2.2 Memory Management (The "Context")
To prevent "context drift" and repetitive errors, the architecture utilizes a dual-layer memory system:

*   **Short-Term Memory (STM) - `.agents/memory/sessions/STATE.md`**: A high-frequency, volatile log of the current session's observations and tool outputs. To prevent context drift in long-running sessions, agents must summarize previous logs into a session summary once the log exceeds context limits. It provides immediate context for the next loop iteration.
*   **Long-Term Memory (LTM) - `.agents/memory/knowledge_base/`**: A persistent repository of environmental constraints, domain-specific rules (e.g., "Debian fallback logic"), and historical patterns of success/failure.

### 2.3 The Verification Gate (The "Guardrail")
A hard requirement for loop completion. A task is not considered "Done" until:
*   **Unit Verification**: The specific test related to the change passes.
*   **Regression Verification**: The full suite of relevant tests passes.
*   **Security Audit**: Static analysis (e.g., `gosec`) returns zero high-severity issues.

### 2.4 Parallel Execution & Isolation (The "Sandbox")
To maximize autonomy and minimize risk, the architecture supports parallel implementation loops:

*   **Engineer Isolation**: Every Engineer implementation loop must operate within a dedicated Git worktree. This provides a sandbox for experimentation and prevents unverified code from polluting the main branch.
*   **Orchestrator Parallelism**: The Orchestrator can decompose a single high-level goal into multiple independent sub-tasks, spawning parallel implementation loops (via sub-agents) for each.
*   **Integration Protocol**: Once all parallel implementation loops reach the `COMPLETED` state, the Orchestrator performs a sequential merge of all worktrees into the main branch and executes a final global regression check, including a specialized semantic integration pass to detect logic conflicts in shared modules.

## 3. State Machine Definition

| State | Trigger | Transition Condition |
| :--- | :--- | :--- |
| **IDLE** | User Input | Move to `OBSERVE` upon task assignment. |
| **THINKING** | Observation received | Move to `PLAN` after reflection is complete. |
| **ACTING** | Plan generated | Move to `OBSERVE` after tool execution. |
| **VERIFYING** | Action successful | Move to `OBSERVE` (Regression Check). |
| **CONFLICT_RESOLUTION** | Merge conflict detected | Move to `THINKING` (Resolve Conflict) or `ESCALATING`. |
| **RECOVERING** | Action failed (retry_count < threshold) | Move to `THINKING` (Root Cause Analysis). |
| **ESCALATING** | Retry limit reached or critical error | Move to `SUSPENDED` (Waiting for Human). |
| **COMPLETED** | All gates passed | Move to `IDLE` / Report Generation. |
| **SUSPENDED** | Human intervention required | Move to `IDLE` upon human feedback. |

## 4. Error Handling & Self-Correction Logic
When a tool returns an error, the agent must not simply retry. It must follow this protocol:
1.  **Error Classification**: Is the error `Syntax`, `Environment`, `Permission`, or `Logic`?
2.  **Constraint Check**: Does the error match a known constraint in LTM?
3.  **Strategy Pivot**: If `Environment`, adjust the fallback logic. If `Logic`, re-evaluate the code structure.

## 5. Success Metrics (KPIs)
*   **Autonomy Ratio**: $\frac{\text{Successful Loops}}{\text{Total Loops}}$
*   **Regression Rate**: Number of successful fixes that break existing functionality.
*   **Reflection Efficiency**: Reduction in redundant tool calls per task completion.

---
*Document Version: 1.4.0 (Parallel/Worktree + Conflict Resolution Update)*
*Status: Finalized Specification*