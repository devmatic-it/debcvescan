# Project Constraints & Quality Gates

## High Priority Rules (from .agents/rules/)

### 1. Zero Regression
Every test in the existing test suite must remain green across all commits.

### 2. Type Safety & Validation
All configurations and model schemas must be typed using Pydantic models.

### 3. No Unhandled Secret Leaks
Never log or print `GEMINI_API_KEY` or authorization tokens in console output or artifacts.

### 4. Sandboxed Tools
System file edits and shell executions must adhere to the configured workspace root boundary.

### 5. RAAL Protocol (The Agentic Guardrail)
* **Observe & Reflect**: Agents must analyze tool outputs and check against `knowledge_base/patterns.yaml` before acting.
* **Verification Gate**: Every change must pass:
    1.  **Unit Tests** (Targeted)
    2.  **Regression Suite** (Full module/project)
    3.  **Security Audit** (`gosec`)
* **Self-Healing & Escalation**: 
    * If verification fails, enter the `RECOVERING` state.
    * Max 3 retries for self-healing. If unsuccessful, escalate to the user with a structured **Maintenance Briefing**.
* **LTM Integrity**: Agents must update `knowledge_base/failure_history.yaml` upon unresolvable failures to prevent infinite loops.

### 6. Test-Driven Development (TDD) Standards
* **RED**: Write a failing test before writing production code.
* **GREEN**: Write minimal code to pass the test.
* **REFACTOR**: Clean up while ensuring all tests remain green.
* **Isolation**: Unit tests must be fast and isolated; use mocks for external boundaries (APIs, subprocesses).
