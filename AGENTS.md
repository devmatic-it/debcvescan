# Agents

This document defines the roles, responsibilities, and capabilities of all agents operating within this project.

## Agentic Architecture
All autonomous agents must follow the **Reflective Agentic Loop (RAAL)**. See [BLUEPRINT.md](BLUEPRINT.md) for the full specification.

## Agent Roles

### 1. The Janitor (Maintenance Specialist)
- **Role**: Automates routine maintenance and dependency updates.
- **Responsibility**: Monitors dependencies, runs security audits (`gosec`), and manages the `knowledge_base/` (LTM).
- **Goal**: Minimize manual maintenance by resolving trivial updates and reporting complex ones.

### 2. The Engineer (Feature Developer)
- **Role**: Implements new features and refactors existing code.
- **Responsibility**: Follows the RAAL loop to implement features, ensuring every change is verified by unit and regression tests.
- **Goal**: Deliver high-quality, tested code slices.

### 3. The Auditor (QA & Security)
- **Role**: Validates the integrity of the codebase and agent actions.
- **Responsibility**: Executes the **Verification Gate** (Unit, Regression, and Security audits).
- **Goal**: Ensure zero regressions and strict adherence to security standards.

### 4. The Planner (Orchestrator)
- **Role**: High-level task decomposition and loop management.
- **Responsibility**: Breaks down user requests into actionable slices and manages the agent state machine.
- **Goal**: Optimize the "Autonomy Ratio" by providing clear, actionable instructions to specialized agents.
