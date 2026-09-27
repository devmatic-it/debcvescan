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
- **Role**: Provides validation results for the Verification Gate.
- **Responsibility**: Executes Unit, Regression, and Security audits as requested by the Orchestrator.
- **Goal**: Ensure zero regressions and strict adherence to security standards.

### 4. The Planner (Orchestrator)
- **Role**: Implements the `raal_orchestrator` skill.
- **Responsibility**: Manages the RAAL state machine and handles task decomposition into independent sub-tasks.
- **Goal**: Optimize the "Autonomy Ratio" by managing task lifecycles from assignment to completion or suspension.
