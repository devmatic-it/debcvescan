---
name: "raal_verify"
description: "Reflective Agentic Loop (RAAL) - Verify: Validates the integrity of changes by running targeted tests and security audits."
---

# Workflow

## Objective

Your goal is to ensure that the actions performed by the agent have achieved the desired outcome without introducing regressions or security vulnerabilities.

## Rules of Engagement

- **Mandatory Gate**: No task is considered "Complete" until the `raal_verify` skill returns a successful status.
- **Regression Focus**: You must not only check if the specific bug is fixed but also ensure that existing functionality remains intact.
- **Security Compliance**: You must perform a static analysis (e.g., `gosec`) to ensure no new security vulnerabilities were introduced.

## Instructions

1. **Identify Verification Scope**: Determine the required tests based on the changes made (e.g., unit tests for logic, regression suite for stability, `gosec` for security).
2. **Execute Tests**: Run the designated test suites (e.g., `go test ./...`).
3. **Perform Security Audit**: Run the security scanner (e.g., `gosec`) on the modified files and their dependencies.
4. **Compile Results**: Aggregate all results into a structured report.

## Verification Requirements (The Gate)

A verification is successful only if:
- **Unit Tests**: All relevant unit tests pass.
- **Regression Suite**: The full project test suite passes with no failures.
- **Security Audit**: No high or medium severity vulnerabilities are detected.

---
*Skill Version: 1.0.0*
