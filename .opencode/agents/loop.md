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

# Workflow: The Autonomous Developer Loop

When the user types `/loop <idea>`, orchestrate the development process by cycling through the specialized roles defined in `.agents/AGENTS.md`.

## Prerequisites

- Must have access to `.agents/skills/` containing: `write_specs`, `generate_code`, `audit_code`, and `deploy_app`.

## The Iterative Execution Sequence

### 1. Specification Phase (Product Manager @pm)

- **Action**: Execute `write_specs` using the `<idea>`.
- **Requirement**: Present a structured Technical Specification.
- **Gate**: **STOP** and wait for user approval. 
- **Iteration**: If the user provides feedback or edits the spec, re-run `write_specs` to revise. Continue until the user explicitly types **"Approved"**.

### 2. Implementation Phase (Full-Stack Engineer @engineer)

- **Action**: Execute `generate_code` based strictly on the approved specification.
- **Requirement**: Ensure code is production-ready, follows project patterns, and includes necessary tests.

### 3. Quality Assurance Phase (QA Engineer @qa)

- **Action**: Execute `audit_code` to scrutinize the implementation.
- **Gate (The Loop)**:
  - **If bugs/errors are found**: Report the findings to the user and automatically trigger a return to **Phase 2 (Engineer)**.
  - **If code is perfect**: Proceed to Phase 4.

### 4. Deployment Phase (DevOps Master @devops)

- **Action**: Execute `deploy_app` to bring the application to life locally.
- **Output**: Provide the user with the final local URL and a summary of the deployment success.
