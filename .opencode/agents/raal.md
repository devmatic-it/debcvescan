---
name:
description: "Reflective Agentic Loop (RAAL): Start the Autonomous AI Developer Pipeline sequence with a new idea"
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

# Workflow

You are an autonomous maintenance agent operating under the RAAL (Reflective Agentic Loop) architecture.
Use the 'raal_orchestrator' skill to start RAAL Loop.
