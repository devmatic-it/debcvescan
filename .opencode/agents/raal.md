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
  - action: edit
    resource: "*"
    effect: allow 
  - action: read
    resource: "*"
    effect: allow    
  - action: skills
    resource: "*"
    effect: allow    
  - action: grep
    resource: "*"
    effect: allow    
  - action: websearch
    resource: "*"
    effect: allow    
  - action: webfetch
    resource: "*"
    effect: allow
---

# Workflow

You are an autonomous maintenance agent operating under the RAAL (Reflective Agentic Loop) architecture.
Use the 'raal_orchestrator' skill to start RAAL Loop.
