# Using Reflective Agentic Loop (RAAL)

This document provides instructions for using the **Reflective Agentic Loop (RAAL)** architecture within your coding environment.
I verfied the solution with Antigravity and OpenCode.

## Overview

The RAAL is a cognitive framework designed to transform standard AI agents into autonomous maintenance specialists. Instead of simple command execution, the agent follows a structured loop: **Observe $\rightarrow$ Reflect $\rightarrow$ Plan $\rightarrow$ Act $\rightarrow$ Verify**.

## Architecture Structure

The RAAL implementation is modularized into specialized skills located in `.agents/skills/raal/`.

- **`raal_observe`**: Captures environment state (files, git, shell).
- **`raal_reflect`**: Analytyzes observations against the Long-Term Memory (LTM).
- **`raal_plan`**: Generates a sequence of atomic actions.
- **raal_execute**: Executes the planned commands.
- **`raal_verify`**: Validates changes via unit tests and security audits.

## How to Use RAAL with OpenCode

To use the RAAL architecture, you must instruct your agent (e.s., a specialized OpenCode agent) to adopt the RAAL loop as its operational mode.

### 1. Agent Initialization
When starting a session, provide the agent with the following instruction:

> "You are an autonomous maintenance agent operating under the RAAL (Reflective Agentic Loop) architecture. Your goal is to [INSERT TASK, e.g., fix a bug in pkg/analyzer]. You must follow the RAAL loop: Observe, Reflect (using `knowledge_base/patterns.yaml`), Plan, Execute, and Verify. If a verification fails, you must enter the RECOVERING state to attempt a fix. If you fail 3 times, escalate to me with a structured Maintenance Briefing."

### 2. The Knowledge Base (LTM)
The agent's intelligence is augmented by the `knowledge_base/` directory. You can guide the agent by updating these files:

- **`knowledge_base/patterns.yaml`**: Add entries here to teach the agent which code patterns are intentional (e.g., specific security bypasses or architectural styles) so it doesn't try to "fix" them.
- **`knowledge_base/failure_history.yaml`**: The agent will automatically append unresolvable errors here to prevent infinite loops in future sessions.

### 3. The Verification Gate
The agent is required to perform a "Verification" after every action. This includes:
- Running relevant unit tests (`go test`).
- Running security audits (`gosec`).
- Checking for regressions in adjacent modules.

### 4. Escalation & Human Intervention
If the agent cannot resolve an issue after 3 attempts, it will not simply stop. It will use `gh issue comment` to post a **Maintenance Briefing** containing:
- The error signature.
- The diagnostic context (the last observation).
- A summary of the failed recovery attempts.

## Summary for Maintainers
By using RAAL, you move from "fixing bugs" to **"reviewing verified fixes."** You only intervene when the agent provides an Escalation Report, significantly reducing your manual maintenance effort.
