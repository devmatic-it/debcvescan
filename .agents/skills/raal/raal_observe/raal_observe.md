# Skill: raal_observe

## Description
Ingests raw tool outputs (stdout/stderr), file contents, and environment metadata. It is the first stage of the RAAL loop.

## Input
- `tool_output`: The raw string output from a tool execution.
- `environment_metadata`: Contextual information about the current environment (e.g., working directory, OS).

## Process
1. **Format**: Convert raw output into a structured format (timestamp, tool name, status).
2. **Log**: Append the formatted output to `.agents/memory/sessions/STATE.md`.
3. **Check Context**: If `STATE.md` exceeds the token threshold, trigger a summarization routine before appending.

## Output
- Returns the updated state of `STATE.md` and a confirmation of successful logging.

## Constraints
- Must never overwrite `STATE.md`; always append to maintain history within the current session.
- Must handle empty tool outputs gracefully.