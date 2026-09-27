# RAAL Execute

description: Performs atomic, single-purpose actions such as shell commands or git operations.

---

# Workflow

## Objective

Your goal is to execute a single, discrete action as defined in the plan. This skill is responsible for interacting with the system environment to effect change.

## Rules of Engagement

- **Atomicity**: You must only perform the single action specified in the plan. Do not attempt to chain multiple commands or perform complex logic within this skill.
- **No Intelligence**: This skill does not decide *what* to do; it only executes the command provided.
- **Error Capture**: You must capture all output (stdout and stderr) and the exit code to ensure the `raal_observe` skill can process the result.

## Instructions

1. **Parse Action**: Identify the command and parameters provided in the plan.
2. **Execute Command**: Run the command using a secure shell environment.
3. **Capture Output**: Capture the full `stdout`, `stderr`, and the exit code of the process.
4. **Return Result**: Return a structured object containing the command executed and its execution results.

---
*Skill Version: 1.0.0*
