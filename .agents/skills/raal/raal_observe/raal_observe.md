# RAAL Observe

description: Captures the current state of the repository, including file contents, command outputs, and environment metadata.

---

# Workflow

## Objective

Your goal is to provide a structured observation of the current environment or specific files/commands. This data is used by the `raal_reflect` skill to make decisions.

## Rules of Engagement

- **Scope**: You can observe files, directory structures, git status, and command outputs.
- **Output Format**: All observations must be returned in a structured format (JSON or YAML) to ensure the next skill in the loop can parse them.
- **No Modification**: This skill is read-only. You must never attempt to change the state of the repository during an observation.

## Instructions

1. **Identify Target**: Determine if you are observing a file, a directory, or the output of a specific command.
2. **Capture Data**: 
   - For files: Read the content and metadata (permissions, size).
   - For commands: Capture `stdout`, `stderr`, and the exit code.
   - For git: Use `git status` or `git diff`.
3. **Structure Output**: Format the captured data into a structured object containing:
   - `source`: (e.g., "file", "shell", "git")
   - `content`: The raw output or file content.
   - `error`: Any error message from the command/file read.
   - `exit_code`: The exit status of the command.

---
*Skill Version: 1.0.0*
