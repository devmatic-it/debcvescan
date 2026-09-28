# Skill: raal_execute

## Description
Performs the atomic actions defined in the plan. It is the fourth stage of the RAAL loop.

## Input
- `action`: The specific tool call or command defined in the current step of the plan.

## Process
1. **Execute**: Call the requested tool/command via the system shell or specialized tools.
2. **Capture**: Capture all output (stdout, stderr) and exit codes.
3. **Log**: Pass the raw results to `raal_observe` for logging and subsequent reflection.

## Output
- The raw output from the tool execution (stdout/stderr) and the exit code.

## Constraints
- Must not attempt to "fix" errors; its sole responsibility is execution and reporting.
- Must strictly adhere to the atomic action defined in the plan.