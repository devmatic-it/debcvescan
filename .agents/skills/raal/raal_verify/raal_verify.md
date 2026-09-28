# Skill: raal_verify

## Description
A mandatory validation stage that checks not only the immediate fix but also ensures no regressions were introduced in adjacent modules. It is the final stage of the RAAL loop.

## Input
- `target_module`: The module/file modified by the current implementation loop.
- `test_suite`: The set of tests (Unit, Regression, Security) to be executed.

## Process
1. **Unit Verification**: Execute tests specifically related to the changes in `target_module`.
2. **Regression Verification**: Execute the full relevant test suite for the entire project/package to ensure no side effects.
3. **Security Audit**: Run static analysis tools (e.g., `gosec`) on the modified code and its dependencies.
4. **Decision**: 
    - If all tests pass $\rightarrow$ Return `SUCCESS`.
    - If any test fails $\rightarrow$ Return `FAILURE` with error details.

## Output
- A verification report containing:
    - `status`: SUCCESS or FAILURE.
    - `details`: Summary of test results and security findings.

## Constraints
- Must be executed in a clean environment (e.g., the dedicated Git worktree) to ensure results are not polluted by local state.
- A task is only considered `COMPLETED` if the status is `SUCCESS`.