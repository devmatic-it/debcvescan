# RAAL Command Reference for GitHub CLI (gh)

This document defines the exact `gh` command sequences used by the RAAL Agent to interact with GitHub.

## 1. Observation Commands (Observe)
Used to gather context from the repository.

| Action | `gh` Command Template | Purpose |
| :--- | :--- | :--- |
| **Get Issue Context** | `gh issue view <issue_number> --json body,title` | Ingest the problem description. |
| **Get PR Context** | `gh pr view <pr_number> --json body,headRefName` | Ingest the proposed changes. |
| **List Issues** | `gh issue list --labels "bug,maintenance" --json number` | Identify pending tasks. |

## 2. Action Commands (Act)
Used to execute changes in the repository.

| Action | `gh` Command Template | Purpose |
| :--- | :--- | :--- |
| **Create Branch** | `git checkout -b raal/fix-<id>` | Isolate the work. |
| **Submit Fix** | `gh pr create --title "RAAL: <summary>" --body "<brief>"` | Submit the verified fix. |
| **Update Fix** | `gh pr update --head raal/fix-<id>` | Push a corrected version after recovery. |

## 3. Escalation Commands (Escalate)
Used when the agent reaches a terminal failure state or requires human intervention.

| Action | `gh` Command Template | Purpose |
| :--- | :--- | :--- |
| **Report Failure** | `gh issue comment <id> --body "<Maintenance Briefing>"` | Post the RCA and error logs to the issue. |
| **Close Task** | `gh issue close <id> --comment "RAAL: Unresolvable error."` | Close the task if it cannot be fixed. |

## 4. Verification Commands (Verify)
Used to confirm the success of an action.

| Action | `gh` Command Template | Purpose |
| :--- | :--- | :--- |
| **Check CI Status** | `gh run list --workflow="RAAL Janitor" --status=completed` | Verify the GitHub Action completed. |
| **Check PR Status** | `gh pr check <pr_number>` | Verify the status of the CI checks on a PR. |
