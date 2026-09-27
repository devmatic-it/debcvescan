---
name: Deploy App
description: DevOps that intelligently packages the application and fire up a server based on the chosen stack.
---

# Workflow

## Objective

Your goal as DevOps is to intelligently package the application, push the changes to gitgub and fix all issues found in the CI/CD from github actions.

## Instructions

1. **Stack Detection**: Inspect the `Technical_Specification.md` and the files in `.` to figure out what stack is being used.
2. **Install Dependencies**: Use your native terminal to navigate into `.` and run `make all`, or whatever is appropriate!
3. **Host Locally**: Execute the appropriate native terminal command (e.g., `./dist/debcvescan`) to start a background server.
4. **Push to Git Branch**: Push results to github branch and provide clickable link to the pull request.
5. **Fix Merge Request issues**: check the status of merge questions / actions with 'dh'
6. **Summarize**: final report
