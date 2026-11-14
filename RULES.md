# Task delivery and human review

1. Complete the requested change and run the relevant checks defined in `AGENTS.md`.
   Report failed or unexecuted checks explicitly; do not present partial validation as complete.
2. Review the diff and stage only the task's changes for human review. Preserve unrelated
   changes and existing staging; use individual hunks when a file contains unrelated edits.
   Never stage generated artifacts, build caches, or files under `compatibility-tests/`.
3. Keep the handoff concise: what changed, validation results, pending work, and a suggested
   Conventional Commit message. Group related changes to avoid unnecessary commits.
4. Leave the changes staged. Do not commit, push, create tags, or publish unless explicitly
   requested by the user.
