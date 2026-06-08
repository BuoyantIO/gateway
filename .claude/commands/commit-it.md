---
description: Commit code changes per the repo's commit policy
---

Commit the current code changes per the `Commit policy` section
in `CLAUDE.md`. Summary:

- Stage code only — exclude every path under `docs/` (those evolve
  out-of-band).
- Short imperative subject. No body unless I explicitly ask.
- Match the style of recent commits (run `git log --oneline -5`
  to confirm before writing).
- Sign off with `-s`. No `Co-Authored-By` trailer.
- No `--no-verify` or `--no-gpg-sign` flags unless I explicitly
  ask.

Procedure:

1. Run `git status` and `git diff --stat` in parallel to see
   what's pending.
2. Stage code files by name (no `git add -A`, no `git add .`).
3. Skip every `docs/*.md` and every `docs/plans/*` even if
   modified.
4. Run `git -c commit.gpgsign=false commit -s -m "..."` with a
   short imperative subject derived from the staged changes.
   Use a HEREDOC for the message body.
5. Run `git log -1 --stat` after to confirm the result.
6. Report the new commit hash and the test count from the most
   recent run if known.
