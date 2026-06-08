---
description: Plan and implement an issue from docs/issues.md
argument-hint: <issue-number>
---

Run the issue workflow for issue #$ARGUMENTS from `docs/issues.md`.

## Phase 1 — read

1. Find the section in `docs/issues.md` whose heading starts with
   `## $ARGUMENTS.`. That's the lean summary and the source of truth for
   what's in scope.
2. Cross-reference the matching section in
   `docs/production-readiness.md` (heading starts with `### $ARGUMENTS.`)
   for the detailed scope, acceptance criteria, and any prior-art
   notes.
3. If item #$ARGUMENTS is already marked DONE (heading contains `— DONE`
   or strikethrough `~~`), stop and report — there's nothing to
   do.

## Phase 2 — plan

4. Call `EnterPlanMode`.
5. Explore the codebase as needed (Explore subagents for breadth,
   direct Read for targeted lookups).
6. Write the plan to the plan file the harness gives you. Cover:
   context, recommended approach, critical files, tests,
   verification.
7. Call `ExitPlanMode` for approval. Do NOT proceed past this
   point without explicit user approval.

## Phase 3 — implement

8. Make the edits per the plan.
9. For S-sized issues, skip `TaskCreate`. For L-sized, use it
   to track multi-step parallel work.
10. Run, in this order: `cargo fmt`, then
    `cargo clippy --workspace --all-targets -- -D warnings`,
    then `cargo test --workspace`. All three must be clean.

## Phase 4 — sync docs

11. Update item #$ARGUMENTS in all three doc files:
    - `docs/issues.md` (lean blurb, mark DONE)
    - `docs/production-readiness.md` (detailed writeup,
      mark DONE, list tests added)
    - `docs/bcloud-readiness.md` (bcloud-grounded summary,
      mark DONE; if the issue isn't bcloud-relevant, leave
      the section unchanged and note that in your report)
12. Match the style of the existing DONE entries for #3, #4,
    #5 in those files.

## Phase 5 — stop and report

13. **Do not commit.** Report:
    - one-paragraph summary of what landed
    - test count before/after
    - any deviations from the approved plan
    - any follow-up items discovered
14. Wait for the user to invoke `/commit-it`.
