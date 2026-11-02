# Contributing

These guidelines apply to everyone, whether you write the code yourself or
with a coding agent. Agents get the same rules, in more detail, from
[AGENTS.md](AGENTS.md).

## Architecture

[ARCHITECTURE.md](ARCHITECTURE.md) describes the crate graph and which way
its dependencies point, how config flows from the control plane to the data
plane, and what each stage of that path and of the request path decides. Read
it before you add or move code, and update it in the same pull request as any
change to those boundaries.

## Code comments

Keep comments short. Comment only what the code can't say on its own: the
*why* behind something non-obvious, such as invariants, locking and lifecycle
rules, protocol quirks, performance choices and workarounds for upstream bugs.

Don't write comments that:

- Narrate history ("originally", "used to", "after the refactor"). That
  belongs in commit messages and PR descriptions.
- Restate what the code plainly does.
- Argue for a design across several paragraphs.

Doc comments state a brief contract; one or two sentences is usually enough.
When you change code, update or delete the comments that describe it in the
same change.

## Commits

PRs are merged with a merge commit, not squashed, so your commits land on
`main` as you wrote them.

- Make each commit one logical change: the feature or fix, its tests, docs
  and unrelated small fixes go in separate commits when they make sense on
  their own.
- Every commit must build and pass tests, so `git bisect` keeps working.
- Each message explains what that commit changes and why. Use an imperative
  subject line under ~72 characters and wrap the body at 72.
- Address review feedback with `git commit --fixup <sha>`, then run
  `git rebase -i --autosquash` before merging. The final branch shouldn't
  contain "address review" or "fix typo" commits.

## Pull requests

The PR title and description become the merge commit message, so write them
for someone reading `git log`, not just for reviewers:

- Title: a short summary of the whole change.
- Description: the overall why and what, and anything that spans commits.
  Don't repeat each commit's message.
- Leave out checklists and review chatter.

To see one entry per merged PR, use `git log --first-parent main`.

## Policy on Generative AI & LLM-Assisted Contributions ##

### Ultimate Human Accountability ###

The human author submitting a contribution remains entirely and solely
accountable for its content, correctness, security, and runtime functionality.
Utilizing an LLM or AI tool does not shift, diminish, or share accountability
with the software tool, model provider, or AI platform.

- Architectural & Logic Mastery: The human contributor must thoroughly
understand and be able to explain the entirety of their submission.
- Maintainer review focuses entirely on the safety, logic, and quality of the
contribution, regardless of whether generative AI or LLMs were used to create
it.
- Tool-assisted submissions must still adhere to all contribution guidelines
set above in this document.

### Attribution and Co-Author Guidelines ###

Attributing AI tools, models, or assistant platforms (for example, via
`Co-authored-by:` commit message trailers or pull request descriptions) is
**optional**.

- **Optional Tool Attribution:** Contributors who wish to acknowledge AI tool
usage may optionally include a commit trailer or PR footnote.
- **No Legal Co-Authorship:** AI tools and LLMs cannot be designated as legal
copyright holders or primary authors, as accountability rests exclusively with
the human contributor.

### Maintainer Authority and Enforcement ###

Gateway maintainers reserve the right to:

- Reject or close pull requests or issues that exhibit evidence of hallucinated
content or lack of human oversight.
- Require additional explanation, architectural rationale, or smaller
surface-area iteration for complex AI-assisted contributions.
- Block or restrict contributors who repeatedly submit unvalidated AI-generated
pull requests.
