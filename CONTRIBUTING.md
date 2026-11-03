# Contributing

These guidelines apply to everyone, whether you write the code yourself or
with a coding agent. Agents get the same rules, in more detail, from
[AGENTS.md](AGENTS.md).

## Architecture

[ARCHITECTURE.md](ARCHITECTURE.md) is the map of the code: how the code is
grouped, which way imports go and where new code goes. Read it before you add
or move code, and change it in the same pull request as any move.

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

## Rust conventions

- The workspace uses edition 2024. `rust-toolchain.toml` pins the toolchain
  and `rustfmt.toml` sets `max_width = 100`.
- The workspace lints forbid `unsafe_code` and warn on clippy `pedantic`.
  CI runs clippy with `-D warnings`. Generated proto modules are the only
  place where a blanket `allow` is acceptable.
- Every module starts with a `//!` doc that explains the module's role and
  its invariants. Several of those docs carry information that exists
  nowhere else, such as what `resolve` decides, the Store's promotion rules
  and why the drain barrier is drop-counted. Keep them accurate.
- A Rust file follows tokio's order: module doc, `use` groups, `mod`
  declarations, `pub use`, consts, then types, then free functions, then an
  inline `#[cfg(test)] mod tests`. The `use` groups are `std`, external
  crates, then `crate` and `super`, with a blank line between groups and
  alphabetical order within a group. rustfmt does not reorder between
  groups. The principal type comes first, and each type's inherent and
  trait `impl`s follow it directly.
- Unit tests live inline in the module that they cover. `tests/` holds
  integration tests only.

## Commits

Maintainers merge PRs with a merge commit rather than squashing them, so
your commits land on `main` as you wrote them.

- Make each commit one logical change: the feature or fix, its tests, docs
  and unrelated small fixes go in separate commits when they make sense on
  their own.
- Every commit must build and pass tests, so `git bisect` keeps working.
- Each message explains what that commit changes and why. Use an imperative
  subject line under ~72 characters and wrap the body at 72.
- Address review feedback with `git commit --fixup <sha>`, then run
  `git rebase -i --autosquash` before merging. The final branch shouldn't
  contain "address review" or "fix typo" commits.

## Sign your commits

Every commit needs a `Signed-off-by` trailer with your name and email.
The trailer states that you wrote the change or have the right to submit
it under the project's license, as the
[Developer Certificate of Origin](https://developercertificate.org)
describes. `git commit -s` adds the trailer. A check on each pull request
rejects commits without one.

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

The human who submits a contribution remains entirely and solely
accountable for its content, correctness, security and runtime behavior.
An LLM or AI tool does not shift, diminish or share that accountability
with the tool, the model provider or the AI platform.

- Architectural & Logic Mastery: The contributor must understand the whole
submission thoroughly and be able to explain it.
- Maintainers review the safety, logic and quality of every contribution,
whether or not the contributor used generative AI or LLMs to create it.
- A tool-assisted submission must still follow all the contribution
guidelines above.

### Attribution and Co-Author Guidelines ###

Attributing AI tools, models, or assistant platforms (for example, via
`Co-authored-by:` commit message trailers or pull request descriptions) is
**optional**.

- **Optional Tool Attribution:** A contributor who wants to acknowledge the
AI tools that they used may add a commit trailer or a PR footnote.
- **No Legal Co-Authorship:** Nobody may name an AI tool or LLM as a legal
copyright holder or a primary author, because accountability rests only
with the human contributor.

### Maintainer Authority and Enforcement ###

Gateway maintainers reserve the right to:

- Reject or close pull requests or issues that show signs of hallucinated
content or of a lack of human oversight.
- Require more explanation, a rationale for the design, or smaller
iterations for complex AI-assisted contributions.
- Block or restrict contributors who repeatedly submit unvalidated AI-generated
pull requests.
