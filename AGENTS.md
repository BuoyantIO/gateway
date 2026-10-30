# AGENTS.md

## What this is

A Kubernetes Gateway API implementation in Rust: a control plane
(`gateway-cp`) that watches `Gateway`/`HTTPRoute` resources and
provisions the data plane (`gatewayd`) that serves the traffic.
Config flows one way, CP to DP, over a streaming gRPC channel;
nothing in the data plane reads Kubernetes.

## Architecture

`ARCHITECTURE.md` is the high-level map of the codebase. Read it before you add
or move code, and change it in the same pull request as any move.

## Prose style for all text, including commit messages and PR descriptions

- Write one main claim per sentence.
- Put reasons and asides in their own sentences instead of inserting them
  mid-sentence with dashes, parentheses, or relative clauses. Don't use
  em-dashes.
- Every pronoun, "this/that/these," or summarizing noun ("the two halves,"
  "both," "this approach") must have a single, explicit antecedent in the
  immediately preceding sentence. If there's any doubt, repeat the noun.
- Don't end paragraphs with summary or wrap-up sentences. If a conclusion
  depends on an assumption, state the assumption.
- Use active voice and name the actor: the client, the controller,
  gatewayd. Inanimate subjects are fine with project terms such as
  "an HTTPRoute attaches to a listener".
- Keep the relativizer in object relative clauses: "the hostname that
  the client sent", not "the hostname the client sent".
- Use the project's own terms, including the Gateway API's. Don't swap
  in metaphors such as "plugs into" for "attaches to".
- Name the concrete thing: "hostname", "listener name" or "section
  name", not just "name".
- Avoid noun stacks: "each endpoint's in-flight request count", not
  "endpoint in-flight request counter value".
- Keep words that depend on each other close: a verb near its subject
  and its complements, a modifier near the word it modifies. Move a
  long relative clause to the end of the sentence, or turn it into a
  leading condition: "when a route's bind and listener are both
  registered, the Store promotes the route to active". Split a sentence
  whose one subject governs several far-apart verbs.

## Code comments and documentation

Comments in this repo are kept short on purpose. Target an overall Rust comment
ratio under 15%, with no module above ~25%.

### Write a comment only when it says something the code can't

Keep (and keep tight) comments that explain *why* something non-obvious is
done:

- Invariants and contracts a caller must respect.
- Concurrency and locking rules, lifecycle and leak bounds.
- Protocol quirks and wire formats
- Performance-sensitive choices and workarounds for upstream bugs.
- Units and ranges when the type doesn't make them clear.

When in doubt, leave the comment out.

### Don't write

- **History.** No "originally", "pre-refactor", "used to", "we changed X to
  Y", "now that...", bug stories or references to removed code. That goes in
  commit messages and PR descriptions.
- **Restatements.** No comment that repeats what the next line or the
  signature already says.
- **Essays.** No multi-paragraph docs arguing for a design on small types or
  functions. Don't explain why something lives in one module instead of
  another.
- **Cross-reference lists to keep in sync** ("used in three places, keep
  these in sync..."). Name the callers in one sentence if it matters.
- **Notes about the current task or change** ("added for the new X",
  "fix for the issue above", "TODO from review").

### Style

- Module docs (`//!`): one or two sentences of purpose, plus real invariants.
- Item docs (`///`): a brief contract. One line is usually enough; fields
  usually need nothing.
- Inline (`//`): only for the non-obvious why.
- Test docs: state what the test checks in one line, not why it was written.
- Plain sentences. No ad hoc bold/caps emphasis.

### Keep comments correct

When changing code, update or delete the comments that describe it in the
same change: renamed or removed items, moved logic, changed defaults. Never
leave a doc comment attached to the wrong item, and re-read edited comments
so they still parse as sentences.

## Commits and pull requests

PRs are merged with a merge commit, not squashed, so each commit lands on
`main` as written and the PR description becomes the merge commit message.

### Commits

- One logical change per commit: the feature or fix, its tests, docs and
  unrelated small fixes go in separate commits when they make sense on their
  own.
- Every commit builds and passes tests, so `git bisect` works.
- The message says what the commit changes and why, for that commit only.
  Subject line in the imperative, under ~72 characters; wrap the body at 72.
- Address review feedback with `git commit --fixup <sha>` and fold it in with
  `git rebase -i --autosquash` before merging. No "address review" or "fix
  typo" commits on the final branch.

### PR descriptions

The description is the merge commit message, so write it for `git log`
readers, not just reviewers:

- Title: a short summary of the whole change.
- Body: the overall why and what, and anything that spans commits. Don't
  repeat each commit's message.
- No checklists nor review chatter

## Commands

`just` drives everything (`just --list`). `protoc`
(`protobuf-compiler`) must be installed: two crates compile protos in
`build.rs`.

```sh
just lint         # cargo fmt --check + clippy --workspace --all-targets -D warnings
just lint-chart   # helm lint charts/gateway
just test-unit    # cargo test --workspace
just up           # build images, create the gateway-e2e kind cluster, install the chart
just test-e2e     # cargo test -p gateway-e2e -- --ignored
just down         # delete the cluster and the cloud-provider-kind container
just ci           # up + test-e2e + down
```

Single unit test:

```sh
cargo test -p gateway-cp diff::tests::value_change_yields_upsert
```

Single e2e test (needs `just up` first; every e2e test is
`#[ignore]`d so `cargo test --workspace` skips them):

```sh
cargo test -p gateway-e2e --test e2e -- --ignored routing::exact_beats_prefix
```

Note `e2e/README.md` is stale on two points: the runner is
`just test-e2e` (not `just test`), and the suite is one test binary
named `e2e` (not one per file), so `--test e2e` plus a
`module::test_name` filter is how you narrow it.

## Conventions

- Edition 2024, toolchain pinned by `rust-toolchain.toml`,
  `max_width = 100`.
- Workspace lints: `unsafe_code` is forbidden, clippy `pedantic` is
  warned, and CI runs clippy with `-D warnings`. Generated proto
  modules are the only place blanket `allow`s are acceptable.
- Prefer a module-level `//!` doc that explains the module's role and
  its invariants. This codebase leans heavily on those; several
  ("what `resolve` decides", the Store's promotion rules, why the
  drain barrier is drop-counted) carry information found nowhere
  else. Keep them accurate.
- Rust file order, matching tokio's style: module doc, `use` groups
  (`std`, external crates, `crate`/`super`, blank line between,
  alphabetical within a group; rustfmt does not reorder between
  groups), `mod` declarations, `pub use`, consts, then types with the
  principal type first and each type's `impl`s (inherent and trait)
  immediately below it, then free functions, then an inline
  `#[cfg(test)] mod tests`.
- Unit tests live inline in the module they cover; `tests/` holds
  integration tests only.
