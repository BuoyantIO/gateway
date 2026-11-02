# AGENTS.md

The prose, comment, logging and commit rules below are shared with the
Kinference repository, whose `AGENTS.md` is the canonical copy. Change
them there first.

## Architecture

`ARCHITECTURE.md` is the map of the code: how the code is grouped, which
way imports go and where new code goes. Read it before you add or move
code, and change it in the same pull request as any move.

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

## Logging

gateway-cp and gatewayd log through `tracing`. Both default to `info`,
so the operator reads every INFO, WARN and ERROR line in production. Log
volume should grow with events, not with traffic.

### Levels

- ERROR: something needs fixing, and the gateway can't recover on its
  own.
- WARN: the gateway is degraded or misconfigured. Log a WARN line once
  per cause, never once per request. Latch the line, or let a metric
  count the repeats.
- INFO: lifecycle and state changes. Examples are startup, readiness,
  shutdown, a data plane connecting or disconnecting, a Gateway being
  provisioned, and a leadership change. Each event logs one INFO line.
  The request path never logs at INFO.
- DEBUG: per-request decisions.
- TRACE: per-event and per-frame detail, such as each body frame or
  each watch event.

### Don't log

- An event that a metric already counts, unless the line adds context that
  the metric can't hold.
- An event that another line already logs. Log the event once, where the
  state changes.
- A task exiting on cancel, or a config value that the operator can read
  in the config file.
- A path that can't happen. Use `debug_assert!` or `unreachable!` instead.

### Messages and fields

- A message is one short lowercase phrase that says what happened:
  "admin server listening", "config applied".
- Don't start a message with a module prefix. The subscriber already
  prints the target.
- Put values in fields, not in the message text.
- Don't explain the code in a message. When the operator has to change a
  setting, name the setting.
- No caps for emphasis and no em dashes.
- Use the same field names in every crate: `namespace`, `name`, `bind`,
  `listener`, `route`, `backend`, `error`.
- Record an error as `error = &err as &dyn std::error::Error`. The
  subscriber then prints the error's sources too.

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
