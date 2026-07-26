# Hide Internal Codex Sessions

## Problem

Codex writes a rollout file for every top-level conversation, spawned worker,
nested worker, and permission guardian.  Agent Log currently treats every
rollout as an ordinary session.  Because workers inherit their parent's working
directory, the session browser groups them with the user's project.  Bulk sync,
archive summarization, background summary sweeps, and AI search consume the same
unfiltered collection.

## Design

Keep backend discovery complete, because live-buffer matching and explicit
session access need raw transcript records.  Filter the merged archive-wide
collection through a backend-specific visibility method:

- Backends expose whether a discovered record is an ordinary user session.
- The default implementation keeps records visible.
- The Codex implementation rejects any record whose `session_meta.source`
  identifies it as a subagent, including spawned workers and guardians.
- `agent-log--read-all-sessions` applies this policy together with the existing
  ignored-project filter.

This boundary covers browsing, opening the latest session, bulk synchronization,
archive summarization, background summary sweeps, and AI search.  Direct
`agent-log-open-session` and `agent-log-open-file` continue to resolve raw files,
so internal transcripts remain available when explicitly requested.

Maintenance code can explicitly include internal sessions while retaining the
existing ignored-project rules.  In particular, the redaction rebuild must
re-render non-ignored internal transcripts after clearing the rendered archive.
No child files, rendered Markdown, or cached summaries are deleted merely
because ordinary session views hide them.

## Verification

Add regression coverage that mixes a top-level Codex session, a spawned worker,
a guardian, and a Claude session.  The shared archive collection must retain the
top-level Codex and Claude records while excluding both internal Codex records.
Also verify that direct Codex discovery still returns all records.
Verify that redaction rebuild includes internal sessions and that exact-ID
lookup continues to resolve them.

Run the targeted regression test, the full ERT suite, byte compilation, and an
archive-backed check against the onboarding project.  The archive-backed check
must show that the ordinary collection contains no Codex subagents while raw
Codex discovery still finds them.
