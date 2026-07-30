# Agent / Agent Log Integration — Agent Log Side

## Problem

Agent Log maps live terminal buffers to transcripts with heuristics that
predate the `agent` package's current design.  Two are dead in every
configuration: reading `claude-code-extras--status-data` (the package was
renamed to `agent`, which stores the data in `agent-claude--status-data`),
and reading statusline files keyed by sanitized buffer name (`agent` now keys
them by a per-process UUID hash).  Resuming a session from a rendered log
calls `claude-code.el`/`codex.el` directly, so the new process bypasses
`agent`'s account handling, lifecycle registration, and teardown, and
resuming a session that is already live starts a duplicate process.  Browsing
gives no indication that a session is currently running.

`agent` now maintains an authoritative live-identity contract (see
`agent/docs/superpowers/specs/2026-07-29-agent-log-integration-design.md`):
`agent-session-id` is populated as soon as each backend reports its native
ID, and the public surface is `agent-session`, `agent-session-id`,
`agent-session-buffers`, `agent-session-display-state`, and the
`agent-session-id-functions` hook.  Agent Log's backend keys already equal
`agent`'s backend symbols.

## Design: optional bridge

A new file, `agent-log-agent.el`, ships with Agent Log and holds every
reference to the `agent` package.  `agent-log.el` arranges
`(with-eval-after-load 'agent (require 'agent-log-agent))`, so loading Agent
Log alone never touches `agent`, and loading both packages in either order
activates the bridge.  The bridge uses only `agent`'s public API; the rest of
Agent Log never mentions `agent`.

The bridge is additive `cl-defmethod :around` overrides on existing generics
plus one small core extension point, so removing the file restores today's
standalone behavior exactly:

1. **Buffer → transcript** (`agent-log--current-buffer-session-file`
   `:around`, base `agent-log-backend`): when the current buffer is an
   `agent` session whose struct carries a native ID and a matching backend
   key, resolve the transcript with `agent-log--find-session-file` (a
   filesystem lookup for both backends, no catalog read); fall back to
   `cl-call-next-method` when the ID is not yet known or the file is not on
   disk yet.  The existing backend heuristics remain untouched as the
   standalone path.

2. **Live session IDs** (`agent-log--active-session-ids` `:around`): with
   `agent` loaded, return the IDs recorded on `agent`'s session structs for
   that backend key.  This is authoritative (agent tracks every live backend
   buffer), replaces the dead Claude heuristic, and avoids the Codex catalog
   read the standalone heuristic performs.  The standalone methods remain for
   use without `agent`.

3. **Live state in the browser**: new core variable
   `agent-log-live-session-info-function`, nil by default.  When non-nil it
   is called with BACKEND-KEY and SESSION-ID and returns a plist
   `(:buffer BUFFER :state STATE)` for live sessions, else nil.  The bridge
   installs an implementation backed by `agent-session-buffers`,
   `agent-session`, and `agent-session-display-state`.
   `agent-log--build-candidates` consults it and annotates live rows with
   their state (`busy`, `waiting`, `background-waiting`, `unknown`) using a
   distinct face.  Selecting a session in the browser still opens the
   rendered log — that action is preserved unchanged.

4. **Duplicate-safe, agent-routed resume** (`agent-log--resume-session`
   `:around`): first consult the live info; when the session is already
   running, switch to its buffer and say so instead of resuming a duplicate.
   Otherwise, when the backend key names a registered `agent` backend,
   construct an `agent-session` (backend, project directory from the same
   sources the direct path uses, account left nil so
   `agent-account-resolve` fills it) and call
   `agent-start-session … :resume-id ID`, preserving account handling,
   lifecycle registration, and teardown.  For app-server Codex resumes the
   bridge still pre-registers the exact transcript path
   (`agent-log-codex--exact-resume-paths` and its advice), which continues to
   apply because `codex-start-session :resume-id` reaches
   `codex--app-server-begin-resume-session-id`.  Without `agent`, the
   existing direct `claude-code.el`/`codex.el` methods run unchanged.

## Dead-heuristic cleanup

The two configuration-independent dead paths — the
`claude-code-extras--status-data` read and the sanitized-buffer-name status
file read — are deleted along with their tests, because no installed package
produces what they consume.  The live fallbacks that still work without
`agent` (visible-text transcript matching, newest project JSONL,
`history.jsonl` project match, Codex recorded state / resumed process
command / cwd-and-launch-time matching) are kept.

## Non-goals

No merged backend registries; no new slots on either backend record; no
second catalog or archive index anywhere; Agent Log keeps listing exactly
what each tool's native resume interface lists.  Browsing history stays lazy:
nothing in the bridge runs at load or menu-construction time.

## Verification

- ERT (with a stubbed `agent` feature): current-buffer resolution prefers the
  agent-reported ID and falls back when it is nil; active-session-ids uses
  agent's answer; browser candidates carry live-state annotations; resuming a
  live session switches to its buffer; resuming an inactive session calls
  `agent-start-session` with the right backend, directory, and resume ID;
  everything still works with the bridge absent.
- Full suite and byte compilation in this repository stay clean (the
  Makefile gains the `agent` sibling on the compile load path for the bridge
  file).
- Live: browse shows a running session's state; choosing it opens the
  rendered log; resuming it switches to the live buffer; resuming an
  inactive session produces a tracked `agent` session in the right directory
  and account; with `agent` absent, browsing, opening, and resuming behave as
  today.

The uncommitted summary-sweep changes in this working tree are preserved
exactly and are not part of this change; bridge edits deliberately avoid the
functions those changes touch.
