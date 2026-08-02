# Session Browser Performance Design

## Problem

`agent-log-browse-sessions` takes several seconds to display the session
picker on the current archive. Measurements identified two independent
sources of latency:

1. The Codex backend asks `thread/list` to scan rollout files on every page.
   With more than 1,300 Codex threads, pagination alone takes roughly four to
   eight seconds.
2. The optional agent bridge annotates each historical row by scanning every
   live agent buffer. With roughly 1,500 historical sessions, this repeats the
   same live-buffer scan roughly 1,500 times and adds another one to three
   seconds.

Summary-state checks can also repeat the already-loaded Codex catalog when the
agent bridge is absent.

## Goals

- Display the actual session picker in at most 1.5 seconds on the current
  archive in three consecutive active-Emacs runs.
- Preserve the complete Codex catalog, pagination, live-state labels, and
  existing resume behavior.
- Preserve standalone operation when the optional agent package is absent.
- Avoid stale caches and silent error fallbacks.

## Non-goals

- Persisting live state in archive metadata.
- Changing the picker layout, sorting, grouping, or completion behavior.
- Replacing the Codex app server or agent package as identity authorities.

## Design

### Indexed Codex catalog

Codex `thread/list` requests will set `useStateDbOnly` to true, matching the
native Resume picker's indexed path. Pagination and ID-based deduplication
remain unchanged. If and only if the first indexed page is empty, Agent Log
will retry the request with `useStateDbOnly` false so Codex can scan rollout
files and repair an absent index. App-server errors will continue to surface;
they will not trigger an unrelated fallback.

### Catalog reuse

Live-session detection may receive the session catalog already loaded by the
caller. The standalone Codex method will filter that catalog instead of
calling `thread/list` again. Backends that do not need the catalog may ignore
the optional argument.

### Bulk live-state snapshot

Core Agent Log will add an optional bulk extension point alongside the
existing single-session lookup. The bulk function will return an equal-tested
hash table keyed by `(BACKEND-KEY . SESSION-ID)`, with values using the current
`(:buffer BUFFER :state STATE)` representation.

`agent-log--build-candidates` will call the bulk function once before mapping
over sessions and use hash lookups for each row. When a bulk function is
installed, its result is authoritative even when the table is empty. When no
bulk function is installed, the existing per-session extension remains the
compatibility path.

The agent bridge will build the table with one pass over
`agent-session-buffers`. The existing point lookup remains available for
resume routing and other single-session operations. This keeps ephemeral live
state out of durable archive metadata and avoids cache invalidation.

## Failure behavior

An error from either live-state extension will propagate as it does now. Agent
Log will not silently discard live annotations. An installed bulk function
returning an empty table means that no sessions are live; it will not cause
per-row rescans.

If the Codex state database has no first page, the explicit rollout-scan retry
repairs and returns the catalog. A nonempty indexed first page remains the
authority, including for subsequent pagination.

## Verification

Regression tests will cover:

- `useStateDbOnly` on every indexed Codex page;
- the empty-first-page repair request;
- reuse of an existing catalog for live-session detection;
- one bulk snapshot call for an entire candidate list;
- preservation of the per-session compatibility extension;
- agent-bridge snapshot keys and live states.

Completion requires warning-free byte compilation, the full ERT suite, and
three consecutive active-Emacs invocations that reach the real `Session:`
minibuffer within 1.5 seconds. The live check must use the package artifact
loaded by the user's current Emacs profile.
