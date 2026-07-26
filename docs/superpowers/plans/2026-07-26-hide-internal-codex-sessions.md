# Hide Internal Codex Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Exclude Codex workers and guardians from ordinary session collections
without preventing explicit access to their transcript files.

**Architecture:** Add a backend-dispatched visibility method and apply it once
in `agent-log--read-all-sessions`.  Codex classifies `:source` values containing
`:subagent` as internal; other backends use the visible-by-default method.

**Tech Stack:** Emacs Lisp, `cl-generic`, ERT, Elpaca batch verification.

---

### Task 1: Add the failing archive-visibility regression

**Files:**
- Modify: `agent-log-test.el`

- [ ] **Step 1: Write the failing test**

Add an ERT test that stubs two backends.  Return one top-level Codex session,
one spawned Codex worker, one Codex guardian, and one Claude session.  Assert
that `agent-log--read-all-sessions` returns only the top-level Codex and Claude
IDs.

- [ ] **Step 2: Run the regression test and verify RED**

Run:

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  agent-log-test-read-all-sessions/excludes-internal-codex-sessions
```

Expected: FAIL because both internal Codex IDs are still present.

### Task 2: Implement the shared visibility boundary

**Files:**
- Modify: `agent-log.el`
- Modify: `agent-log-codex.el`
- Modify: `agent-log-redact.el`

- [ ] **Step 1: Add the generic method**

Define `agent-log--session-user-visible-p` in `agent-log.el`.  Its default
method for `agent-log-backend` returns non-nil.

- [ ] **Step 2: Filter the shared collection**

Add `agent-log--session-user-visible-p` to the predicate applied by
`agent-log--read-all-sessions`, alongside the ignored-project test.

- [ ] **Step 3: Implement Codex classification**

Specialize `agent-log--session-user-visible-p` for `agent-log-codex` and return
nil when `agent-log-codex--subagent-session-p` identifies the record.

- [ ] **Step 4: Preserve maintenance and exact-ID paths**

Allow maintenance callers to include internal backend sessions while retaining
the existing ignored-project filter.  Use that path when the redaction command
clears and rebuilds rendered logs.  Resolve exact session IDs through the direct
file lookup rather than the visible archive collection.

- [ ] **Step 5: Run the regression tests and verify GREEN**

Run the targeted ERT command from Task 1.

Expected: one test passes.

### Task 3: Document and verify the behavior

**Files:**
- Modify: `README.org`
- Modify: `agent-log.texi`

- [ ] **Step 1: Update the manual**

Document that archive-wide commands exclude Codex workers and guardians, while
direct open-by-ID and open-by-file remain available.

- [ ] **Step 2: Run the full package verification**

Run:

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
~/My\ Drive/dotfiles/claude/bin/batch-test.sh agent-log
```

Expected: all ERT tests pass and batch compilation exits cleanly.

- [ ] **Step 3: Verify the real onboarding archive**

Evaluate the installed package in isolated batch Emacs and count onboarding
records in raw Codex discovery and in `agent-log--read-all-sessions`.

Expected: raw discovery includes subagents; the ordinary collection includes
zero records whose source contains `:subagent`.

- [ ] **Step 4: Commit the implementation**

Stage only the implementation hunks in `agent-log.el`, `agent-log-codex.el`,
`agent-log-redact.el`, `agent-log-test.el`, `README.org`, `agent-log.texi`, and
the design/plan files, preserving unrelated working-tree changes.
Commit with:

```sh
git commit -m "agent-log: hide internal Codex sessions"
```
