# Session Browser Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agent-log-browse-sessions` reach its real picker within 1.5 seconds on the current archive without losing sessions or live-state annotations.

**Architecture:** Read Codex's indexed app-server catalog first and use rollout repair only when the first indexed page is empty. Reuse that catalog during summary preflight, then take one authoritative snapshot of live agent sessions before formatting browser rows instead of scanning live buffers once per historical session.

**Tech Stack:** Emacs Lisp, EIEIO generic methods, Codex app-server JSON-RPC, ERT, Org/Texinfo documentation.

---

## File map

- `agent-log-codex.el`: Codex catalog acquisition and standalone live-session detection.
- `agent-log.el`: backend interface, summary preflight, live-state extension points, and browser candidate construction.
- `agent-log-agent.el`: optional agent-package bridge and bulk live-state snapshot.
- `agent-log-claude.el`: Claude implementation of the extended live-session generic.
- `agent-log-test.el`: wire-contract, catalog-reuse, bulk-snapshot, bridge, and end-to-end regression tests.
- `README.org`: source documentation for catalog and live-state behavior.
- `agent-log.texi`: generated Texinfo output from `README.org`.

The existing large files remain in place; splitting them is outside this fix.

### Task 1: Use Codex's indexed catalog

**Files:**
- Modify: `agent-log-test.el:3500-3590`
- Modify: `agent-log-codex.el:177-245`

- [ ] **Step 1: Write the indexed-wire-contract regression test**

Update `agent-log-test-codex-thread-list/matches-native-wire-contract` so both
pages require `useStateDbOnly` and add the empty-index repair test:

```elisp
(ert-deftest agent-log-test-codex-thread-list/repairs-empty-index ()
  "Falls back to rollout repair when Codex's state database is empty."
  (let ((backend
         (agent-log--make-codex
          :name "Codex" :key 'codex :directory "/unused/.codex"))
        calls)
    (cl-letf (((symbol-function 'agent-log-codex--effective-home)
               (lambda (_backend) "/tmp/active-codex-home/"))
              ((symbol-function 'make-process)
               (lambda (&rest _args) 'fake-process))
              ((symbol-function 'agent-log-codex--stop-catalog-process)
               (lambda (&rest _args) nil))
              ((symbol-function 'agent-log-codex--catalog-request)
               (lambda (_process _request-id method params)
                 (pcase method
                   ("initialize" nil)
                   ("thread/list"
                    (push (alist-get 'useStateDbOnly params) calls)
                    (if (eq (alist-get 'useStateDbOnly params) t)
                        '((data . []) (nextCursor . nil))
                      '((data . [((id . "repaired"))])
                        (nextCursor . nil))))))))
      (should (equal (mapcar (lambda (thread) (alist-get 'id thread))
                             (agent-log-codex--thread-list backend))
                     '("repaired"))))
    (should (equal (nreverse calls) '(t :json-false)))))
```

In the existing pagination test, assert:

```elisp
(should (eq (alist-get 'useStateDbOnly first-page) t))
(should (eq (alist-get 'useStateDbOnly second-page) t))
```

- [ ] **Step 2: Run the focused tests and confirm the red state**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  agent-log-test-codex-thread-list/matches-native-wire-contract
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  agent-log-test-codex-thread-list/repairs-empty-index
```

Expected: both tests fail because indexed requests are absent and no repair
retry occurs.

- [ ] **Step 3: Implement indexed listing with an explicit repair retry**

In `agent-log-codex--thread-list`, add state before the pagination loop:

```elisp
(state-db-only t)
(first-page t)
```

Build every request with the explicit JSON boolean:

```elisp
(let* ((params
        `((limit . ,agent-log-codex--thread-list-page-size)
          (sortKey . "updated_at")
          (sortDirection . "desc")
          (useStateDbOnly . ,(if state-db-only t :json-false))
          ,@(when cursor `((cursor . ,cursor)))))
       (result
        (agent-log-codex--catalog-request
         process (cl-incf request-id) "thread/list" params))
       (page (append (alist-get 'data result) nil)))
  (if (and first-page state-db-only (null page))
      (setq state-db-only nil
            cursor nil)
    (setq first-page nil)
    (dolist (thread page)
      (let ((id (alist-get 'id thread)))
        (unless (and (stringp id) (gethash id seen-ids))
          (when (stringp id)
            (puthash id t seen-ids))
          (setq threads (nconc threads (list thread))))))
    (let ((next-cursor (alist-get 'nextCursor result)))
      (cond
       ((not (stringp next-cursor))
        (setq done t))
       ((gethash next-cursor seen-cursors)
        (error "Codex thread catalog repeated cursor %s" next-cursor))
       (t
        (puthash next-cursor t seen-cursors)
        (setq cursor next-cursor))))))
```

Update the function docstring to state that indexed listing is primary and an
empty initial page triggers rollout repair. Do not catch app-server errors.

- [ ] **Step 4: Run the focused tests and confirm the green state**

Run the Step 2 command again.

Expected: 2 tests pass, 0 unexpected.

- [ ] **Step 5: Commit the indexed catalog change**

Stage only the Task 1 hunks from mixed files, inspect the cached diff, and
commit:

```bash
git add -p agent-log-codex.el agent-log-test.el
git diff --cached --check
git diff --cached
git commit -m "agent-log: use indexed Codex session catalog"
```

Do not stage the pre-existing summary-sweep hunks in `agent-log-test.el`.

### Task 2: Reuse the catalog during summary preflight

**Files:**
- Modify: `agent-log-test.el:1720-1740,3728-3795`
- Modify: `agent-log.el:168-171,2805-2817`
- Modify: `agent-log-codex.el:673-700`
- Modify: `agent-log-claude.el:512-516`
- Modify: `agent-log-agent.el:74-90`

- [ ] **Step 1: Write the catalog-reuse regression test**

```elisp
(ert-deftest agent-log-test-sessions-needing-summary/reuses-session-catalog ()
  "Passes the existing catalog to live-session detection."
  (let* ((backend agent-log-test--codex-backend)
         (sessions (list (list "s1" :file "/a.jsonl" :backend backend)))
         (index (make-hash-table :test #'equal))
         received)
    (cl-letf (((symbol-function 'agent-log--active-backend-instances)
               (lambda () (list backend)))
              ((symbol-function 'agent-log--active-session-ids)
               (lambda (_backend &optional catalog)
                 (setq received catalog)
                 nil)))
      (agent-log--sessions-needing-summary sessions index))
    (should (eq received sessions))))
```

Update the browse/resume test's replacement function to accept the optional
catalog:

```elisp
(lambda (_backend &optional _sessions) nil)
```

- [ ] **Step 2: Run the focused tests and confirm the red state**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-sessions-needing-summary/reuses-session-catalog'
```

Expected: failure because the active-session function receives `nil` rather
than the existing session list.

- [ ] **Step 3: Extend live-session detection and reuse the supplied list**

Change the generic contract in `agent-log.el`:

```elisp
(cl-defgeneric agent-log--active-session-ids (backend &optional sessions)
  "Return live session IDs for BACKEND.
When SESSIONS is non-nil, reuse that session catalog for any lookup
needed to identify live sessions.")
```

Pass the catalog from summary preflight:

```elisp
(let ((active-ids
       (cl-loop for backend in (agent-log--active-backend-instances)
                append (agent-log--active-session-ids backend sessions))))
  ...)
```

In the Codex method, filter a supplied merged catalog to that backend and read
the backend only when no catalog is supplied:

```elisp
(let ((sessions
       (if sessions
           (seq-filter
            (lambda (session)
              (eq (plist-get (cdr session) :backend) backend))
            sessions)
         (agent-log--read-sessions backend)))
      ids)
  ...)
```

Add optional ignored `_sessions` arguments to the Claude method and the agent
bridge's around method. Keep `cl-call-next-method` unchanged so original
arguments are forwarded.

- [ ] **Step 4: Run the focused test and full browse/resume regression**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-sessions-needing-summary/reuses-session-catalog'
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-codex-browse-open-resume/canonical-id'
```

Expected: each command reports 1 pass and 0 unexpected.

- [ ] **Step 5: Commit catalog reuse**

```bash
git add agent-log-agent.el agent-log-claude.el
git add -p agent-log.el agent-log-codex.el agent-log-test.el
git diff --cached --check
git diff --cached
git commit -m "agent-log: reuse catalog for live-session checks"
```

Stage only Task 2 hunks from files that also contain summary-sweep work.

### Task 3: Snapshot live agent state once per browser

**Files:**
- Modify: `agent-log-test.el:4580-4675`
- Modify: `agent-log.el:220-229,1765-1811`
- Modify: `agent-log-agent.el:47-60`

- [ ] **Step 1: Write the bulk candidate regression test**

Place this beside the existing live-session annotation test:

```elisp
(ert-deftest agent-log-test-build-candidates/snapshots-live-sessions-once ()
  "Use one bulk live-state snapshot for every browser candidate."
  (let* ((backend agent-log-claude--instance)
         (sessions
          `(("live-1" :display "hello" :timestamp 1700000000000
             :project "/tmp/p" :file "/tmp/live-1.jsonl" :backend ,backend)
            ("dead-1" :display "bye" :timestamp 1700000000000
             :project "/tmp/p" :file "/tmp/dead-1.jsonl" :backend ,backend)))
         (table (make-hash-table :test #'equal))
         (calls 0)
         (agent-log-live-session-info-table-function
          (lambda ()
            (cl-incf calls)
            table))
         (agent-log-live-session-info-function
          (lambda (&rest _)
            (ert-fail "Point lookup ran despite installed bulk snapshot"))))
    (puthash '(claude-code . "live-1")
             (list :buffer (current-buffer) :state 'busy)
             table)
    (cl-letf (((symbol-function 'agent-log--read-index)
               (lambda () (make-hash-table :test #'equal)))
              ((symbol-function 'agent-log--session-size-label)
               (lambda (_meta) "1k")))
      (let ((candidates (agent-log--build-candidates sessions)))
        (should (= calls 1))
        (should (string-match-p "\\[busy\\]" (car (nth 0 candidates))))
        (should-not (string-match-p "\\[" (car (nth 1 candidates))))))))
```

In the existing
`agent-log-test-build-candidates/annotates-live-sessions` test, add this local
binding to its `let*` so it continues to exercise the point-lookup compatibility
path even after `agent-log-agent` globally installs the bulk provider:

```elisp
(agent-log-live-session-info-table-function nil)
```

- [ ] **Step 2: Write the agent-bridge snapshot test**

```elisp
(ert-deftest agent-log-test-agent-bridge/session-info-table ()
  "Snapshot live session identities and states in one registry pass."
  (agent-log-test--with-agent-session "sid-1"
    (let* ((table (agent-log-agent--session-info-table))
           (info (gethash '(claude-code . "sid-1") table)))
      (should (eq (hash-table-test table) 'equal))
      (should (eq (plist-get info :state) 'waiting))
      (should (eq (plist-get info :buffer) buf)))))
```

- [ ] **Step 3: Run both new tests and confirm the red state**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-build-candidates/snapshots-live-sessions-once'
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-agent-bridge/session-info-table'
```

Expected: failures because the table extension variable and bridge function do
not exist.

- [ ] **Step 4: Add the bulk extension point and consume it once**

Define the optional extension beside the existing point lookup:

```elisp
(defvar agent-log-live-session-info-table-function nil
  "Function returning a snapshot of every currently live session.
When non-nil, called without arguments and returns an equal-tested hash
table keyed by (BACKEND-KEY . SESSION-ID).  Values use the same
(:buffer BUFFER :state STATE) plist as
`agent-log-live-session-info-function'.  An installed function is
authoritative even when it returns an empty table.")
```

At the start of `agent-log--build-candidates`, distinguish an installed bulk
provider from an absent one and call it exactly once:

```elisp
(let* ((index (agent-log--read-index))
       (bulk-live-info-p
        (functionp agent-log-live-session-info-table-function))
       (live-info-table
        (when bulk-live-info-p
          (funcall agent-log-live-session-info-table-function)))
       ...)
```

Replace the per-row lookup with:

```elisp
(live
 (when backend
   (let ((key (cons (agent-log-backend-key backend) session-id)))
     (if bulk-live-info-p
         (gethash key live-info-table)
       (when agent-log-live-session-info-function
         (funcall agent-log-live-session-info-function
                  (car key) (cdr key)))))))
```

Do not catch provider errors and do not fall back to point lookups when the
bulk provider returns an empty table.

- [ ] **Step 5: Implement the agent registry snapshot**

Add this function beside `agent-log-agent--session-info`:

```elisp
(defun agent-log-agent--session-info-table ()
  "Return an equal-tested table describing every live agent session."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (buffer (agent-session-buffers) table)
      (when-let* ((session (agent-session buffer))
                  (backend-key (agent-session-backend session))
                  (session-id (agent-session-id session)))
        (puthash (cons backend-key session-id)
                 (list :buffer buffer
                       :state (agent-session-display-state buffer))
                 table)))))
```

Install both bridge extensions explicitly:

```elisp
(setq agent-log-live-session-info-function #'agent-log-agent--session-info
      agent-log-live-session-info-table-function
      #'agent-log-agent--session-info-table)
```

- [ ] **Step 6: Run bulk, compatibility, and bridge tests**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-build-candidates/snapshots-live-sessions-once'
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-build-candidates/annotates-live-sessions'
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  'agent-log-test-agent-bridge/session-info-table'
```

Expected: each command reports 1 pass and 0 unexpected. The existing annotation
test's explicit nil bulk binding proves the point-lookup compatibility path
remains intact.

- [ ] **Step 7: Commit the bulk snapshot**

```bash
git add agent-log-agent.el
git add -p agent-log.el agent-log-test.el
git diff --cached --check
git diff --cached
git commit -m "agent-log: batch live session annotations"
```

Do not stage summary-sweep hunks in the mixed files.

### Task 4: Document and verify the complete browser path

**Files:**
- Modify: `README.org:263-275,455`
- Modify: `agent-log.texi:330-342,558,790-793` (generated)

- [ ] **Step 1: Document indexed listing and bulk live annotations**

In the session-browsing section of `README.org`, state:

```org
For Codex, Agent Log follows native Resume's database-first path so browsing
does not scan the rollout archive on every invocation; if the initial indexed
page is empty, it asks app-server to run its normal rollout scan-and-repair
path.  Live-state annotations use one snapshot of the agent package's session
registry for the entire picker, rather than rescanning live buffers for each
historical row.
```

Update the live-state extension paragraph to name both the single-session and
bulk table functions and explain that the optional bridge installs both.

- [ ] **Step 2: Regenerate Texinfo through the repository's Org export hook**

Save `README.org` in the configured Emacs profile so `.dir-locals.el` runs
`org-texinfo-export-to-texinfo`. Confirm `agent-log.texi` contains both new
sentences:

```bash
rg -n "database-first|one snapshot|live-session-info-table" \
  README.org agent-log.texi
```

Expected: matching source and generated documentation.

- [ ] **Step 3: Run package loading, compilation, and the complete test suite**

Run:

```bash
~/My\ Drive/dotfiles/claude/bin/batch-test.sh agent-log
make compile
make test
git diff --check
```

Expected: package loads successfully; byte compilation emits no warnings; all
ERT tests pass; and `git diff --check` reports no whitespace errors. Move the
source-tree `.elc` files created by `make compile` to Trash before committing.

- [ ] **Step 4: Measure three real active-Emacs picker runs**

Confirm that `symbol-file` for `agent-log-browse-sessions` points into the
current profile's `elpaca/builds/agent-log/agent-log.elc`. Then schedule three
invocations of `agent-log-browse-sessions`. For each invocation, record elapsed
time in a one-shot `minibuffer-setup-hook` when the `Session: ` prompt appears,
and schedule `abort-recursive-edit` on a zero-second timer so it runs after the
minibuffer's recursive edit is established.

Environment: active 8.3.0-dev Emacs profile, `agent-log-group-by-project` nil,
current real Claude and Codex archives, optional agent bridge loaded.

Inspect the loaded artifact:

```bash
emacsclient --eval \
  '(list :feature (featurep (quote agent-log))
         :grouped agent-log-group-by-project
         :bridge (featurep (quote agent-log-agent))
         :file (symbol-file (quote agent-log-browse-sessions)))'
```

Schedule the three runs:

```bash
emacsclient --eval \
  '(progn
     (defvar agent-log--e2e-times nil)
     (defvar agent-log--e2e-errors nil)
     (defvar agent-log--e2e-start nil)
     (defvar agent-log--e2e-count 0)
     (defvar agent-log--e2e-done nil)
     (defun agent-log--e2e-abort ()
       (when (active-minibuffer-window)
         (abort-recursive-edit)))
     (defun agent-log--e2e-minibuffer ()
       (when (equal (minibuffer-prompt) "Session: ")
         (push (- (float-time) agent-log--e2e-start)
               agent-log--e2e-times)
         (remove-hook (quote minibuffer-setup-hook)
                      (function agent-log--e2e-minibuffer))
         (run-at-time 0 nil (function agent-log--e2e-abort))))
     (defun agent-log--e2e-run ()
       (if (>= agent-log--e2e-count 3)
           (progn
             (remove-hook (quote minibuffer-setup-hook)
                          (function agent-log--e2e-minibuffer))
             (setq agent-log--e2e-times (nreverse agent-log--e2e-times)
                   agent-log--e2e-done t)
             (fmakunbound (quote agent-log--e2e-abort))
             (fmakunbound (quote agent-log--e2e-minibuffer))
             (fmakunbound (quote agent-log--e2e-run)))
         (setq agent-log--e2e-start (float-time))
         (add-hook (quote minibuffer-setup-hook)
                   (function agent-log--e2e-minibuffer))
         (condition-case err
             (agent-log-browse-sessions)
           (quit nil)
           (error (push (error-message-string err)
                        agent-log--e2e-errors)))
         (setq agent-log--e2e-count (1+ agent-log--e2e-count))
         (run-at-time 0.5 nil (function agent-log--e2e-run))))
     (setq agent-log--e2e-times nil
           agent-log--e2e-errors nil
           agent-log--e2e-count 0
           agent-log--e2e-done nil)
     (run-at-time 0 nil (function agent-log--e2e-run))
     :scheduled)'
```

Poll after the runs finish, then remove the retained result variables:

```bash
emacsclient --eval \
  '(list :done agent-log--e2e-done
         :times agent-log--e2e-times
         :errors agent-log--e2e-errors
         :count agent-log--e2e-count)'
emacsclient --eval \
  '(progn
     (mapc (lambda (symbol)
             (when (boundp symbol) (makunbound symbol)))
           (quote (agent-log--e2e-times agent-log--e2e-errors
                   agent-log--e2e-start agent-log--e2e-count
                   agent-log--e2e-done)))
     :clean)'
```

Expected: three timings, every one at or below 1.5 seconds, no errors, and the
actual `Session: ` minibuffer observed in every run.

- [ ] **Step 5: Commit the documentation**

Stage only the performance documentation hunks from the files that also contain
summary-sweep edits:

```bash
git add -p README.org agent-log.texi
git diff --cached --check
git diff --cached
git commit -m "docs: explain fast session catalog loading"
```

- [ ] **Step 6: Confirm repository hygiene**

Run:

```bash
git status --short --branch
git log -4 --oneline
```

Expected: only the user's pre-existing summary-sweep changes remain modified;
there are no generated `.elc` files, test artifacts, background processes, or
unstaged performance hunks.
