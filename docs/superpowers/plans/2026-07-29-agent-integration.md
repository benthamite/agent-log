# Agent Log Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume `agent`'s live-identity contract through an optional
bridge, per `docs/superpowers/specs/2026-07-29-agent-integration-design.md`.

**Architecture:** A new `agent-log-agent.el` holds every reference to the
`agent` package: `:around` methods on existing generics for buffer→transcript
resolution, live IDs, and duplicate-safe agent-routed resume, plus an
implementation of one new core extension point used to annotate the browser.
Dead heuristics that consumed artifacts of the pre-rename agent package are
deleted.

**Tech Stack:** Emacs Lisp, `cl-generic`, ERT.

## Global Constraints

- The working tree has UNCOMMITTED summary-sweep changes in `README.org`,
  `agent-log.el`, `agent-log-test.el`, and `agent-log.texi`.  Preserve them
  exactly.  NEVER run `git add <file>` / `git add -A` on those four files,
  and never stash, checkout, or reset them.  Stage only your own hunks with
  `git diff -- FILE > p.patch`, hand-trim the patch to your hunks, then
  `git apply --cached p.patch`.  Do not edit inside
  `agent-log--browse-flat`, `agent-log--browse-grouped`, or the other
  functions the uncommitted diff touches (check with `git diff` first).
- Loading `agent-log` alone must not load or require `agent`.
- No code added here may read the Codex catalog (`agent-log--read-sessions`
  for Codex spawns an app-server) outside explicit user actions that already
  do so (resume validation).
- Backend registries stay separate; no new slots on backend records.
- Full ERT suite and `make compile` stay clean.

---

### Task 1: Core live-info extension point and browser annotation

**Files:**
- Modify: `agent-log.el` (customization section for the defvar and defface;
  `agent-log--build-candidates`, ~line 1748)
- Test: `agent-log-test.el` (new section at end of file)

**Interfaces:**
- Produces: `agent-log-live-session-info-function` (defvar, nil default):
  called with BACKEND-KEY (symbol) and SESSION-ID (string), returns
  `(:buffer BUFFER :state STATE)` or nil.  Face `agent-log-live-state`.
  Task 3's bridge installs the implementation.

- [ ] **Step 1: Write the failing test**

```elisp
(ert-deftest agent-log-test-build-candidates/annotates-live-sessions ()
  "Live sessions carry a state tag from the live-info function."
  (let* ((backend agent-log-claude--instance)
         (sessions
          `(("live-1" :display "hello" :timestamp 1700000000000
             :project "/tmp/p" :file "/tmp/live-1.jsonl" :backend ,backend)
            ("dead-1" :display "bye" :timestamp 1700000000000
             :project "/tmp/p" :file "/tmp/dead-1.jsonl" :backend ,backend)))
         (agent-log-live-session-info-function
          (lambda (key id)
            (when (and (eq key 'claude-code) (equal id "live-1"))
              (list :buffer (current-buffer) :state 'busy)))))
    (cl-letf (((symbol-function 'agent-log--read-index)
               (lambda () (make-hash-table :test #'equal)))
              ((symbol-function 'agent-log--session-size-label)
               (lambda (_meta) "1k")))
      (let* ((candidates (agent-log--build-candidates sessions))
             (live-label (car (nth 0 candidates)))
             (dead-label (car (nth 1 candidates))))
        (should (string-match-p "\\[busy\\]" live-label))
        (should-not (string-match-p "\\[" dead-label))))))
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  agent-log-test-build-candidates/annotates-live-sessions
```

Expected: FAIL (`agent-log-live-session-info-function` void).

- [ ] **Step 3: Implement**

In `agent-log.el`, near the other defvars in the customization/framework
area:

```elisp
(defvar agent-log-live-session-info-function nil
  "Function reporting whether a historical session is currently live.
When non-nil, called with BACKEND-KEY (a backend key symbol such as
`claude-code' or `codex') and SESSION-ID (string).  Returns a plist
\(:buffer BUFFER :state STATE) when that session is running in a live
buffer, where STATE is a symbol such as `busy', `waiting',
`background-waiting', or `unknown'; nil otherwise.  Installed by the
optional agent integration; nil means no live information is
available.")

(defface agent-log-live-state
  '((t :inherit success :weight bold))
  "Face for the live-state tag on sessions in the browser."
  :group 'agent-log)
```

In `agent-log--build-candidates`, inside the per-session `let*`, after the
`backend` binding add:

```elisp
              (live (when (and agent-log-live-session-info-function backend)
                      (funcall agent-log-live-session-info-function
                               (agent-log-backend-key backend) session-id)))
              (live-tag (if live
                            (propertize
                             (format "[%s] " (plist-get live :state))
                             'face 'agent-log-live-state)
                          ""))
```

and change the final label to include it:

```elisp
              (label (concat icon " " live-tag body)))
```

- [ ] **Step 4: Run the test and verify it passes**

Same command as Step 2.  Expected: PASS.

- [ ] **Step 5: Commit (selective staging)**

```sh
git diff -- agent-log.el > /tmp/al-core.patch
# trim /tmp/al-core.patch to only the hunks you wrote, then:
git apply --cached /tmp/al-core.patch
git diff -- agent-log-test.el > /tmp/al-test.patch
# trim to your test hunk, then:
git apply --cached /tmp/al-test.patch
git commit -m "agent-log: add a live-session annotation point to the browser"
```

Verify afterwards: `git status` still shows the four files modified (the
summary-sweep changes remain unstaged) and `git diff` still contains exactly
the summary-sweep hunks.

### Task 2: Extract the Codex resume preamble

**Files:**
- Modify: `agent-log-codex.el` (`agent-log--resume-session` method,
  lines 735-774)
- Test: existing suite only (pure refactor)

**Interfaces:**
- Produces: `agent-log-codex--prepare-resume BACKEND SESSION-ID` →
  project directory string or nil.  Validates the session against the
  canonical catalog (signals `user-error' when absent or its transcript is
  unreadable), caches the transcript with
  `codex--cache-session-transcript', records `agent-log--session-project',
  and, when the default `codex-terminal-backend' is `app-server', installs
  the exact-path resume advice and registers the transcript in
  `agent-log-codex--exact-resume-paths'.  Task 4's bridge consumes this.

- [ ] **Step 1: Refactor**

Split the current method so validation and preparation live in a named
function; the method keeps only the launch:

```elisp
(defun agent-log-codex--prepare-resume (backend session-id)
  "Validate SESSION-ID against the canonical Codex catalog and prepare resume.
Cache the canonical transcript, record the session project, and make
app-server resumes path-exact.  Return the project directory recorded in
the catalog, or nil when it names no usable directory.  Signal a
`user-error' when SESSION-ID is not in the catalog or its transcript is
unreadable."
  (let ((session (assoc session-id (agent-log--read-sessions backend))))
    (unless session
      (user-error
       "Codex session %s is not in the canonical interactive thread catalog"
       session-id))
    (let ((transcript (plist-get (cdr session) :file)))
      (setq agent-log--session-project
            (or (plist-get (cdr session) :project)
                agent-log--session-project))
      (unless (require 'codex nil t)
        (user-error "Package `codex' is required but not available"))
      (unless (and (stringp transcript) (file-readable-p transcript))
        (user-error "Canonical Codex transcript is not readable: %s"
                    transcript))
      (when (fboundp 'codex--cache-session-transcript)
        (codex--cache-session-transcript session-id transcript))
      (when (and (eq codex-terminal-backend 'app-server)
                 (fboundp 'codex--app-server-launch-resume-session))
        (agent-log-codex--install-exact-resume-advice)
        (puthash session-id transcript
                 agent-log-codex--exact-resume-paths))
      (when (and agent-log--session-project
                 (not (string-empty-p agent-log--session-project))
                 (file-directory-p agent-log--session-project))
        agent-log--session-project))))

(cl-defmethod agent-log--resume-session ((backend agent-log-codex) session-id)
  "Resume the Codex session SESSION-ID."
  (let* ((project-dir (or (agent-log-codex--prepare-resume backend session-id)
                          default-directory))
         (default-directory (if (file-directory-p project-dir)
                                project-dir
                              default-directory)))
    (cl-letf (((symbol-function 'codex--directory)
               (lambda () default-directory)))
      (if (and (eq codex-terminal-backend 'app-server)
               (fboundp 'codex--app-server-launch-resume-session))
          (condition-case err
              (codex--app-server-launch-resume-session session-id)
            (error
             (remhash session-id agent-log-codex--exact-resume-paths)
             (signal (car err) (cdr err))))
        (codex--start-subcommand "resume" nil (list session-id))))))
```

- [ ] **Step 2: Run the full suite and verify green**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
make compile
```

Expected: all tests pass; clean compile.  (agent-log-codex.el is not among
the dirty files, so normal staging is safe.)

- [ ] **Step 3: Commit**

```sh
git add agent-log-codex.el
git commit -m "agent-log: extract the Codex resume preparation step"
```

### Task 3: Bridge file — identity, live IDs, live info

**Files:**
- Create: `agent-log-agent.el`
- Modify: `agent-log.el` (add `(with-eval-after-load 'agent (require 'agent-log-agent))` immediately before `(provide 'agent-log)`)
- Modify: `Makefile` (add `-L $(ELPACA_REPOS)agent` to `LOAD_PATH`; compile
  `agent-log-agent.el` in the `compile` target; load `agent-log-codex.el`
  in the `test` target after `agent-log-claude.el` — the test file itself
  soft-requires the bridge)
- Modify: `.github/workflows/test.yml` (clone
  `https://github.com/benthamite/agent.git` into `../agent` alongside the
  other dependencies; note that the agent-side commits must be pushed
  before this repo's CI can pass)
- Test: `agent-log-test.el`

**Interfaces:**
- Consumes: from `agent` (public): `agent-session`, `agent-session-id`,
  `agent-session-backend`, `agent-session-buffers`,
  `agent-session-display-state`, `agent-backend`, `agent-session-create`,
  `agent-start-session`.  From Task 1:
  `agent-log-live-session-info-function`.
- Produces: `agent-log-agent--session-info BACKEND-KEY SESSION-ID` →
  `(:buffer BUFFER :state STATE)` or nil, used by Task 4.

- [ ] **Step 1: Write the failing tests**

Add to `agent-log-test.el` (new final section `;;;; Agent bridge`; these
tests require the real `agent` package, available on the load path):

```elisp
(require 'agent-log-agent nil t)

(defmacro agent-log-test--with-agent-session (id &rest body)
  "Run BODY in a fake live agent session buffer carrying ID.
Anaphorically binds `buf' to that buffer.  Skips the test when the
optional agent bridge is not loadable (e.g. CI without the sibling
agent checkout).  Stubs `agent-backend' so the bridge treats the
backend as registered."
  (declare (indent 1))
  `(progn
     (skip-unless (featurep 'agent-log-agent))
     (let ((buf (generate-new-buffer " *agent-log-agent-test*")))
       (unwind-protect
           (progn
             (with-current-buffer buf
               (setq-local agent--session
                           (agent-session-create
                            :backend 'claude-code
                            :directory "~/project/"
                            :id ,id)))
             (cl-letf (((symbol-function 'agent-session-buffers)
                        (lambda () (list buf)))
                       ((symbol-function 'agent-session-display-state)
                        (lambda (&rest _) 'waiting))
                       ((symbol-function 'agent-backend)
                        (lambda (_key) t)))
               ,@body))
         (kill-buffer buf)))))

(ert-deftest agent-log-test-agent-bridge/session-info ()
  "The bridge reports live buffer and state for a matching session."
  (agent-log-test--with-agent-session "sid-1"
    (let ((info (agent-log-agent--session-info 'claude-code "sid-1")))
      (should (eq (plist-get info :state) 'waiting))
      (should (buffer-live-p (plist-get info :buffer))))
    (should-not (agent-log-agent--session-info 'claude-code "other"))
    (should-not (agent-log-agent--session-info 'codex "sid-1"))))

(ert-deftest agent-log-test-agent-bridge/current-buffer-session-file ()
  "The agent-recorded id resolves the transcript through the bridge."
  (agent-log-test--with-agent-session "sid-1"
    (with-current-buffer buf
      (cl-letf (((symbol-function 'agent-log--find-session-file)
                 (lambda (_backend id)
                   (when (equal id "sid-1") "/tmp/sid-1.jsonl"))))
        (should (equal (agent-log--current-buffer-session-file
                        agent-log-claude--instance)
                       "/tmp/sid-1.jsonl"))))))

(ert-deftest agent-log-test-agent-bridge/active-session-ids ()
  "With agent loaded, live ids come from agent's session structs."
  (agent-log-test--with-agent-session "sid-1"
    (should (equal (agent-log--active-session-ids
                    agent-log-claude--instance)
                   '("sid-1")))))
```

- [ ] **Step 2: Run the tests and verify they fail**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el \
  agent-log-test-agent-bridge/
```

Expected: FAIL (`agent-log-agent.el` missing).

- [ ] **Step 3: Implement `agent-log-agent.el`**

```elisp
;;; agent-log-agent.el --- Bridge to the agent live-session package -*- lexical-binding: t -*-

;; Optional integration between Agent Log (the durable archive) and the
;; `agent' package (live session control).  Loaded only when both
;; packages are present; everything in Agent Log that mentions `agent'
;; lives here, and only public `agent' API is used.

;;; Code:

(require 'cl-lib)
(require 'agent-log)
(require 'agent)

(defun agent-log-agent--session-info (backend-key session-id)
  "Return live info for SESSION-ID under BACKEND-KEY, or nil.
The result is a plist (:buffer BUFFER :state STATE) built from the
agent package's authoritative session identity and display state."
  (cl-loop for buffer in (agent-session-buffers)
           for session = (agent-session buffer)
           when (and session
                     (eq (agent-session-backend session) backend-key)
                     (equal (agent-session-id session) session-id))
           return (list :buffer buffer
                        :state (agent-session-display-state buffer))))

(setq agent-log-live-session-info-function #'agent-log-agent--session-info)

(cl-defmethod agent-log--current-buffer-session-file :around
  ((backend agent-log-backend))
  "Resolve the transcript from the agent-recorded native session id.
Fall back to the backend heuristics when the id is not yet known or
its transcript is not on disk."
  (or (when-let* ((session (agent-session (current-buffer)))
                  (id (agent-session-id session))
                  ((eq (agent-session-backend session)
                       (agent-log-backend-key backend))))
        (agent-log--find-session-file backend id))
      (cl-call-next-method)))

(cl-defmethod agent-log--active-session-ids :around
  ((backend agent-log-backend))
  "Report live session ids from the agent package's registry.
Agent tracks every live backend buffer, so its answer replaces the
standalone heuristics whenever it registers this backend."
  (let ((key (agent-log-backend-key backend)))
    (if (agent-backend key)
        (delete-dups
         (cl-loop for buffer in (agent-session-buffers)
                  for session = (agent-session buffer)
                  when (and session
                            (eq (agent-session-backend session) key)
                            (agent-session-id session))
                  collect (agent-session-id session)))
      (cl-call-next-method))))

(provide 'agent-log-agent)
;;; agent-log-agent.el ends here
```

Wire the loader in `agent-log.el` immediately before `(provide 'agent-log)`:

```elisp
(with-eval-after-load 'agent
  (require 'agent-log-agent))
```

Update `Makefile` as listed under Files.

- [ ] **Step 4: Run the tests and verify they pass**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
make compile && make test
```

Expected: all pass, clean compile of the new file.

- [ ] **Step 5: Commit (selective staging for the dirty files)**

```sh
git add agent-log-agent.el Makefile
git diff -- agent-log.el > /tmp/al-loader.patch   # trim to the loader hunk
git apply --cached /tmp/al-loader.patch
git diff -- agent-log-test.el > /tmp/al-t3.patch  # trim to the bridge tests
git apply --cached /tmp/al-t3.patch
git commit -m "agent-log: map live buffers through agent's session identity"
```

### Task 4: Duplicate-safe, agent-routed resume

**Files:**
- Modify: `agent-log-agent.el`
- Test: `agent-log-test.el`

**Interfaces:**
- Consumes: `agent-log-agent--session-info` (Task 3),
  `agent-log-codex--prepare-resume` (Task 2),
  `agent-log-claude--session-project-directory` (existing),
  `agent-start-session`/`agent-session-create` (agent).

- [ ] **Step 1: Write the failing tests**

```elisp
(ert-deftest agent-log-test-agent-bridge/resume-live-switches ()
  "Resuming a live session switches to its buffer, no new process."
  (agent-log-test--with-agent-session "sid-1"
    (let (started shown)
      (cl-letf (((symbol-function 'agent-start-session)
                 (lambda (&rest args) (setq started args)))
                ((symbol-function 'pop-to-buffer)
                 (lambda (b &rest _) (setq shown b))))
        (agent-log--resume-session agent-log-claude--instance "sid-1")
        (should (eq shown buf))
        (should-not started)))))

(ert-deftest agent-log-test-agent-bridge/resume-inactive-routes-through-agent ()
  "Resuming an inactive session goes through `agent-start-session'."
  (agent-log-test--with-agent-session "other-id"
    (let (started)
      (cl-letf (((symbol-function 'agent-start-session)
                 (lambda (session &rest options)
                   (setq started (cons session options))
                   (generate-new-buffer " *stub-live*")))
                ((symbol-function 'agent-log-claude--session-project-directory)
                 (lambda (_id) "/tmp/project/")))
        (agent-log--resume-session agent-log-claude--instance "sid-9")
        (should started)
        (let ((session (car started)))
          (should (eq (agent-session-backend session) 'claude-code))
          (should (equal (agent-session-directory session) "/tmp/project/")))
        (should (equal (plist-get (cdr started) :resume-id) "sid-9"))))))

(ert-deftest agent-log-test-agent-bridge/resume-without-agent-backend-falls-back ()
  "When agent does not register the backend, the direct path runs."
  (skip-unless (featurep 'agent-log-agent))
  (let (direct
        (real-require (symbol-function 'require)))
    (cl-letf (((symbol-function 'agent-backend) (lambda (_key) nil))
              ((symbol-function 'agent-log-agent--session-info)
               (lambda (&rest _) nil))
              ((symbol-function 'require)
               (lambda (feature &optional filename noerror)
                 (if (eq feature 'claude-code)
                     t
                   (funcall real-require feature filename noerror))))
              ((symbol-function 'claude-code--start)
               (lambda (&rest args) (setq direct (or args '(nil)))))
              ((symbol-function 'agent-log-claude--session-project-directory)
               (lambda (_id) nil)))
      (agent-log--resume-session agent-log-claude--instance "sid-9")
      (should direct))))
```

- [ ] **Step 2: Run the tests and verify they fail**

Same runner as Task 3 Step 2.  Expected: the first two FAIL (no :around
resume yet; a real resume would be attempted — stubs keep this safe).

- [ ] **Step 3: Implement in `agent-log-agent.el`**

```elisp
(defun agent-log-agent--switch-to-live (backend-key session-id)
  "Switch to SESSION-ID's live buffer; return non-nil when it was live."
  (when-let* ((live (agent-log-agent--session-info backend-key session-id))
              (buffer (plist-get live :buffer)))
    (pop-to-buffer buffer)
    (message "Session %s is already live (%s); switched to its buffer"
             session-id (plist-get live :state))
    t))

(defun agent-log-agent--resume (backend-key directory session-id)
  "Resume SESSION-ID through `agent-start-session'.
BACKEND-KEY names the agent backend; DIRECTORY is the project
directory or nil for the backend's ambient default.  Account handling,
lifecycle registration, and teardown all come from the agent package."
  (agent-start-session
   (agent-session-create
    :backend backend-key
    :directory (and directory
                    (file-name-as-directory
                     (abbreviate-file-name directory))))
   :resume-id session-id))

(with-eval-after-load 'agent-log-claude
  (cl-defmethod agent-log--resume-session :around
    ((_backend agent-log-claude) session-id)
    "Prefer the live buffer, then the agent dispatcher, then the direct path."
    (cond
     ((agent-log-agent--switch-to-live 'claude-code session-id))
     ((agent-backend 'claude-code)
      (agent-log-agent--resume
       'claude-code
       (agent-log-claude--session-project-directory session-id)
       session-id))
     (t (cl-call-next-method)))))

(with-eval-after-load 'agent-log-codex
  (cl-defmethod agent-log--resume-session :around
    ((backend agent-log-codex) session-id)
    "Prefer the live buffer, then the agent dispatcher, then the direct path.
The catalog validation, transcript caching, and app-server exact-path
registration from `agent-log-codex--prepare-resume' apply on the agent
path too, because `codex-start-session' reaches the same resume entry
point."
    (cond
     ((agent-log-agent--switch-to-live 'codex session-id))
     ((agent-backend 'codex)
      (agent-log-agent--resume
       'codex
       (agent-log-codex--prepare-resume backend session-id)
       session-id))
     (t (cl-call-next-method)))))
```

Add the matching `declare-function` forms at the top of
`agent-log-agent.el` for `agent-log-claude--session-project-directory`
and `agent-log-codex--prepare-resume` (defined in files loaded lazily).

- [ ] **Step 4: Run the tests and verify they pass**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
make compile
```

Expected: all pass.

- [ ] **Step 5: Commit**

```sh
git add agent-log-agent.el
git diff -- agent-log-test.el > /tmp/al-t4.patch  # trim to the new tests
git apply --cached /tmp/al-t4.patch
git commit -m "agent-log: route resume through the agent dispatcher"
```

### Task 5: Delete the dead pre-rename heuristics

**Files:**
- Modify: `agent-log-claude.el` (delete `claude-code-extras--status-data`
  defvar at line 41 and `agent-log-claude--buffer-status-data`
  (lines 319-323); rewrite the `agent-log--active-session-ids` Claude
  method; delete `agent-log-claude--read-status-file`,
  `agent-log-claude--status-file-for-buffer`,
  `agent-log-claude--sanitize-buffer-name`, and the
  `agent-log-claude--status-directory` defconst; rewire
  `agent-log-claude--session-id-from-buffer` and the status branches of
  the Claude `agent-log--current-buffer-session-file` method)
- Modify: `agent-log-test.el` (delete/adjust the tests that stub the
  removed functions, around lines 3351-3413 and 3945-3976 — verify exact
  extents with `git diff` awareness first)

**Interfaces:**
- Consumes: nothing new.  The bridge (Tasks 3-4) supplies live detection
  when `agent` is present; the surviving heuristics (visible-text match,
  newest project JSONL, history.jsonl) cover the standalone case.

- [ ] **Step 1: Rewrite the affected functions**

The Claude active-ids method becomes an honest stub:

```elisp
(cl-defmethod agent-log--active-session-ids ((_backend agent-log-claude))
  "Return live Claude session ids.
Standalone Agent Log has no reliable live-identity source for Claude
Code; the optional agent integration overrides this with the
authoritative answer."
  nil)
```

`agent-log-claude--session-id-from-buffer` derives from the session file
instead of the removed status file:

```elisp
(defun agent-log-claude--session-id-from-buffer ()
  "Return the session ID for the Claude session in the current buffer.
Resolve the buffer's session file (through the agent integration when
available, otherwise the standalone heuristics) and derive the id from
its file name."
  (when-let* ((file (agent-log--current-buffer-session-file
                     agent-log-claude--instance)))
    (agent-log--session-id-from-file agent-log-claude--instance file)))
```

The Claude `agent-log--current-buffer-session-file` method drops its
`status`, `transcript`, and `session-id` bindings and their two branches,
keeping the visible-text, latest-JSONL, and history.jsonl fallbacks:

```elisp
(cl-defmethod agent-log--current-buffer-session-file ((backend agent-log-claude))
  "Return the JSONL file for the Claude Code session in the current buffer.
BACKEND is the Claude Code backend instance.  Match visible terminal
text against project transcripts, then fall back to the most recent
JSONL in the project directory, then to a session in `history.jsonl'
whose project matches the buffer directory.  The optional agent
integration short-circuits this with the authoritative session id."
  (let* ((dir (claude-code--extract-directory-from-buffer-name (buffer-name)))
         (session-dir (and dir (agent-log-claude--find-project-session-dir dir))))
    (or (and session-dir (agent-log-claude--visible-session-file session-dir))
        (and session-dir (agent-log-claude--find-latest-jsonl session-dir))
        (when-let* ((match (agent-log-claude--find-session-for-project
                            dir (agent-log--read-sessions backend))))
          (plist-get (cdr match) :file)))))
```

Delete the now-unused defuns/defvars listed under Files.  Delete or rewrite
the tests that stub them (they test deleted behavior).

- [ ] **Step 2: Run the full suite and verify green**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
make compile
```

Expected: all pass; no references to deleted symbols remain
(`grep -rn "claude-code-extras\|read-status-file\|status-file-for-buffer\|sanitize-buffer-name\|status-directory" agent-log-claude.el agent-log-test.el` is empty apart from unrelated matches).

- [ ] **Step 3: Commit**

```sh
git add agent-log-claude.el
git diff -- agent-log-test.el > /tmp/al-t5.patch  # trim to your hunks
git apply --cached /tmp/al-t5.patch
git commit -m "agent-log: drop live heuristics that read pre-rename artifacts"
```

### Task 6: Documentation and final verification

**Files:**
- Modify: `README.org` (new "Agent integration" section: the optional
  bridge, live-state annotations in the browser, duplicate-safe resume,
  agent-routed resume, standalone behavior unchanged; note the shared
  `agent-history` command on the agent side)
- Regenerate: `agent-log.texi` via ox-texinfo (the file is
  AUTO-GENERATED from README.org)

- [ ] **Step 1: Update README.org and regenerate the manual**

```sh
emacs -Q --batch README.org --eval '(progn (require (quote ox-texinfo)) (org-texinfo-export-to-texinfo))'
```

Note: README.org and agent-log.texi both carry uncommitted summary-sweep
hunks.  The regenerated texi will contain those hunks too (they come from
the org source); when staging, trim your patch to only the hunks belonging
to the new integration section.

- [ ] **Step 2: Full verification in both repos**

```sh
~/My\ Drive/dotfiles/claude/bin/elisp-ert agent-log agent-log-test.el
make compile
cd ../agent && make test && make compile
```

Expected: everything green.

- [ ] **Step 3: Commit (selective staging)**

```sh
git diff -- README.org > /tmp/al-doc.patch      # trim to integration section
git apply --cached /tmp/al-doc.patch
git diff -- agent-log.texi > /tmp/al-texi.patch # trim likewise
git apply --cached /tmp/al-texi.patch
git commit -m "agent-log: document the agent integration"
```

Verify afterwards that `git diff` still shows exactly the summary-sweep
changes in all four files.
