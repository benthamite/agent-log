;;; agent-log.el --- Browse AI coding agent session logs  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Pablo Stafforini

;; Author: Pablo Stafforini
;; URL: https://github.com/benthamite/agent-log
;; Version: 0.3.0
;; Package-Requires: ((emacs "29.1") (markdown-mode "2.6"))
;; Keywords: tools

;; This file is NOT part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Browse and render AI coding agent session logs stored as JSONL files.
;; Supports multiple backends (Claude Code, Codex, etc.) via a generic
;; interface.  Maintains a mirror directory of pre-rendered Markdown
;; files so that standard tools (consult-ripgrep, Dired, grep) work
;; natively on readable content.
;;
;; Entry points:
;;   `agent-log-browse-sessions'    - pick a session from history
;;   `agent-log-open-latest'        - open the most recent session
;;   `agent-log-open-from-session'  - open log for session in current buffer
;;   `agent-log-open-directory'     - browse rendered files in Dired
;;   `agent-log-open-file'          - open a specific JSONL file
;;   `agent-log-resume-session'     - resume session in the coding agent
;;   `agent-log-sync-all'           - render all unrendered/stale sessions

;;; Code:

(require 'cl-lib)
(require 'seq)
(require 'json)
(require 'filenotify)
(require 'outline)
(require 'markdown-mode)
(require 'transient)

;;;;; Soft dependency: gptel (for session summaries)

(defvar gptel-backend)
(defvar gptel-model)
(defvar gptel-use-tools)
(defvar gptel--known-backends)
(declare-function gptel-request "gptel")
(declare-function gptel-get-backend "gptel")
(declare-function gptel-backend-models "gptel")
(declare-function gptel-plus-compute-cost "gptel-plus")

;;;;; Backend framework

(cl-defstruct (agent-log-backend (:constructor nil)
                                  (:copier nil))
  "Base type for agent-log backends.
Each backend represents an AI coding agent (Claude Code, Codex, etc.)
and knows how to discover sessions, parse JSONL entries, and render
conversations."
  (name nil :type string :documentation "Display name, e.g. \"Claude Code\".")
  (key nil :type symbol :documentation "Backend key, e.g. `claude-code'.")
  (directory nil :type string :documentation "Root configuration directory.")
  (rendered-directory nil :type string
                      :documentation "Where rendered Markdown files go.")
  (icon-svg nil :type (or string null)
            :documentation "SVG source string for the backend icon.
Should use \"currentColor\" for fill/stroke to inherit face colors,
or hardcode a brand color (e.g. \"#D97757\").")
  (icon-fallback nil :type (or string null)
                 :documentation "Short text fallback when SVG is unavailable, e.g. \"CC\"."))

;;;;;; Icons

(defun agent-log--svg-icon (svg-data &optional face)
  "Return a propertized string displaying SVG-DATA as an inline icon.
FACE determines the color and height (default `default').
\"currentColor\" in the SVG is replaced with the foreground of FACE.
Returns an empty string when SVG support is unavailable."
  (if (not (image-type-available-p 'svg))
      ""
    (let* ((face (or face 'default))
           (fg (face-foreground face nil t))
           (h (window-font-height nil face))
           (colored (replace-regexp-in-string
                     "currentColor" (or fg "#000") svg-data t t))
           (img (create-image colored 'svg t :height h :ascent 'center)))
      (propertize " " 'display img 'rear-nonsticky '(display)))))

(defun agent-log--backend-icon (backend)
  "Return an icon string for BACKEND.
Uses the SVG icon when available, otherwise the text fallback."
  (if-let* ((svg (agent-log-backend-icon-svg backend))
            (rendered (agent-log--svg-icon svg))
            ((not (string-empty-p rendered))))
      rendered
    (or (agent-log-backend-icon-fallback backend) "")))

;;;;;; Generic functions

(cl-defgeneric agent-log--read-sessions (backend)
  "Return an alist of (SESSION-ID . METADATA) for BACKEND.
METADATA is a plist with at least :display, :timestamp, :project,
:file, and :file-dir.  Sessions are sorted most-recent-first.")

(cl-defgeneric agent-log--build-session-file-index (backend)
  "Return a hash table mapping session IDs to file paths for BACKEND.")

(cl-defgeneric agent-log--find-session-file (backend session-id)
  "Return the JSONL file path for SESSION-ID under BACKEND, or nil.")

(cl-defgeneric agent-log--normalize-entries (backend entries)
  "Convert raw JSONL ENTRIES to the canonical plist format for BACKEND.
Returns a list of normalized entries suitable for the rendering pipeline.")

(cl-defgeneric agent-log--filter-conversation (backend entries)
  "Return only conversation entries from ENTRIES for BACKEND.")

(cl-defgeneric agent-log--conversation-entry-p (backend entry)
  "Return non-nil if ENTRY is a conversation turn for BACKEND.")

(cl-defgeneric agent-log--system-entry-p (backend entry)
  "Return non-nil if ENTRY is a system-generated message for BACKEND.")

(cl-defgeneric agent-log--extract-session-metadata (backend entries)
  "Extract session metadata from ENTRIES for BACKEND.
Returns a plist with :project and :date.")

(cl-defgeneric agent-log--first-user-text (backend entries)
  "Return the text of the first user message in ENTRIES for BACKEND.")

(cl-defgeneric agent-log--summarize-tool-input-by-name (backend name input)
  "Return a one-line summary for tool NAME with INPUT plist for BACKEND.")

(cl-defgeneric agent-log--extract-message-text (backend content)
  "Extract plain text from message CONTENT for BACKEND.")

(cl-defgeneric agent-log--active-session-ids (backend)
  "Return a list of session IDs for live sessions under BACKEND.")

(cl-defgeneric agent-log--resume-session (backend session-id)
  "Resume the session SESSION-ID in the coding agent for BACKEND.")

;;;;; Customization

(defgroup agent-log nil
  "Browse AI coding agent session logs."
  :group 'tools
  :prefix "agent-log-")

(defcustom agent-log-backends
  '((claude-code . agent-log-claude)
    (codex . agent-log-codex))
  "Alist mapping backend key symbols to their feature (file) names.
Each backend file is loaded on first use."
  :type '(alist :key-type symbol :value-type symbol))

(defcustom agent-log-active-backends 'auto
  "Backends to scan for sessions.
A list of backend key symbols, or the symbol `auto' to detect
installed tools by checking for their config directories."
  :type '(choice (const :tag "Auto-detect installed" auto)
                 (repeat :tag "Explicit list" symbol)))

;;;;;; Backend registry

(defvar agent-log--backend-registry (make-hash-table :test #'eq)
  "Hash table mapping backend key symbols to backend struct instances.")

(defun agent-log--register-backend (key instance)
  "Register backend INSTANCE under KEY."
  (puthash key instance agent-log--backend-registry))

(defun agent-log--get-backend (key)
  "Return the backend instance for KEY, loading it if needed.
Returns nil if KEY is not in `agent-log-backends'."
  (or (gethash key agent-log--backend-registry)
      (when-let* ((feature (alist-get key agent-log-backends)))
        (require feature nil t)
        (gethash key agent-log--backend-registry))))

(defun agent-log--detect-backends ()
  "Return a list of backend keys whose directories exist."
  (let (result)
    (pcase-dolist (`(,key . ,_feature) agent-log-backends)
      (when-let* ((instance (agent-log--get-backend key))
                  (dir (agent-log-backend-directory instance)))
        (when (file-directory-p (expand-file-name dir))
          (push key result))))
    (nreverse result)))

(defun agent-log--active-backend-instances ()
  "Return a list of backend instances for all active backends."
  (let ((keys (if (eq agent-log-active-backends 'auto)
                  (agent-log--detect-backends)
                agent-log-active-backends)))
    (delq nil (mapcar #'agent-log--get-backend keys))))

(defun agent-log--read-all-sessions ()
  "Return merged sessions from all active backends, sorted most-recent-first."
  (let ((all '()))
    (dolist (backend (agent-log--active-backend-instances))
      (condition-case err
          (setq all (nconc all (agent-log--read-sessions backend)))
        (error (message "agent-log: failed to read sessions from %s: %s"
                        (agent-log-backend-name backend)
                        (error-message-string err)))))
    (sort all (lambda (a b)
                (agent-log--timestamp>
                 (plist-get (cdr a) :timestamp)
                 (plist-get (cdr b) :timestamp))))))

(defun agent-log--find-session-file-any (session-id)
  "Try all active backends to find SESSION-ID, return file path or nil."
  (cl-loop for backend in (agent-log--active-backend-instances)
           thereis (agent-log--find-session-file backend session-id)))

;;;;;; Forward declarations for agent-log-claude.el

(declare-function agent-log-open-from-session "agent-log-claude")
(declare-function agent-log-rename-sessions "agent-log-claude")
(declare-function agent-log-claude--session-end-handler "agent-log-claude")
(declare-function agent-log-claude--maybe-rename-session "agent-log-claude")
(defvar claude-code-event-hook)

(defcustom agent-log-directory "~/.claude"
  "Root directory of Claude Code configuration.
This variable is used by the Claude Code backend.  In future
versions it will move to `agent-log-claude-directory'."
  :type 'directory)

(defcustom agent-log-rendered-directory "~/.claude/rendered"
  "Directory where rendered Markdown files are stored.
This variable is used by the Claude Code backend.  In future
versions it will move to a backend-specific customization."
  :type 'directory)

(defcustom agent-log-show-thinking 'collapsed
  "How to display assistant thinking blocks.
`hidden' omits them entirely, `collapsed' shows them folded under
a heading, `visible' shows them expanded."
  :type '(choice (const :tag "Hidden" hidden)
                 (const :tag "Collapsed" collapsed)
                 (const :tag "Visible" visible)))

(defcustom agent-log-show-tools 'collapsed
  "How to display tool-use and tool-result sections.
`hidden' omits them entirely, `collapsed' shows them folded under
a heading, `visible' shows them expanded."
  :type '(choice (const :tag "Hidden" hidden)
                 (const :tag "Collapsed" collapsed)
                 (const :tag "Visible" visible)))

(defcustom agent-log-timestamp-format "%Y-%m-%d %H:%M:%S"
  "Format string for timestamps in rendered output."
  :type 'string)

(defcustom agent-log-max-tool-input-length 200
  "Maximum characters to show for tool input summaries."
  :type 'integer)

(defcustom agent-log-max-tool-result-length 500
  "Maximum characters to show for tool result content."
  :type 'integer)

(defcustom agent-log-live-update t
  "Whether to watch the JSONL file for live updates."
  :type 'boolean)

(defcustom agent-log-group-by-project t
  "Whether to group sessions by project in the browser.
When non-nil, `agent-log-browse-sessions' first prompts for a
project, then for a session within that project."
  :type 'boolean)

(defcustom agent-log-display-width 60
  "Maximum width of the first-message column in the session browser."
  :type 'integer)

(defcustom agent-log-slug-max-length 50
  "Maximum length of the slug portion of rendered filenames."
  :type 'integer)

(defcustom agent-log-summary-backend nil
  "The gptel backend name for summary generation, e.g. \"Gemini\" or \"Claude\".
When nil, the backend is inferred from `agent-log-summary-model', falling
back to `gptel-backend'."
  :type '(choice (const :tag "Infer from model or use gptel default" nil)
                 (string :tag "Backend name")))

(defcustom agent-log-summary-model nil
  "The gptel model for summary generation, e.g. `claude-haiku-4-5-20251001'.
When nil, defaults to `gptel-model'."
  :type '(choice (const :tag "Use gptel default" nil)
                 (symbol :tag "Model name")))

(defcustom agent-log-summary-max-content-length 8000
  "Maximum characters of conversation text sent to the LLM for summarization."
  :type 'integer)

(defcustom agent-log-sync-on-session-end nil
  "Whether to sync and summarize when a Claude Code session ends.
When non-nil, `agent-log-sync-all' and `agent-log-summarize-sessions'
run automatically after a session terminates.  Requires the `claude-code'
package and a \"Stop\" hook configured in Claude Code settings."
  :type 'boolean
  :set (lambda (sym val)
         (set-default sym val)
         (if (featurep 'agent-log-claude)
             (if val
                 (add-hook 'claude-code-event-hook #'agent-log-claude--session-end-handler)
               (remove-hook 'claude-code-event-hook #'agent-log-claude--session-end-handler))
           ;; Defer until agent-log-claude is loaded.
           (when val
             (eval-after-load 'agent-log-claude
               '(when agent-log-sync-on-session-end
                  (add-hook 'claude-code-event-hook
                            #'agent-log-claude--session-end-handler)))))))

(defcustom agent-log-auto-rename-sessions nil
  "When non-nil, rename sessions automatically after summarization.
Each time a session receives an AI summary, its one-line summary
is slugified and written as a custom-title entry in the session
JSONL file, making it visible in Claude Code's /resume picker."
  :type 'boolean)

;;;;; AI search

(defcustom agent-log-search-scope-backend nil
  "The gptel backend name for search scope narrowing (stage 1).
When nil, the backend is inferred from `agent-log-search-scope-model',
falling back to `gptel-backend'."
  :type '(choice (const :tag "Infer from model or use gptel default" nil)
                 (string :tag "Backend name")))

(defcustom agent-log-search-scope-model nil
  "The gptel model for search scope narrowing (stage 1).
When nil, defaults to `gptel-model'.  A small, fast model (e.g.
`claude-haiku-4-5-20251001') is recommended."
  :type '(choice (const :tag "Use gptel default" nil)
                 (symbol :tag "Model name")))

(defcustom agent-log-search-backend nil
  "The gptel backend name for search selection (stage 2).
When nil, the backend is inferred from `agent-log-search-model',
falling back to `gptel-backend'."
  :type '(choice (const :tag "Infer from model or use gptel default" nil)
                 (string :tag "Backend name")))

(defcustom agent-log-search-model nil
  "The gptel model for search selection (stage 2).
When nil, defaults to `gptel-model'."
  :type '(choice (const :tag "Use gptel default" nil)
                 (symbol :tag "Model name")))

(defcustom agent-log-search-budget '(tokens . 50000)
  "Per-request budget threshold for AI search, as a (TYPE . LIMIT) cons cell.
TYPE is `tokens' or `dollars'.

Before stage 2, the estimated cost of the prompt is compared to
this threshold.  If it exceeds the limit, the user is asked to
confirm via `y-or-n-p'.

In `tokens' mode, usage is estimated heuristically at one token
per four characters.  In `dollars' mode, cost estimation requires
the `gptel-plus' package; if unavailable, the budget is not enforced."
  :type '(choice (cons :tag "Token limit" (const :tag "" tokens) integer)
                 (cons :tag "Dollar limit" (const :tag "" dollars) number)))

;;;;; Internal variables

(defvar-local agent-log--backend nil
  "Backend instance for the current buffer.
Set when a session is opened so that buffer-local operations
\(live updates, rendering, resume) dispatch to the correct backend.")

(defvar-local agent-log--source-file nil
  "Path to the JSONL file being displayed.")

(defvar-local agent-log--file-offset 0
  "Byte offset into the JSONL file for incremental reads.")

(defvar-local agent-log--partial-line ""
  "Leftover partial line from the last incremental read.")

(defvar-local agent-log--partial-bytes nil
  "Unibyte string of leftover bytes from an incomplete UTF-8 sequence.
When a chunk boundary splits a multi-byte character, the trailing
bytes are saved here and prepended to the next raw read.")

(defvar-local agent-log--watcher nil
  "File-notify descriptor for live updates.")

(defvar-local agent-log--session-project nil
  "Project name for the current session.")

(defvar-local agent-log--session-date nil
  "Date string for the current session.")

(defvar-local agent-log--session-id nil
  "Session ID (UUID) for the current buffer.")

(defvar-local agent-log--rendered-file nil
  "Path to the rendered .md file for the current session.")

(defvar agent-log--summarize-active nil
  "Non-nil when summary generation is in progress.")

(defvar agent-log--summarize-stop nil
  "When non-nil, stop summary generation after the current request.")

(defvar agent-log--summarize-generation 0
  "Generation counter for summary runs.
Incremented each time `agent-log-summarize-sessions' starts a new run.
Callbacks and timers from a previous generation are ignored, preventing
stale callbacks from forking duplicate chains.")

(defvar agent-log--summarize-request-id nil
  "Nonce for the current in-flight gptel request.
Set before each `gptel-request' and consumed by the first callback
invocation.  Subsequent callbacks for the same request see a mismatch
and are silently ignored, preventing chain forking from streaming.")

;; Concurrency control for async summary generation
;; -------------------------------------------------
;; `agent-log--summarize-generation' and `agent-log--summarize-request-id'
;; work together to prevent duplicate chains.  gptel may invoke a callback
;; multiple times (e.g. partial streaming chunks), and any callback that
;; schedules the next request can fork the chain.  The generation counter
;; invalidates an entire run when the user stops or restarts, while the
;; request-id nonce ensures only the *first* callback per request advances
;; the chain.  Both must match for a callback to take effect.

(defvar agent-log--search-sessions-cache nil
  "Cached sessions alist for the current search.
Used when following links in the result buffer.")

(defvar agent-log--search-index-cache nil
  "Cached index hash table for the current search.
Used when following links in the result buffer.")

(defun agent-log--default-backend ()
  "Return the buffer-local backend, or the first active backend."
  (or agent-log--backend (car (agent-log--active-backend-instances))))

(defun agent-log--backend-for-file (file)
  "Return the backend whose directory contains FILE, or the default backend."
  (let ((file (expand-file-name file)))
    (or (cl-loop for backend in (agent-log--active-backend-instances)
                 when (let ((dir (expand-file-name
                                  (agent-log-backend-directory backend))))
                        (string-prefix-p dir file))
                 return backend)
        (agent-log--default-backend))))

;;;;; Entry points

;;;###autoload
(defun agent-log-browse-sessions ()
  "Browse sessions and open the selected one.
When `agent-log-group-by-project' is non-nil, first prompts for
a project, then for a session within that project."
  (interactive)
  (let ((sessions (agent-log--read-all-sessions)))
    (if agent-log-group-by-project
        (agent-log--browse-grouped sessions)
      (agent-log--browse-flat sessions))))

;;;###autoload
(defun agent-log-open-file (file)
  "Open and render the JSONL session log at FILE."
  (interactive "fJSONL file: ")
  (let* ((file (expand-file-name file))
         (backend (agent-log--backend-for-file file))
         (session-id (file-name-sans-extension (file-name-nondirectory file)))
         (entries (agent-log--parse-and-normalize file backend))
         (first-msg (agent-log--find-first-message entries))
         (progress (agent-log--find-progress-entry entries))
         (ts-iso (when first-msg (plist-get first-msg :timestamp)))
         (epoch-ms (when (stringp ts-iso)
                     (agent-log--iso-to-epoch-ms ts-iso)))
         (display (or (and backend
                           (agent-log--first-user-text backend entries))
                      ""))
         (project (when progress (or (plist-get progress :cwd) "")))
         (metadata (list :file file
                         :timestamp epoch-ms
                         :project (or project "")
                         :display display
                         :backend backend)))
    (agent-log--open-rendered session-id metadata)))

;;;###autoload
(defun agent-log-open-latest ()
  "Open the most recent session."
  (interactive)
  (let ((sessions (agent-log--read-all-sessions)))
    (unless sessions
      (user-error "No sessions found"))
    (let* ((latest (car sessions))
           (session-id (car latest))
           (metadata (cdr latest)))
      (agent-log--open-rendered session-id metadata))))

;;;###autoload
(defun agent-log-open-directory ()
  "Open the rendered Markdown directory in Dired."
  (interactive)
  (let ((dir (expand-file-name agent-log-rendered-directory)))
    (unless (file-directory-p dir)
      (make-directory dir t))
    (dired dir)))

;;;###autoload
(defun agent-log-open-session (session-id)
  "Open the session with SESSION-ID."
  (interactive "sSession ID: ")
  (let ((file (agent-log--find-session-file-any session-id)))
    (unless file
      (user-error "No JSONL file found for session %s" session-id))
    (agent-log-open-file file)))

;;;###autoload
(defun agent-log-sync-all (&optional callback)
  "Render all unrendered or stale sessions.
Uses timers to avoid blocking Emacs.  When CALLBACK is non-nil,
call it with no arguments after the last session is rendered."
  (interactive)
  (let* ((sessions (agent-log--read-all-sessions))
         (index (agent-log--read-index))
         (pending (agent-log--pending-sessions sessions index)))
    (if (null pending)
        (progn
          (message "All %d sessions up to date" (length sessions))
          (when callback (funcall callback)))
      (message "Syncing %d session(s)..." (length pending))
      (agent-log--sync-next pending 0 (length pending) callback))))

(defun agent-log--pending-sessions (sessions index)
  "Return sessions from SESSIONS that need rendering per INDEX."
  (seq-filter
   (lambda (session)
     (let* ((sid (car session))
            (meta (cdr session))
            (entry (gethash sid index))
            (rpath (when entry (plist-get entry :file)))
            (csize (when entry (plist-get entry :jsonl-size)))
            (jfile (plist-get meta :file))
            (jsize (file-attribute-size (file-attributes jfile))))
       (not (and rpath (file-exists-p rpath) csize jsize (= csize jsize)))))
   sessions))

(defun agent-log--sync-next (remaining done total &optional callback)
  "Render the next session in REMAINING.
DONE sessions rendered so far out of TOTAL.  When CALLBACK is
non-nil, call it with no arguments after the last session."
  (if (null remaining)
      (progn
        (message "Sync complete: rendered %d session(s)" total)
        (when callback (funcall callback)))
    (let* ((session (car remaining))
           (sid (car session))
           (meta (cdr session)))
      (condition-case err
          (let ((result (agent-log--render-to-file sid meta)))
            (agent-log--index-update-props
             sid (list :file (car result) :jsonl-size (cdr result))))
        (error (message "Failed to render %s: %s"
                        sid (error-message-string err))))
      ;; Yield to the event loop between sessions to keep Emacs responsive
      ;; and avoid deep recursion when processing hundreds of sessions.
      (run-with-timer 0 nil #'agent-log--sync-next
                      (cdr remaining) (1+ done) total callback))))

(defun agent-log--activate-mode ()
  "Activate `agent-log-mode' with parent mode hooks suppressed.
Suppresses `markdown-mode-hook' and `markdown-view-mode-hook' (which
may set up editing-oriented features inappropriate for a read-only
rendered buffer) and flycheck's global-mode hook (which would try to
lint the rendered Markdown as if it were a source file, triggering
spurious checker errors and background processes)."
  (let ((markdown-mode-hook nil)
        (markdown-view-mode-hook nil)
        (after-change-major-mode-hook
         (remq 'flycheck-global-mode-enable-in-buffers
               after-change-major-mode-hook)))
    (agent-log-mode)))

;;;;; Index file

(defun agent-log--index-file ()
  "Return the path to the rendered-directory index file."
  (expand-file-name "_index.el" agent-log-rendered-directory))

(defun agent-log--read-index ()
  "Read the index hash table from disk.
Returns an empty hash table if the file does not exist or is corrupt."
  (let ((file (agent-log--index-file)))
    (condition-case err
        (if (file-exists-p file)
            (let ((obj (with-temp-buffer
                         (insert-file-contents file)
                         (read (current-buffer)))))
              (if (hash-table-p obj) obj
                (message "agent-log: index file corrupt (not a hash table), rebuilding")
                (make-hash-table :test #'equal)))
          (make-hash-table :test #'equal))
      (error
       (message "agent-log: failed to read index: %s" (error-message-string err))
       (make-hash-table :test #'equal)))))

(defun agent-log--write-index (index)
  "Write INDEX hash table to disk atomically.
Writes to a temporary file first, then renames to avoid corruption
if Emacs crashes mid-write."
  (let* ((file (agent-log--index-file))
         (dir (file-name-directory file)))
    (make-directory dir t)
    (let ((tmp (make-temp-file (expand-file-name "_index-tmp" dir) nil ".el")))
      (condition-case err
          (progn
            (with-temp-file tmp
              (let ((print-level nil)
                    (print-length nil))
                (prin1 index (current-buffer))
                (insert "\n")))
            (rename-file tmp file t))
        (error
         (ignore-errors (delete-file tmp))
         (signal (car err) (cdr err)))))))

(defun agent-log--index-merge (index session-id props)
  "Merge PROPS into the INDEX entry for SESSION-ID.
Existing properties not in PROPS are preserved."
  (let ((existing (or (gethash session-id index) '())))
    (cl-loop for (key val) on props by #'cddr
             do (setq existing (plist-put existing key val)))
    (puthash session-id existing index)))

(defun agent-log--index-update-props (session-id props)
  "Atomically merge PROPS into the disk index entry for SESSION-ID.
Reads the current index from disk, merges PROPS, and writes back,
ensuring concurrent operations do not clobber each other."
  (let ((index (agent-log--read-index)))
    (agent-log--index-merge index session-id props)
    (agent-log--write-index index)))

(defun agent-log--index-update (session-id rendered-path jsonl-size)
  "Update the index entry for SESSION-ID with RENDERED-PATH and JSONL-SIZE."
  (agent-log--index-update-props
   session-id (list :file rendered-path :jsonl-size jsonl-size)))

;;;;; Slug and filepath

(defun agent-log--slugify (text)
  "Convert TEXT to a filename-safe slug.
Lowercases, replaces non-alphanumeric runs with hyphens,
and truncates to `agent-log-slug-max-length'."
  (let* ((slug (downcase (or text "")))
         (slug (replace-regexp-in-string "[^a-z0-9]+" "-" slug))
         (slug (replace-regexp-in-string "\\`-+\\|-+\\'" "" slug))
         (slug (if (> (length slug) agent-log-slug-max-length)
                   (substring slug 0 agent-log-slug-max-length)
                 slug)))
    (if (string-empty-p slug) "untitled" slug)))

(defun agent-log--rendered-filepath (_session-id metadata)
  "Compute the rendered .md filepath for a session.
METADATA is a plist with :timestamp, :project, :display."
  (let* ((ts (plist-get metadata :timestamp))
         (date-str (if (numberp ts)
                       (format-time-string "%Y-%m-%d_%H-%M"
                                           (seconds-to-time (/ ts 1000.0)))
                     "unknown"))
         (display (or (plist-get metadata :display) ""))
         (slug (agent-log--slugify display))
         (project (agent-log--short-project
                   (or (plist-get metadata :project) "")))
         (project-dir (expand-file-name project agent-log-rendered-directory))
         (filename (format "%s_%s.md" date-str slug)))
    (expand-file-name filename project-dir)))

(defun agent-log--iso-to-epoch-ms (ts)
  "Convert ISO 8601 timestamp TS to epoch milliseconds."
  (condition-case nil
      (truncate (* (float-time (date-to-time ts)) 1000))
    (error nil)))

;;;;; Render to file

(defun agent-log--render-front-matter (session-id jsonl-file jsonl-size)
  "Generate front matter comments for a rendered file.
SESSION-ID is the UUID, JSONL-FILE the source path,
JSONL-SIZE the source file size in bytes."
  (format (concat "<!-- session: %s -->\n"
                  "<!-- source: %s -->\n"
                  "<!-- rendered: %s -->\n"
                  "<!-- jsonl-size: %d -->\n\n")
          session-id
          jsonl-file
          (format-time-string "%Y-%m-%dT%H:%M:%S")
          (or jsonl-size 0)))

(defun agent-log--extract-session-metadata-from-entries (entries)
  "Extract project and date from ENTRIES as a plist.
Returns (:project SHORT-NAME :date DATE-STRING)."
  (let* ((first-msg (agent-log--find-first-message entries))
         (progress (agent-log--find-progress-entry entries))
         (date (when first-msg
                 (agent-log--format-iso-timestamp
                  (plist-get first-msg :timestamp))))
         (project (when progress (or (plist-get progress :cwd) ""))))
    (list :project (agent-log--short-project (or project ""))
          :date (or date "unknown"))))

(defun agent-log--render-to-file (session-id metadata &optional output-path)
  "Render the JSONL for SESSION-ID to a Markdown file.
METADATA is a plist with :file, :timestamp, :project, :display.
If OUTPUT-PATH is given, write there; otherwise compute from METADATA.
Returns (RENDERED-PATH . JSONL-SIZE)."
  (let* ((jsonl-file (plist-get metadata :file))
         (backend (or (plist-get metadata :backend)
                      (agent-log--default-backend)))
         (entries (agent-log--parse-and-normalize jsonl-file backend))
         (conversation (if backend
                           (agent-log--filter-conversation backend entries)
                         entries))
         (rendered-path (or output-path
                            (agent-log--rendered-filepath session-id metadata)))
         (jsonl-size (file-attribute-size (file-attributes jsonl-file)))
         (session-meta (agent-log--extract-session-metadata-from-entries
                        entries)))
    (make-directory (file-name-directory rendered-path) t)
    (with-temp-file rendered-path
      (insert (agent-log--render-front-matter
               session-id jsonl-file jsonl-size))
      (let ((project (plist-get session-meta :project)))
        (when (equal project "unknown")
          (setq project (agent-log--short-project
                         (or (plist-get metadata :project) ""))))
        (insert (format "# Session: %s — %s\n\n"
                        project
                        (plist-get session-meta :date))))
      (dolist (entry conversation)
        (insert (agent-log--render-entry entry backend))))
    (cons rendered-path jsonl-size)))

(defun agent-log--ensure-rendered (session-id metadata)
  "Ensure SESSION-ID has an up-to-date rendered .md file.
METADATA is a plist with :file, :timestamp, :project, :display.
Returns the path to the rendered file."
  (let* ((index (agent-log--read-index))
         (index-entry (gethash session-id index))
         (rendered-path (when index-entry (plist-get index-entry :file)))
         (cached-size (when index-entry (plist-get index-entry :jsonl-size)))
         (jsonl-file (plist-get metadata :file))
         (current-size (file-attribute-size (file-attributes jsonl-file))))
    (if (and rendered-path
             (file-exists-p rendered-path)
             cached-size current-size
             (= cached-size current-size))
        rendered-path
      (let ((result (agent-log--render-to-file session-id metadata)))
        (agent-log--index-update-props
         session-id (list :file (car result) :jsonl-size (cdr result)))
        (car result)))))

(defun agent-log--open-rendered (session-id metadata)
  "Open the rendered .md file for SESSION-ID.
METADATA is a plist with :file, :timestamp, :project, :display."
  (let* ((rendered-path (agent-log--ensure-rendered session-id metadata))
         (buf (find-file-noselect rendered-path)))
    (with-current-buffer buf
      (agent-log--activate-mode)
      (setq agent-log--source-file (plist-get metadata :file)
            agent-log--session-id session-id
            agent-log--rendered-file rendered-path
            agent-log--session-project (plist-get metadata :project)
            agent-log--backend (or (plist-get metadata :backend)
                                   (agent-log--default-backend)))
      (agent-log--record-offset)
      (when (and agent-log-live-update (not agent-log--watcher))
        (agent-log--start-watcher))
      (agent-log--collapse-as-configured)
      (agent-log--maybe-insert-summary session-id)
      (goto-char (point-min))
      (set-buffer-modified-p nil))
    (pop-to-buffer buf)))

(defun agent-log--append-to-file (file text)
  "Append TEXT to FILE on disk."
  (write-region text nil file t 'quiet))

;;;;; Session browser

(defun agent-log--browse-flat (sessions)
  "Present all SESSIONS in a single `completing-read'."
  (let* ((candidates (agent-log--build-candidates sessions))
         (selected (agent-log--completing-read "Session: " candidates))
         (value (alist-get selected candidates nil nil #'equal))
         (session-id (car value))
         (metadata (cdr value)))
    (agent-log--open-rendered session-id metadata)))

(defun agent-log--browse-grouped (sessions)
  "Present SESSIONS grouped by project: first pick project, then session."
  (let* ((grouped (agent-log--group-by-project sessions))
         (project-names (mapcar #'car grouped))
         (project (agent-log--completing-read "Project: " project-names))
         (project-sessions (alist-get project grouped nil nil #'equal))
         (candidates (agent-log--build-candidates project-sessions))
         (selected (agent-log--completing-read "Session: " candidates))
         (value (alist-get selected candidates nil nil #'equal))
         (session-id (car value))
         (metadata (cdr value)))
    (agent-log--open-rendered session-id metadata)))

(defun agent-log--completing-read (prompt collection)
  "Read from COLLECTION with PROMPT, preserving display order."
  (completing-read prompt
                   (agent-log--preserve-order-table collection)
                   nil t))

(defun agent-log--group-by-project (sessions)
  "Group SESSIONS into an alist of (project-name . sessions).
Groups by the full :project path so sessions that share a
project stay together even across file directories.
Projects are sorted by most recent session timestamp."
  (let ((groups (make-hash-table :test #'equal)))
    (dolist (session sessions)
      (let* ((project (or (plist-get (cdr session) :project) ""))
             (existing (gethash project groups)))
        (puthash project (append existing (list session)) groups)))
    (let* ((full-paths (hash-table-keys groups))
           (display-names (agent-log--unique-project-names full-paths))
           result)
      (maphash (lambda (project group-sessions)
                 (let ((name (cdr (assoc project display-names))))
                   (push (cons name group-sessions) result)))
               groups)
      ;; Sort by most recent session timestamp.
      ;; Each element is (project (sid . plist) ...), so cadr is the
      ;; first session and cdadr is its metadata plist.
      (sort result (lambda (a b)
                     (agent-log--timestamp>
                      (plist-get (cdadr a) :timestamp)
                      (plist-get (cdadr b) :timestamp)))))))

(defun agent-log--build-candidates (sessions)
  "Build an alist of (display-string . (session-id . metadata)) from SESSIONS."
  (let* ((index (agent-log--read-index))
         (proj-width (agent-log--max-project-width sessions))
         ;; Icon column: SVG renders as 1 char, text fallback is typically 2.
         (icon-width (if (image-type-available-p 'svg) 1 2))
         ;; icon + gap + date (16) + 2 gaps (2+2) + project = fixed cols
         (fixed-cols (+ icon-width 1 16 2 proj-width 2))
         ;; Ensure the summary column is wide enough to be useful even
         ;; in narrow frames; below ~20 chars summaries become unreadable.
         (summary-width (max 20 (- (frame-width) fixed-cols 1)))
         (fmt (format "%%s  %%-%ds  %%s" proj-width)))
    (mapcar
     (lambda (session)
       (let* ((session-id (car session))
              (meta (cdr session))
              (backend (plist-get meta :backend))
              (icon (if backend (agent-log--backend-icon backend) ""))
              (ts (plist-get meta :timestamp))
              (date (agent-log--format-epoch-ms ts))
              (project (agent-log--short-project (plist-get meta :project)))
              (index-entry (gethash session-id index))
              (oneline (when index-entry
                         (plist-get index-entry :summary-oneline)))
              (body (if oneline
                        (format fmt date project
                                (agent-log--truncate-string
                                 oneline summary-width))
                      (let ((display (agent-log--normalize-whitespace
                                       (plist-get meta :display))))
                        (format fmt date project
                                (concat "\"" (agent-log--truncate-string
                                              display (- summary-width 2))
                                        "\"")))))
              (label (concat icon " " body)))
         (cons label (cons session-id meta))))
     sessions)))

(defun agent-log--max-project-width (sessions)
  "Return the maximum display width of project names in SESSIONS."
  (let ((max-w 0))
    (dolist (session sessions max-w)
      (let* ((project (agent-log--short-project
                       (plist-get (cdr session) :project)))
             (w (string-width project)))
        (when (> w max-w) (setq max-w w))))))

(defun agent-log--short-project (path)
  "Extract a short project name from PATH."
  (if (or (null path) (string-empty-p path))
      "unknown"
    (file-name-nondirectory (directory-file-name path))))

(defun agent-log--unique-project-names (paths)
  "Return an alist of (PATH . DISPLAY-NAME) with unique display names for PATHS.
Short names are used when unique; parent/name when collisions occur."
  (let ((counts (make-hash-table :test #'equal)))
    (dolist (path paths)
      (cl-incf (gethash (agent-log--short-project path) counts 0)))
    (mapcar (lambda (path)
              (let ((short (agent-log--short-project path)))
                (cons path
                      (if (> (gethash short counts) 1)
                          (agent-log--long-project-name path)
                        short))))
            paths)))

(defun agent-log--long-project-name (path)
  "Return a parent/name string from PATH for disambiguation."
  (if (or (null path) (string-empty-p path))
      "unknown"
    (let* ((dir (directory-file-name path))
           (name (file-name-nondirectory dir))
           (parent-dir (file-name-directory dir))
           (parent (when parent-dir
                     (file-name-nondirectory
                      (directory-file-name parent-dir)))))
      (if (and parent (not (string-empty-p parent)))
          (format "%s/%s" parent name)
        name))))

(defun agent-log--format-epoch-ms (ms)
  "Format millisecond epoch timestamp MS as a date-time string."
  (if (numberp ms)
      (format-time-string "%Y-%m-%d %H:%M" (seconds-to-time (/ ms 1000.0)))
    "unknown"))

;;;;; JSONL parsing

(defun agent-log--parse-jsonl-file (file)
  "Parse FILE as JSONL, returning a list of plists.
Malformed lines are silently skipped."
  (let ((lines (agent-log--read-file-lines file)))
    (delq nil
          (mapcar (lambda (line)
                    (condition-case nil
                        (agent-log--parse-json-line line)
                      (error nil)))
                  lines))))

(defun agent-log--parse-and-normalize (file &optional backend)
  "Parse FILE as JSONL and normalize entries using BACKEND.
When BACKEND is nil, uses `agent-log--default-backend'.
Normalization converts backend-specific formats to the canonical
agent-log format (e.g. Codex envelopes to flat entries)."
  (let ((entries (agent-log--parse-jsonl-file file))
        (backend (or backend (agent-log--default-backend))))
    (if backend
        (agent-log--normalize-entries backend entries)
      entries)))

(defun agent-log--read-file-lines (file)
  "Read FILE and return a list of non-empty lines."
  (with-temp-buffer
    (insert-file-contents file)
    (split-string (buffer-string) "\n" t)))

(defun agent-log--parse-json-line (line)
  "Parse a single JSON LINE into a plist."
  (json-parse-string line :object-type 'plist :array-type 'list))

;;;;; Entry helpers

(defun agent-log--find-first-message (entries)
  "Return the first user or assistant entry from ENTRIES."
  (seq-find (lambda (e) (member (plist-get e :type) '("user" "assistant")))
            entries))

(defun agent-log--find-progress-entry (entries)
  "Return the first progress entry from ENTRIES."
  (seq-find (lambda (e) (equal (plist-get e :type) "progress"))
            entries))

;;;;; Rendering

(defun agent-log--render-full ()
  "Render the full JSONL file into the current buffer."
  (let* ((backend agent-log--backend)
         (entries (agent-log--parse-and-normalize agent-log--source-file backend))
         (conversation (if backend
                           (agent-log--filter-conversation backend entries)
                         entries)))
    (when backend
      (agent-log--extract-session-metadata backend entries))
    (let ((inhibit-read-only t))
      (erase-buffer)
      (insert (agent-log--render-header))
      (dolist (entry conversation)
        (insert (agent-log--render-entry entry backend)))
      (agent-log--record-offset)
      (goto-char (point-min))
      (agent-log--collapse-as-configured))))

(defun agent-log--render-header ()
  "Return the Markdown header for the session."
  (let ((project (agent-log--short-project
                  (or agent-log--session-project "")))
        (date (or agent-log--session-date "unknown")))
    (format "# Session: %s — %s\n\n" project date)))

(defun agent-log--render-entry (entry &optional backend)
  "Render a single conversation ENTRY to a Markdown string.
BACKEND is passed through to tool-use rendering for dispatch."
  (let ((message (plist-get entry :message)))
    (if (not message)
        ""
      (let* ((timestamp (plist-get entry :timestamp))
             (role (plist-get message :role))
             (content (plist-get message :content))
             (time-str (agent-log--format-iso-timestamp timestamp)))
        (cond
         ((equal role "user")
          (agent-log--render-user-turn content time-str))
         ((equal role "assistant")
          (agent-log--render-assistant-turn content time-str backend))
         (t ""))))))

(defun agent-log--render-user-turn (content time-str)
  "Render a user turn with CONTENT and TIME-STR.
If CONTENT contains only tool results and no user text, render
them without a User heading."
  (if (stringp content)
      (format "---\n\n## User — %s\n\n%s\n\n" time-str content)
    (let ((text-parts (agent-log--collect-user-text content))
          (tool-parts (agent-log--collect-tool-results content)))
      (cond
       (text-parts
        (concat (format "---\n\n## User — %s\n\n" time-str)
                (string-join text-parts)
                (string-join tool-parts)))
       (tool-parts
        (string-join tool-parts))
       (t "")))))

(defun agent-log--collect-user-text (content)
  "Collect non-empty text parts from user CONTENT array.
Returns a list of formatted strings, or nil if there is no text."
  (let (parts)
    (dolist (item content)
      (when (equal (plist-get item :type) "text")
        (let ((text (plist-get item :text)))
          (when (and text (not (string-empty-p (string-trim text))))
            (push (format "%s\n\n" text) parts)))))
    (nreverse parts)))

(defun agent-log--collect-tool-results (content)
  "Collect tool result parts from user CONTENT array.
Returns a list of formatted strings, or nil if there are none."
  (let (parts)
    (dolist (item content)
      (when (equal (plist-get item :type) "tool_result")
        (push (agent-log--render-tool-result item) parts)))
    (nreverse parts)))

(defun agent-log--render-assistant-turn (content time-str &optional backend)
  "Render an assistant turn with CONTENT and TIME-STR.
BACKEND is passed through for tool-use dispatch.
Returns an empty string if CONTENT produces no visible output."
  (let ((body (agent-log--render-assistant-body content backend)))
    (if (string-empty-p body)
        ""
      (concat (format "---\n\n## Assistant — %s\n\n" time-str) body))))

(defun agent-log--render-assistant-body (content &optional backend)
  "Render the body of an assistant turn from CONTENT items.
BACKEND is passed through for tool-use dispatch."
  (let ((parts '()))
    (when (listp content)
      (dolist (item content)
        (let ((item-type (plist-get item :type)))
          (cond
           ((equal item-type "thinking")
            (push (agent-log--render-thinking item) parts))
           ((equal item-type "text")
            (let ((text (plist-get item :text)))
              (when (and text (not (string-empty-p (string-trim text))))
                (push (format "%s\n\n" text) parts))))
           ((equal item-type "tool_use")
            (push (agent-log--render-tool-use item backend) parts))))))
    (apply #'concat (nreverse parts))))

(defun agent-log--render-thinking (item)
  "Render a thinking ITEM.
Returns an empty string when the thinking text is empty, which
happens when Claude Code redacts thinking content from the JSONL."
  (let ((text (or (plist-get item :thinking) "")))
    (if (string-empty-p (string-trim text))
        ""
      (let* ((truncated (agent-log--truncate-string text agent-log-max-tool-result-length))
             (clean (replace-regexp-in-string "\n\n+" "\n" truncated)))
        (format "#### Thinking\n\n%s\n\n" clean)))))

(defun agent-log--render-tool-use (item &optional backend)
  "Render a tool_use ITEM with a smart summary of its input.
BACKEND is used for backend-specific tool summarization."
  (let* ((name (plist-get item :name))
         (input (plist-get item :input))
         (summary (agent-log--summarize-tool-input name input backend)))
    (format "#### Tool: %s\n\n%s\n\n" name summary)))

(defun agent-log--render-tool-result (item)
  "Render a tool_result ITEM."
  (let* ((content (plist-get item :content))
         (text (agent-log--extract-tool-result-text content))
         (truncated (agent-log--truncate-string text agent-log-max-tool-result-length)))
    (format "#### Tool result\n\n> %s\n\n"
            (string-replace "\n" "\n> " truncated))))

(defun agent-log--extract-tool-result-text (content)
  "Extract text from tool result CONTENT, which may be a string or list."
  (cond
   ((stringp content) content)
   ((listp content)
    (mapconcat
     (lambda (item)
       (if (equal (plist-get item :type) "text")
           (plist-get item :text)
         ""))
     content
     "\n"))
   (t "")))

;;;;; Tool input summaries

(defun agent-log--summarize-tool-input (name input &optional backend)
  "Return a concise summary of INPUT for tool NAME.
When BACKEND is non-nil, dispatch to the backend-specific summarizer."
  (let* ((backend (or backend agent-log--backend))
         (summary (if backend
                      (agent-log--summarize-tool-input-by-name backend name input)
                    "")))
    (if (string-empty-p summary)
        (agent-log--summarize-tool-input-generic input)
      summary)))

(defun agent-log--summarize-tool-input-generic (input)
  "Return a generic summary of tool INPUT plist.
Returns an empty string if INPUT is not a proper plist."
  (if (not (and (listp input) (cl-evenp (length input))))
      ""
    (let ((parts '()))
      (cl-loop for (key val) on input by #'cddr
               when (keywordp key)
               do (let* ((k (substring (symbol-name key) 1))
                         (v (agent-log--truncate-string
                             (format "%s" val)
                             agent-log-max-tool-input-length)))
                    (push (format "> **%s**: %s" k v) parts)))
      (string-join (nreverse parts) "\n"))))

;;;;; Timestamps

(defun agent-log--format-iso-timestamp (ts)
  "Format ISO 8601 timestamp TS according to `agent-log-timestamp-format'."
  (if (and (stringp ts) (not (string-empty-p ts)))
      (agent-log--parse-and-format-iso ts)
    "unknown"))

(defun agent-log--parse-and-format-iso (ts)
  "Parse ISO 8601 string TS and format it."
  (condition-case nil
      (let ((time (date-to-time ts)))
        (format-time-string agent-log-timestamp-format time))
    (error ts)))

;;;;; Utilities

(defun agent-log--timestamp> (a b)
  "Return non-nil if timestamp A is more recent than B.
Handles non-numeric values by treating them as 0."
  (> (if (numberp a) a 0)
     (if (numberp b) b 0)))

(defun agent-log--preserve-order-table (collection)
  "Wrap COLLECTION in a completion table that preserves display order.
COLLECTION is a list of strings or an alist of (string . value)."
  (lambda (string pred action)
    (if (eq action 'metadata)
        '(metadata (display-sort-function . identity)
                   (cycle-sort-function . identity))
      (complete-with-action action collection string pred))))

(defun agent-log--normalize-whitespace (str)
  "Collapse all whitespace in STR into single spaces and trim."
  (string-trim (replace-regexp-in-string "[\n\r\t ]+" " " (or str ""))))

(defun agent-log--truncate-string (str max)
  "Truncate STR to MAX characters, appending ellipsis if needed."
  (if (<= (length str) max)
      str
    (concat (substring str 0 max) "…")))

;;;;; Major mode

(defvar agent-log-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "n" #'agent-log-next-turn)
    (define-key map "p" #'agent-log-previous-turn)
    (define-key map (kbd "TAB") #'agent-log-toggle-section)
    (define-key map "C" #'agent-log-collapse-all)
    (define-key map "E" #'agent-log-expand-all)
    (define-key map "g" #'agent-log-refresh)
    (define-key map "w" #'agent-log-copy-turn)
    (define-key map "r" #'agent-log-resume-session)
    (define-key map "?" #'agent-log-menu)
    (define-key map "q" #'quit-window)
    map)
  "Keymap for `agent-log-mode'.")

(define-derived-mode agent-log-mode markdown-view-mode "Agent-Log"
  "Major mode for viewing AI coding agent session logs.
\\{agent-log-mode-map}"
  (setq-local outline-regexp "##+ ")
  (setq-local outline-level #'agent-log--outline-level)
  (outline-minor-mode 1)
  ;; Collapsed sections show an ellipsis (the `t' in the cons cell) so
  ;; the user knows there is hidden content they can expand.  Hidden
  ;; sections vanish entirely with no visual indicator.
  (add-to-invisibility-spec '(agent-log-collapsed . t))
  (add-to-invisibility-spec 'agent-log-hidden)
  (add-hook 'kill-buffer-hook #'agent-log--cleanup nil t))

(defun agent-log--outline-level ()
  "Return the outline level based on the number of `#' characters."
  (- (match-end 0) (match-beginning 0) 1))

(defun agent-log--cleanup ()
  "Clean up file watcher and update index when buffer is killed."
  (when agent-log--watcher
    (file-notify-rm-watch agent-log--watcher)
    (setq agent-log--watcher nil))
  (when (and agent-log--session-id agent-log--rendered-file agent-log--source-file)
    (let ((final-size (file-attribute-size
                       (file-attributes agent-log--source-file))))
      (when final-size
        (agent-log--index-update agent-log--session-id
                                  agent-log--rendered-file
                                  final-size)))))

;;;;; Live updates

(defun agent-log--record-offset ()
  "Record the current byte size of the source file."
  (when agent-log--source-file
    (setq agent-log--file-offset
          (file-attribute-size (file-attributes agent-log--source-file)))))

(defun agent-log--start-watcher ()
  "Start watching the JSONL file for change events."
  (setq agent-log--watcher
        (file-notify-add-watch
         agent-log--source-file '(change)
         (let ((buf (current-buffer)))
           (lambda (_event)
             (when (buffer-live-p buf)
               (with-current-buffer buf
                 (agent-log--handle-file-change))))))))

(defun agent-log--handle-file-change ()
  "Handle a change notification on the JSONL file."
  (when (and agent-log--source-file
             (file-exists-p agent-log--source-file))
    (let* ((new-size (file-attribute-size
                      (file-attributes agent-log--source-file)))
           (at-end (>= (point) (point-max))))
      (when (and new-size (> new-size agent-log--file-offset))
        (condition-case err
            (let ((new-text (agent-log--read-bytes-from
                             agent-log--source-file
                             agent-log--file-offset new-size)))
              (setq agent-log--file-offset new-size)
              (agent-log--process-incremental-text new-text at-end))
          (error
           (message "agent-log: error reading incremental update: %s"
                    (error-message-string err))))))))

(defun agent-log--incomplete-utf8-tail-length (unibyte-str)
  "Return the number of trailing bytes that form an incomplete UTF-8 sequence.
UNIBYTE-STR is a unibyte string.  Returns 0 if the string ends on
a complete character boundary."
  (let* ((len (length unibyte-str))
         (i (1- len)))
    (if (< len 1)
        0
      ;; Walk backward past continuation bytes (10xxxxxx).
      (while (and (>= i (max 0 (- len 4)))
                  (= (logand (aref unibyte-str i) #xC0) #x80))
        (cl-decf i))
      (if (< i 0)
          ;; All bytes are continuations — all are leftover.
          ;; Cap at 3: a UTF-8 char is at most 4 bytes (1 lead + 3 continuation).
          (min len 3)
        (let* ((lead (aref unibyte-str i))
               (expected (cond
                          ((< lead #x80) 1)        ; 0xxxxxxx — ASCII
                          ((< lead #xC0) 1)        ; unexpected continuation
                          ((< lead #xE0) 2)        ; 110xxxxx
                          ((< lead #xF0) 3)        ; 1110xxxx
                          ((< lead #xF8) 4)        ; 11110xxx
                          (t 1)))                   ; invalid
               (available (- len i)))
          (if (< available expected)
              available
            0))))))

(defun agent-log--read-bytes-from (file start end)
  "Read bytes from FILE between START and END offsets.
Handles incomplete UTF-8 sequences at chunk boundaries by saving
trailing partial bytes in `agent-log--partial-bytes' and
prepending any previously saved bytes."
  (let ((saved-partial agent-log--partial-bytes)
        result new-partial)
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (when saved-partial
        (insert saved-partial))
      (let ((coding-system-for-read 'raw-text))
        (insert-file-contents file nil start end))
      (let ((tail (agent-log--incomplete-utf8-tail-length
                   (buffer-substring-no-properties (point-min) (point-max)))))
        (if (> tail 0)
            (progn
              (setq new-partial
                    (buffer-substring-no-properties (- (point-max) tail) (point-max)))
              (delete-region (- (point-max) tail) (point-max)))
          (setq new-partial nil))
        (setq result (decode-coding-region (point-min) (point-max) 'utf-8 t))))
    (setq agent-log--partial-bytes new-partial)
    result))

(defun agent-log--process-incremental-text (text at-end)
  "Parse new TEXT from the JSONL file and append rendered entries.
If AT-END is non-nil, scroll to show new content."
  (let* ((combined (concat agent-log--partial-line text))
         (lines (split-string combined "\n")))
    (setq agent-log--partial-line (car (last lines)))
    (let ((complete-lines (butlast lines)))
      (dolist (line complete-lines)
        (unless (string-empty-p line)
          (agent-log--append-rendered-line line))))
    (when at-end
      (goto-char (point-max)))))

(defun agent-log--append-rendered-line (line)
  "Parse LINE as JSON and append its rendering if it is a conversation entry.
Appends to both the buffer and the rendered .md file on disk.
For backends that use an envelope format (e.g. Codex), normalizes the
single entry before checking whether it is a conversation entry."
  (when-let* ((raw (agent-log--try-parse-json line))
              (backend agent-log--backend))
    ;; Normalize: for enveloped formats, convert the single entry.
    ;; The result is a list; for flat formats (Claude), wrap the raw entry.
    (let ((normalized (agent-log--normalize-entries backend (list raw))))
      (dolist (entry normalized)
        (when (agent-log--conversation-entry-p backend entry)
          (let ((rendered (agent-log--render-entry entry backend))
                (inhibit-read-only t))
            (when agent-log--rendered-file
              (agent-log--append-to-file agent-log--rendered-file rendered))
            ;; Sync modtime BEFORE buffer insert to prevent the
            ;; supersession check in `prepare_to_modify_buffer'.
            (set-visited-file-modtime)
            (save-excursion
              (goto-char (point-max))
              (insert rendered)
              (agent-log--collapse-region
               (- (point-max) (length rendered)) (point-max)))
            (set-buffer-modified-p nil)))))))

(defun agent-log--try-parse-json (line)
  "Parse LINE as JSON, returning nil if it is not valid JSON."
  (ignore-errors (agent-log--parse-json-line line)))

;;;;; Navigation commands

(defun agent-log-next-turn ()
  "Move point to the next User or Assistant heading."
  (interactive)
  (let ((pos (agent-log--find-turn-heading t)))
    (if pos
        (goto-char pos)
      (message "No more turns"))))

(defun agent-log-previous-turn ()
  "Move point to the previous User or Assistant heading."
  (interactive)
  (let ((pos (agent-log--find-turn-heading nil)))
    (if pos
        (goto-char pos)
      (message "No previous turns"))))

(defun agent-log--find-turn-heading (forward)
  "Find the next (if FORWARD) or previous turn heading.
Returns the position, or nil."
  (save-excursion
    (if forward (end-of-line) (beginning-of-line))
    (let ((re "^## \\(User\\|Assistant\\) — "))
      (if forward
          (when (re-search-forward re nil t)
            (match-beginning 0))
        (when (re-search-backward re nil t)
          (match-beginning 0))))))

(defun agent-log-toggle-section ()
  "Toggle the visibility of the section at point."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (cond
     ((looking-at "^####+ ")
      (let* ((heading-end (save-excursion (end-of-line) (point)))
             (ov (cl-find-if (lambda (o) (overlay-get o 'agent-log-section))
                             (overlays-at heading-end))))
        (if ov
            (delete-overlay ov)
          (let ((section-end (agent-log--find-section-end)))
            (when (< heading-end section-end)
              (let ((new-ov (make-overlay heading-end section-end nil t)))
                (overlay-put new-ov 'invisible 'agent-log-collapsed)
                (overlay-put new-ov 'agent-log-section t)))))))
     (t
      (when (bound-and-true-p outline-minor-mode)
        (outline-toggle-children))))))

(defun agent-log-collapse-all ()
  "Collapse all tool-use, tool-result, and thinking sections."
  (interactive)
  (agent-log--remove-section-overlays)
  (agent-log--apply-section-visibility "^####+ " 'collapse))

(defun agent-log-expand-all ()
  "Expand all sections."
  (interactive)
  (let ((inhibit-read-only t))
    (if (fboundp 'outline-show-all)
        (outline-show-all)
      (outline-flag-region (point-min) (point-max) nil))
    (agent-log--remove-section-overlays)))

(defun agent-log--apply-configured-visibility (&optional start end)
  "Apply thinking and tool visibility per user configuration.
When START and END are given, restrict to that region."
  (pcase agent-log-show-thinking
    ('collapsed (agent-log--apply-section-visibility "^#### Thinking$" 'collapse start end))
    ('hidden (agent-log--apply-section-visibility "^#### Thinking$" 'hide start end)))
  (pcase agent-log-show-tools
    ('collapsed (agent-log--apply-section-visibility "^#### Tool" 'collapse start end))
    ('hidden (agent-log--apply-section-visibility "^#### Tool" 'hide start end))))

(defun agent-log--collapse-as-configured ()
  "Collapse or hide sections per user configuration."
  (agent-log--remove-section-overlays)
  (agent-log--apply-configured-visibility)
  (agent-log--hide-empty-turns))

(defun agent-log--find-section-end ()
  "Find the end of the #### section at point.
Point must be at the beginning of a #### heading line.
The section extends until the next heading (any level) or the
next horizontal rule (`---'), whichever comes first.  Trailing
blank lines before that boundary are included."
  (save-excursion
    (forward-line 1)
    (let ((limit (or (save-excursion
                       (when (re-search-forward "^\\(##\\|---$\\)" nil t)
                         (match-beginning 0)))
                     (point-max))))
      (goto-char limit)
      limit)))

(defun agent-log--apply-section-visibility (regexp action &optional start end)
  "Apply visibility ACTION to sections matching REGEXP.
ACTION is `collapse' (hide body, keep heading) or `hide' (hide
heading and body).  When START and END are given, restrict the
search to that region."
  (save-excursion
    (goto-char (or start (point-min)))
    (while (re-search-forward regexp end t)
      (let* ((heading-start (match-beginning 0))
             (heading-end (save-excursion
                            (goto-char heading-start)
                            (end-of-line) (point)))
             (section-end (save-excursion
                            (goto-char heading-start)
                            (agent-log--find-section-end)))
             (ov-start (if (eq action 'collapse) heading-end heading-start))
             (inv-spec (if (eq action 'collapse)
                           'agent-log-collapsed
                         'agent-log-hidden)))
        (when (< ov-start section-end)
          (let ((ov (make-overlay ov-start section-end nil t)))
            (overlay-put ov 'invisible inv-spec)
            (overlay-put ov 'agent-log-section t)))
        (goto-char section-end)))))

(defun agent-log--collapse-region (start end)
  "Collapse or hide new sections between START and END."
  (agent-log--apply-configured-visibility start end))

(defun agent-log--remove-section-overlays ()
  "Remove all section visibility overlays from the current buffer."
  (dolist (ov (overlays-in (point-min) (point-max)))
    (when (overlay-get ov 'agent-log-section)
      (delete-overlay ov))))

(defun agent-log--hide-empty-turns ()
  "Hide turn headings whose visible content is entirely invisible.
After tool/thinking sections are hidden, some assistant turns may
contain no visible content.  This hides those headings and their
preceding separator."
  (save-excursion
    (goto-char (point-min))
    (while (re-search-forward "^## Assistant — " nil t)
      (let* ((heading-bol (line-beginning-position))
             ;; Look for "---\n\n" separator just before the heading (5 chars back).
             (turn-start (save-excursion
                           (goto-char heading-bol)
                           (if (re-search-backward
                                "^---$" (max (point-min) (- heading-bol 5)) t)
                               (match-beginning 0)
                             heading-bol)))
             (content-start (save-excursion
                              (end-of-line)
                              (min (1+ (point)) (point-max))))
             (turn-end (save-excursion
                         (goto-char content-start)
                         (if (re-search-forward "^---$" nil t)
                             (match-beginning 0)
                           (point-max)))))
        (when (agent-log--region-all-invisible-p content-start turn-end)
          (let ((ov (make-overlay turn-start turn-end nil t)))
            (overlay-put ov 'invisible 'agent-log-hidden)
            (overlay-put ov 'agent-log-section t)))))))

(defun agent-log--region-all-invisible-p (start end)
  "Return non-nil if all non-whitespace in START..END is invisible."
  (save-excursion
    (goto-char start)
    (catch 'visible
      (while (< (point) end)
        (let ((inv (get-char-property (point) 'invisible)))
          (if (and inv (invisible-p inv))
              (goto-char (next-single-char-property-change
                          (point) 'invisible nil end))
            (if (looking-at-p "[[:space:]\n]")
                (forward-char 1)
              (throw 'visible nil)))))
      t)))

(defun agent-log-refresh ()
  "Re-render from JSONL source and reload buffer."
  (interactive)
  (when agent-log--source-file
    (setq agent-log--partial-line ""
          agent-log--partial-bytes nil)
    (if (and agent-log--session-id agent-log--rendered-file)
        (let ((metadata (list :file agent-log--source-file
                              :timestamp nil
                              :project (or agent-log--session-project "")
                              :display "")))
          (agent-log--render-to-file
           agent-log--session-id metadata agent-log--rendered-file)
          (let ((inhibit-read-only t))
            (erase-buffer)
            (insert-file-contents agent-log--rendered-file)
            (set-buffer-modified-p nil)
            (goto-char (point-min))
            (agent-log--collapse-as-configured)
            (agent-log--maybe-insert-summary agent-log--session-id)
            (agent-log--record-offset)))
      (agent-log--render-full))))

(defun agent-log-copy-turn ()
  "Copy the current turn (from ## heading to next ##) to the kill ring."
  (interactive)
  (let ((start (agent-log--turn-start))
        (end (agent-log--turn-end)))
    (when (and start end)
      (kill-ring-save start end)
      (message "Turn copied"))))

(defun agent-log--turn-start ()
  "Return the start position of the current turn heading."
  (save-excursion
    (beginning-of-line)
    (if (looking-at "^## ")
        (point)
      (when (re-search-backward "^## " nil t)
        (point)))))

(defun agent-log--turn-end ()
  "Return the end position of the current turn."
  (save-excursion
    (when-let* ((start (agent-log--turn-start)))
      (goto-char start)
      (forward-line 1)
      (if (re-search-forward "^## " nil t)
          (match-beginning 0)
        (point-max)))))

;;;;; Session summaries

(defconst agent-log--no-conversation-sentinel "(no conversation)"
  "Sentinel stored as :summary-oneline for sessions with no user/assistant text.
Used to distinguish \"already processed, nothing to summarize\" from
\"not yet summarized\" (nil).")

(defconst agent-log--summary-system-message
  "You are a concise summarizer. Given a conversation between a user and an AI \
coding assistant, produce a JSON object with exactly two fields:
- \"oneline\": A single-line summary (max 80 characters) capturing the main task \
or topic.
- \"summary\": A paragraph of 3-5 sentences describing what was discussed, what \
was accomplished, and key outcomes.
Respond with ONLY the JSON object, no markdown formatting, no code fences, \
no other text."
  "System message for summary generation.")

(defun agent-log--find-backend-for-model (model)
  "Return the gptel backend that provides MODEL, or nil."
  (cl-loop for (_name . backend) in gptel--known-backends
           when (member model (gptel-backend-models backend))
           return backend))

(defun agent-log--resolve-summary-backend-and-model ()
  "Return (backend . model) for summary generation.
Resolves `agent-log-summary-backend' and `agent-log-summary-model',
inferring the backend from the model when needed."
  (let* ((model (or agent-log-summary-model gptel-model))
         (backend (cond
                   (agent-log-summary-backend
                    (gptel-get-backend agent-log-summary-backend))
                   (agent-log-summary-model
                    (or (agent-log--find-backend-for-model
                         agent-log-summary-model)
                        gptel-backend))
                   (t gptel-backend))))
    (cons backend model)))

(defun agent-log--extract-conversation-text (entries &optional backend)
  "Extract a condensed text representation of ENTRIES for summarization.
BACKEND is used for filtering and text extraction.
Returns a string with user and assistant messages, truncated to
`agent-log-summary-max-content-length'."
  (let* ((backend (or backend (agent-log--default-backend)))
         (conversation (if backend
                           (agent-log--filter-conversation backend entries)
                         entries))
         (parts '())
         (total 0)
         (max-len agent-log-summary-max-content-length))
    (dolist (entry conversation)
      (when (< total max-len)
        (let* ((message (plist-get entry :message))
               (role (plist-get message :role))
               (content (plist-get message :content))
               (text (if backend
                         (agent-log--extract-message-text backend content)
                       ""))
               (prefix (if (equal role "user") "User: " "Assistant: "))
               (line (concat prefix text "\n\n")))
          (when (and text (not (string-empty-p (string-trim text))))
            (push line parts)
            (cl-incf total (length line))))))
    (let ((result (string-join (nreverse parts))))
      (if (> (length result) max-len)
          (substring result 0 max-len)
        result))))

(defun agent-log--build-summary-prompt (conversation-text)
  "Build a prompt for summarizing CONVERSATION-TEXT."
  (format "Summarize this conversation:\n\n---\n%s\n---" conversation-text))

(defun agent-log--parse-summary-response (response)
  "Parse RESPONSE as a JSON summary object.
Returns (SUMMARY . ONELINE) or nil."
  (condition-case nil
      (let* ((cleaned (string-trim response))
             ;; Remove markdown code fences (``` or ```json) if present
             (cleaned (if (string-match "\\````\\(?:json\\)?[\n\r]+" cleaned)
                          (replace-regexp-in-string
                           "[\n\r]+```\\'" ""
                           (replace-regexp-in-string
                            "\\````\\(?:json\\)?[\n\r]+" "" cleaned))
                        cleaned))
             (parsed (json-parse-string cleaned :object-type 'plist))
             (summary (plist-get parsed :summary))
             (oneline (plist-get parsed :oneline)))
        (when (and (stringp summary) (stringp oneline))
          (cons summary oneline)))
    (error nil)))

(defun agent-log--sessions-needing-summary (sessions index)
  "Return sessions from SESSIONS that lack a summary in INDEX.
Sessions with a live agent process are excluded by session ID."
  (let ((active-ids (cl-loop for backend in (agent-log--active-backend-instances)
                             append (agent-log--active-session-ids backend))))
    (seq-filter
     (lambda (session)
       (let* ((sid (car session))
              (entry (gethash sid index)))
         (and (not (and entry (plist-get entry :summary-oneline)))
              (not (member sid active-ids)))))
     sessions)))

;;;###autoload
(defun agent-log-summarize-sessions ()
  "Generate AI summaries for all sessions that lack one.
If summary generation is already in progress, stop it instead."
  (interactive)
  (unless (require 'gptel nil t)
    (user-error "Package `gptel' is required for summary generation"))
  (cond
   (agent-log--summarize-active
    (agent-log-stop-summarizing))
   (t
    (let* ((sessions (agent-log--read-all-sessions))
           (index (agent-log--read-index))
           (pending (agent-log--sessions-needing-summary sessions index)))
      (if (null pending)
          (message "All %d sessions already have summaries" (length sessions))
        (setq agent-log--summarize-active t
              agent-log--summarize-stop nil)
        (cl-incf agent-log--summarize-generation)
        (message "Generating summaries for %d session(s)... (run again to stop)"
                 (length pending))
        (agent-log--summarize-next
         pending 0 (length pending)
         agent-log--summarize-generation))))))

;;;###autoload
(defun agent-log-stop-summarizing ()
  "Stop summary generation immediately.
Any in-flight gptel request will still complete, but its callback
will not spawn further work."
  (interactive)
  (if agent-log--summarize-active
      (progn
        ;; Bump the generation so that any pending callback or timer
        ;; from the current run becomes stale and is silently ignored.
        (cl-incf agent-log--summarize-generation)
        (setq agent-log--summarize-active nil
              agent-log--summarize-stop nil)
        (message "Summary generation stopped"))
    (message "No summary generation in progress")))

(defun agent-log--summarize-next (remaining done total gen)
  "Generate summary for the next session in REMAINING.
DONE sessions processed so far out of TOTAL.  GEN is the
generation counter; if it no longer matches
`agent-log--summarize-generation', this call is stale and does
nothing."
  (when (and agent-log--summarize-active
             (= gen agent-log--summarize-generation))
    (if (or (null remaining) agent-log--summarize-stop)
        (let ((stopped agent-log--summarize-stop))
          (setq agent-log--summarize-active nil
                agent-log--summarize-stop nil)
          (message "Summary generation %s: %d/%d session(s) done"
                   (if stopped "stopped" "complete") done total))
      (let* ((session (car remaining))
             (sid (car session))
             (meta (cdr session))
             (jsonl-file (plist-get meta :file)))
        (condition-case err
            (let* ((backend (plist-get meta :backend))
                   (entries (agent-log--parse-and-normalize jsonl-file backend))
                   (text (agent-log--extract-conversation-text entries backend)))
              (if (string-empty-p (string-trim text))
                  (progn
                    (agent-log--index-update-props
                     sid (list :summary agent-log--no-conversation-sentinel
                               :summary-oneline agent-log--no-conversation-sentinel))
                    (agent-log--summarize-next
                     (cdr remaining) (1+ done) total gen))
                (agent-log--summarize-one
                 sid meta text remaining done total gen)))
          (error
           (message "Failed to summarize %s: %s"
                    sid (error-message-string err))
           ;; Brief delay before the next request to avoid hammering the
           ;; LLM API and to let the event loop process pending I/O.
           (run-with-timer 0.1 nil
                           #'agent-log--summarize-next
                           (cdr remaining)
                           (1+ done) total gen)))))))

(defun agent-log--summarize-one (sid meta text remaining done total gen)
  "Send a gptel request to summarize session SID.
META is the session metadata plist.  TEXT is the extracted
conversation text.  REMAINING, DONE, TOTAL, and GEN are
chain-continuation state for `agent-log--summarize-next'."
  (let* ((prompt (agent-log--build-summary-prompt text))
         (resolved (agent-log--resolve-summary-backend-and-model))
         (gptel-backend (car resolved))
         (gptel-model (cdr resolved))
         (gptel-use-tools nil)
         (request-id (cl-gensym "summarize-"))
         (display (agent-log--summarize-display-name meta text sid)))
    (message "Summarizing %d/%d with %s: %s..." (1+ done) total
             gptel-model
             (agent-log--truncate-string display 70))
    (setq agent-log--summarize-request-id request-id)
    (gptel-request prompt
      :system agent-log--summary-system-message
      :callback
      (lambda (response _info)
        (agent-log--summarize-callback
         response request-id sid remaining done total gen)))))

(defun agent-log--summarize-display-name (meta text sid)
  "Return a human-readable display name from META, TEXT, or SID."
  (let ((display (plist-get meta :display)))
    (if (or (null display)
            (string-empty-p display)
            (string-prefix-p "/" display))
        (if (string-match "\\`User: \\(.+\\)" text)
            (match-string 1 text)
          sid)
      display)))

(defun agent-log--summarize-callback (response request-id sid remaining done total gen)
  "Handle the gptel RESPONSE for a summary request.
REQUEST-ID, SID, REMAINING, DONE, TOTAL, and GEN are
chain-continuation state.  Non-string responses (tool-calls,
reasoning blocks) are ignored; only the final string response or
an error (nil) consumes the request guard and advances the chain."
  (when (eq agent-log--summarize-request-id request-id)
    (cond
     ;; Success: got a string response.
     ((stringp response)
      (setq agent-log--summarize-request-id nil)
      (when (and agent-log--summarize-active
                 (= gen agent-log--summarize-generation))
        (let ((parsed (agent-log--parse-summary-response response)))
          (if parsed
              (progn
                (agent-log--index-update-props
                 sid (list :summary (car parsed)
                           :summary-oneline (cdr parsed)))
                (when agent-log-auto-rename-sessions
                  (when (require 'agent-log-claude nil t)
                    (agent-log-claude--maybe-rename-session sid (cdr parsed)))))
            (message "Failed to parse summary for %s" sid)))
        ;; Brief delay before the next request to avoid hammering the
        ;; LLM API and to let the event loop process pending I/O.
        (run-with-timer
         0.1 nil
         #'agent-log--summarize-next
         (cdr remaining)
         (1+ done) total gen)))
     ;; Error: nil response from gptel.  Clear the guard and advance.
     ((null response)
      (setq agent-log--summarize-request-id nil)
      (message "Summary request failed for %s, skipping" sid)
      (when (and agent-log--summarize-active
                 (= gen agent-log--summarize-generation))
        (run-with-timer
         0.1 nil
         #'agent-log--summarize-next
         (cdr remaining)
         (1+ done) total gen))))))

(defun agent-log--maybe-insert-summary (session-id)
  "Insert the AI summary for SESSION-ID into the current buffer, if available."
  (let* ((index (agent-log--read-index))
         (entry (gethash session-id index))
         (summary (when entry (plist-get entry :summary))))
    (when summary
      (let ((inhibit-read-only t))
        (save-excursion
          ;; Remove any existing summary first
          (agent-log--remove-inserted-summary)
          ;; Insert after the # Session: header
          (goto-char (point-min))
          (when (re-search-forward "^# Session:.*\n\n" nil t)
            (let ((start (point)))
              (insert (format "> **Summary**: %s\n\n" summary))
              (put-text-property start (point)
                                 'agent-log-summary t))))))))

(defun agent-log--remove-inserted-summary ()
  "Remove any previously inserted summary from the current buffer."
  (let ((inhibit-read-only t))
    (save-excursion
      (goto-char (point-min))
      (let ((start (text-property-any
                    (point-min) (point-max) 'agent-log-summary t)))
        (when start
          (let ((end (next-single-property-change
                      start 'agent-log-summary nil (point-max))))
            (delete-region start end)))))))

;;;;; AI search

(defconst agent-log--search-scope-system-message
  "You are a search-scope assistant for a conversation log archive.  Given a \
user's natural language query plus metadata about the archive (available \
projects with session counts, and the date range), return a JSON object that \
narrows which sessions to search.

Return ONLY a JSON object with these fields:
- \"projects\": an array of project short-names to include, or the string \
\"all\" to include every project.
- \"date_after\": an ISO 8601 date string (YYYY-MM-DD) for the earliest date \
to include, or null for no lower bound.
- \"date_before\": an ISO 8601 date string (YYYY-MM-DD) for the latest date \
to include, or null for no upper bound.

Be inclusive rather than exclusive.  If the query does not mention a specific \
project or date range, use \"all\" and null dates.  Only narrow when the query \
clearly indicates a scope.

Respond with ONLY the JSON object, no markdown formatting, no code fences."
  "System message for search scope narrowing (stage 1).")

(defconst agent-log--search-system-message
  "You are a search assistant for a conversation log archive.  You receive a \
user's query and a set of session summaries.  Each summary has a SESSION_ID, \
a one-line summary, and a paragraph summary.

Your task: identify the sessions most relevant to the query and produce a \
markdown narrative describing what you found.  Use markdown links of the form \
[description](SESSION_ID) to reference sessions.  The SESSION_ID is a UUID; \
use it verbatim as the link target.

Guidelines:
- Lead with the most relevant sessions.
- Explain WHY each session is relevant to the query.
- Group related sessions when appropriate.
- If no sessions are relevant, say so clearly.
- Be concise but informative.
- Do not fabricate session content; only reference what the summaries describe."
  "System message for search selection (stage 2).")

(defun agent-log--resolve-search-scope-backend-and-model ()
  "Return (backend . model) for search scope narrowing (stage 1).
Resolves `agent-log-search-scope-backend' and
`agent-log-search-scope-model', inferring the backend from the
model when needed."
  (let* ((model (or agent-log-search-scope-model gptel-model))
         (backend (cond
                   (agent-log-search-scope-backend
                    (gptel-get-backend agent-log-search-scope-backend))
                   (agent-log-search-scope-model
                    (or (agent-log--find-backend-for-model
                         agent-log-search-scope-model)
                        gptel-backend))
                   (t gptel-backend))))
    (cons backend model)))

(defun agent-log--resolve-search-backend-and-model ()
  "Return (backend . model) for search selection (stage 2).
Resolves `agent-log-search-backend' and `agent-log-search-model',
inferring the backend from the model when needed."
  (let* ((model (or agent-log-search-model gptel-model))
         (backend (cond
                   (agent-log-search-backend
                    (gptel-get-backend agent-log-search-backend))
                   (agent-log-search-model
                    (or (agent-log--find-backend-for-model
                         agent-log-search-model)
                        gptel-backend))
                   (t gptel-backend))))
    (cons backend model)))

(defun agent-log--search-gather-metadata (sessions index)
  "Compute metadata for SESSIONS and INDEX needed by the search pipeline.
Returns a plist with:
  :projects     - alist of (SHORT-NAME . COUNT) for projects with summaries
  :date-earliest - earliest timestamp (epoch-ms) among summarized sessions
  :date-latest   - latest timestamp (epoch-ms) among summarized sessions
  :summarized    - count of sessions with summaries
  :unsummarized  - count of sessions without summaries"
  (let ((project-counts (make-hash-table :test #'equal))
        (active-ids (cl-loop for backend in (agent-log--active-backend-instances)
                             append (agent-log--active-session-ids backend)))
        (earliest nil)
        (latest nil)
        (summarized 0)
        (unsummarized 0))
    (dolist (session sessions)
      (let* ((sid (car session))
             (meta (cdr session))
             (entry (gethash sid index))
             (ts (plist-get meta :timestamp))
             (project (agent-log--short-project (plist-get meta :project))))
        (let ((oneline (and entry (plist-get entry :summary-oneline))))
          (cond
           ;; Has a real summary: count it and track its metadata.
           ((and oneline (not (equal oneline agent-log--no-conversation-sentinel)))
            (cl-incf summarized)
            (cl-incf (gethash project project-counts 0))
            (when (or (null earliest) (and (numberp ts) (< ts earliest)))
              (setq earliest ts))
            (when (or (null latest) (and (numberp ts) (> ts latest)))
              (setq latest ts)))
           ;; Empty session (sentinel) or active session: silently skip.
           ((or (equal oneline agent-log--no-conversation-sentinel)
                (member sid active-ids))
            nil)
           ;; No summary at all: genuinely unsummarized.
           (t (cl-incf unsummarized))))))
    (let (projects)
      (maphash (lambda (name count) (push (cons name count) projects))
               project-counts)
      (setq projects (sort projects (lambda (a b) (> (cdr a) (cdr b)))))
      (list :projects projects
            :date-earliest earliest
            :date-latest latest
            :summarized summarized
            :unsummarized unsummarized))))

(defun agent-log--search-build-scope-prompt (query metadata)
  "Build the stage 1 scope-narrowing prompt from QUERY and METADATA."
  (let* ((projects (plist-get metadata :projects))
         (earliest (plist-get metadata :date-earliest))
         (latest (plist-get metadata :date-latest))
         (summarized (plist-get metadata :summarized))
         (project-lines
          (mapconcat (lambda (p) (format "  - %s (%d sessions)" (car p) (cdr p)))
                     projects "\n"))
         (date-from (if earliest
                        (format-time-string "%Y-%m-%d" (/ earliest 1000))
                      "unknown"))
         (date-to (if latest
                      (format-time-string "%Y-%m-%d" (/ latest 1000))
                    "unknown")))
    (format "User query: %S\n\nArchive metadata:\n- Projects:\n%s\n- Date range: %s to %s\n- Total sessions with summaries: %d"
            query project-lines date-from date-to summarized)))

(defun agent-log--search-parse-scope-response (response)
  "Parse RESPONSE as a JSON scope object.
Returns a plist (:projects LIST-OR-ALL :date-after EPOCH-OR-NIL
:date-before EPOCH-OR-NIL), or nil on parse failure."
  (when (stringp response)
    (let ((text (string-trim response)))
      ;; Strip markdown code fences if present.
      (when (string-match "\\````\\(?:json\\)?\n?" text)
        (setq text (substring text (match-end 0))))
      (when (string-match "\n?```\\'" text)
        (setq text (substring text 0 (match-beginning 0))))
      (condition-case nil
          (let* ((json-object-type 'plist)
                 (json-array-type 'list)
                 (obj (json-read-from-string text))
                 (projects (plist-get obj :projects))
                 (date-after (plist-get obj :date_after))
                 (date-before (plist-get obj :date_before)))
            (list :projects (if (and (stringp projects)
                                     (equal projects "all"))
                                "all"
                              (if (listp projects) projects "all"))
                  :date-after (agent-log--search-parse-date date-after)
                  :date-before (agent-log--search-parse-date date-before)))
        (error nil)))))

(defun agent-log--search-parse-date (date-string)
  "Parse DATE-STRING (YYYY-MM-DD) to epoch milliseconds, or nil."
  (when (and (stringp date-string)
             (string-match "\\`\\([0-9]\\{4\\}\\)-\\([0-9]\\{2\\}\\)-\\([0-9]\\{2\\}\\)\\'" date-string))
    (let ((time (encode-time 0 0 0
                             (string-to-number (match-string 3 date-string))
                             (string-to-number (match-string 2 date-string))
                             (string-to-number (match-string 1 date-string)))))
      (* (float-time time) 1000))))

(defun agent-log--search-apply-scope (sessions index scope)
  "Filter SESSIONS using INDEX and SCOPE criteria.
Returns sessions that match the project filter, fall within the
date range, and have a summary in the INDEX."
  (let ((projects (plist-get scope :projects))
        (date-after (plist-get scope :date-after))
        (date-before (plist-get scope :date-before)))
    (seq-filter
     (lambda (session)
       (let* ((sid (car session))
              (meta (cdr session))
              (entry (gethash sid index))
              (ts (plist-get meta :timestamp))
              (project (agent-log--short-project (plist-get meta :project))))
         (and
          ;; Must have a summary.
          entry
          (plist-get entry :summary-oneline)
          (not (equal (plist-get entry :summary-oneline)
                      agent-log--no-conversation-sentinel))
          ;; Project filter.
          (or (equal projects "all")
              (member project projects))
          ;; Date range.
          (or (null date-after)
              (and (numberp ts) (>= ts date-after)))
          (or (null date-before)
              ;; Add 86400000 ms (one day) to make the upper bound
              ;; inclusive of the entire day.
              (and (numberp ts) (<= ts (+ date-before 86400000)))))))
     sessions)))

(defun agent-log--search-estimate-tokens (text)
  "Return a rough token estimate for TEXT (one token per four characters)."
  (if (and text (stringp text) (> (length text) 0))
      (/ (length text) 4)
    0))

(defun agent-log--search-check-budget (prompt-text system-text model)
  "Check if the estimated cost of PROMPT-TEXT and SYSTEM-TEXT exceeds the budget.
MODEL is the gptel model symbol for pricing lookup.
Returns non-nil if the user approves or the budget is not exceeded."
  (let* ((estimated-tokens (+ (agent-log--search-estimate-tokens prompt-text)
                              (agent-log--search-estimate-tokens system-text)))
         (budget-type (car agent-log-search-budget))
         (budget-limit (cdr agent-log-search-budget)))
    (pcase budget-type
      ('tokens
       (if (> estimated-tokens budget-limit)
           (y-or-n-p
            (format "Estimated ~%d tokens (budget: %d). Continue? "
                    estimated-tokens budget-limit))
         t))
      ('dollars
       (if (and (require 'gptel-plus nil t)
                (fboundp 'gptel-plus-compute-cost))
           (let ((input-rate (get model :input-cost)))
             (if input-rate
                 (let ((estimated-cost (/ (* estimated-tokens input-rate) 1000000.0)))
                   (if (> estimated-cost budget-limit)
                       (y-or-n-p
                        (format "Estimated ~$%.4f (budget: $%.2f). Continue? "
                                estimated-cost budget-limit))
                     t))
               ;; No pricing data for this model; proceed.
               (message "agent-log: no pricing data for %s; budget not enforced" model)
               t))
         ;; gptel-plus not available; proceed with warning.
         (message "agent-log: dollar budget requires gptel-plus; budget not enforced")
         t))
      (_ t))))

(defun agent-log--search-build-selection-prompt (query filtered-sessions index)
  "Build the stage 2 selection prompt from QUERY, FILTERED-SESSIONS and INDEX."
  (let ((session-blocks
         (mapconcat
          (lambda (session)
            (let* ((sid (car session))
                   (meta (cdr session))
                   (entry (gethash sid index))
                   (ts (plist-get meta :timestamp))
                   (project (agent-log--short-project (plist-get meta :project)))
                   (date (if (numberp ts)
                             (format-time-string "%Y-%m-%d %H:%M" (/ ts 1000))
                           "unknown"))
                   (oneline (or (plist-get entry :summary-oneline) ""))
                   (summary (or (plist-get entry :summary) "")))
              (format "### %s\n**Project**: %s | **Date**: %s\n**Summary**: %s\n%s"
                      sid project date oneline summary)))
          filtered-sessions "\n\n")))
    (format "User query: %S\n\n## Sessions\n\n%s" query session-blocks)))

(defun agent-log--search-send-selection (query filtered-sessions index)
  "Send the stage 2 selection request for QUERY over FILTERED-SESSIONS.
INDEX is the session index for looking up summaries."
  (let* ((n (length filtered-sessions))
         (prompt (agent-log--search-build-selection-prompt
                  query filtered-sessions index))
         (system agent-log--search-system-message)
         (resolved (agent-log--resolve-search-backend-and-model))
         (gptel-backend (car resolved))
         (gptel-model (cdr resolved))
         (gptel-use-tools nil))
    (if (agent-log--search-check-budget prompt system gptel-model)
        (progn
          (message "Searching %d session(s) with %s..." n gptel-model)
          (gptel-request prompt
            :system system
            :callback
            (lambda (response _info)
              (agent-log--search-selection-callback response))))
      (message "Search aborted"))))

(defun agent-log--search-selection-callback (response)
  "Handle the stage 2 RESPONSE."
  (cond
   ((stringp response)
    (agent-log--search-display-results response))
   ((null response)
    (message "agent-log: search request failed (nil response)"))))

(defvar agent-log-search-link-map
  (let ((map (make-sparse-keymap)))
    (define-key map [mouse-1] #'agent-log-search-follow-link)
    (define-key map (kbd "RET") #'agent-log-search-follow-link)
    map)
  "Keymap for clickable session links in search results.")

(defvar agent-log-search-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "q") #'quit-window)
    (define-key map (kbd "RET") #'agent-log-search-follow-link)
    map)
  "Keymap for `agent-log-search-mode'.")

(define-derived-mode agent-log-search-mode markdown-view-mode "Agent-Log-Search"
  "Mode for displaying AI search results over session logs.
Session references are clickable links that open the rendered log."
  :group 'agent-log
  (setq-local buffer-read-only t))

(defun agent-log--search-display-results (narrative)
  "Display NARRATIVE in the `*agent-log-search*' buffer."
  (let ((buf (get-buffer-create "*agent-log-search*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert narrative)
        (agent-log--search-buttonize-links)
        (goto-char (point-min)))
      (let ((markdown-mode-hook nil)
            (markdown-view-mode-hook nil)
            (after-change-major-mode-hook
             (remq 'flycheck-global-mode-enable-in-buffers
                   after-change-major-mode-hook)))
        (agent-log-search-mode))
      (set-buffer-modified-p nil))
    (pop-to-buffer buf)))

(defconst agent-log--uuid-regexp
  "[0-9a-f]\\{8\\}-[0-9a-f]\\{4\\}-[0-9a-f]\\{4\\}-[0-9a-f]\\{4\\}-[0-9a-f]\\{12\\}"
  "Regexp matching a UUID.")

(defun agent-log--search-buttonize-links ()
  "Make session UUIDs in the buffer clickable.
First pass: replace markdown links `[text](UUID)' with clickable TEXT.
Second pass: buttonize any remaining bare UUIDs.
Uses overlays for the link face so that `markdown-mode' font-lock
does not overwrite it."
  (save-excursion
    ;; Pass 1: markdown links [desc](UUID) — work backward.
    (goto-char (point-max))
    (let ((md-re (concat "\\[\\([^]]+\\)](\\(" agent-log--uuid-regexp "\\))")))
      (while (re-search-backward md-re nil t)
        (let ((desc (match-string 1))
              (sid (match-string 2))
              (beg (match-beginning 0))
              (end (match-end 0)))
          (delete-region beg end)
          (goto-char beg)
          (agent-log--search-insert-link desc sid))))
    ;; Pass 2: bare UUIDs not already buttonized — work backward.
    (goto-char (point-max))
    (while (re-search-backward agent-log--uuid-regexp nil t)
      (unless (get-text-property (match-beginning 0) 'agent-log-search-session-id)
        (let ((sid (match-string 0))
              (beg (match-beginning 0))
              (end (match-end 0)))
          (delete-region beg end)
          (goto-char beg)
          (agent-log--search-insert-link sid sid))))))

(defun agent-log--search-insert-link (text session-id)
  "Insert TEXT as a clickable link to SESSION-ID.
Text properties handle interaction (click, keymap, help-echo).
An overlay handles the face so that font-lock cannot overwrite it."
  (let ((start (point)))
    (insert (propertize text
                        'agent-log-search-session-id session-id
                        'mouse-face 'highlight
                        'help-echo (format "mouse-1: open session %s" session-id)
                        'keymap agent-log-search-link-map))
    (let ((ov (make-overlay start (point) nil t nil)))
      (overlay-put ov 'face 'link)
      (overlay-put ov 'evaporate t))))

(defun agent-log-search-follow-link ()
  "Open the session log for the link at point."
  (interactive)
  (let ((sid (get-text-property (point) 'agent-log-search-session-id)))
    (if (null sid)
        (user-error "No session link at point")
      (let ((session (assoc sid agent-log--search-sessions-cache)))
        (if session
            (agent-log--open-rendered (car session) (cdr session))
          (agent-log-open-session sid))))))

;;;###autoload
(defun agent-log-search (query)
  "Search session logs using AI with natural language QUERY.
Stage 1 narrows the search scope by project and date range.
Stage 2 selects relevant sessions and produces a narrative with
clickable links to the matching logs."
  (interactive "sSearch logs: ")
  (unless (require 'gptel nil t)
    (user-error "Package `gptel' is required for AI search"))
  (let* ((sessions (agent-log--read-all-sessions))
         (index (agent-log--read-index))
         (metadata (agent-log--search-gather-metadata sessions index))
         (unsummarized (plist-get metadata :unsummarized))
         (summarized (plist-get metadata :summarized)))
    (when (zerop summarized)
      (user-error "No sessions have summaries; run `agent-log-summarize-sessions' first"))
    (when (> unsummarized 0)
      (unless (y-or-n-p
               (format "%d session(s) lack summaries and will be excluded. Continue? "
                       unsummarized))
        (user-error "Search aborted")))
    (setq agent-log--search-sessions-cache sessions
          agent-log--search-index-cache index)
    (let* ((scope-prompt (agent-log--search-build-scope-prompt query metadata))
           (resolved (agent-log--resolve-search-scope-backend-and-model))
           (gptel-backend (car resolved))
           (gptel-model (cdr resolved))
           (gptel-use-tools nil))
      (message "Analyzing search scope with %s..." gptel-model)
      (gptel-request scope-prompt
        :system agent-log--search-scope-system-message
        :callback
        (lambda (response _info)
          (agent-log--search-scope-callback
           response query sessions index))))))

(defun agent-log--search-scope-callback (response query sessions index)
  "Handle the stage 1 scope RESPONSE.
QUERY is the original search query.  SESSIONS and INDEX are the
full session list and index for filtering."
  (let ((scope (or (and (stringp response)
                        (agent-log--search-parse-scope-response response))
                   ;; Fallback: include everything.
                   (list :projects "all" :date-after nil :date-before nil))))
    (let ((filtered (agent-log--search-apply-scope sessions index scope)))
      (if (null filtered)
          (agent-log--search-display-results
           "No sessions with summaries matched the search scope.")
        ;; Cap at 100 most recent sessions.
        (let ((truncated (> (length filtered) 100)))
          (when truncated
            (setq filtered (seq-take filtered 100)))
          (agent-log--search-send-selection query filtered index))))))

;;;;; Resume session

(defun agent-log--extract-session-id-from-buffer ()
  "Extract session ID from the front-matter comment of the current buffer."
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "<!-- session: \\([^ ]+\\) -->" nil t)
      (match-string 1))))

(defun agent-log-resume-session ()
  "Resume the session for the current buffer in the coding agent."
  (interactive)
  (let ((session-id (or agent-log--session-id
                        (agent-log--extract-session-id-from-buffer))))
    (unless session-id
      (user-error "No session ID found in current buffer"))
    (unless agent-log--backend
      (user-error "No backend associated with this buffer"))
    (agent-log--resume-session agent-log--backend session-id)))

;;;;; Transient menu

(transient-define-suffix agent-log-cycle-show-thinking ()
  "Cycle `agent-log-show-thinking' through hidden → collapsed → visible."
  :description (lambda ()
                 (format "Show thinking: %s"
                         (propertize (symbol-name agent-log-show-thinking)
                                     'face 'transient-value)))
  :transient t
  (interactive)
  (setq agent-log-show-thinking
        (pcase agent-log-show-thinking
          ('hidden 'collapsed)
          ('collapsed 'visible)
          ('visible 'hidden)))
  (when (derived-mode-p 'agent-log-mode)
    (agent-log--collapse-as-configured))
  (message "Show thinking → %s" agent-log-show-thinking))

(transient-define-suffix agent-log-cycle-show-tools ()
  "Cycle `agent-log-show-tools' through hidden → collapsed → visible."
  :description (lambda ()
                 (format "Show tools: %s"
                         (propertize (symbol-name agent-log-show-tools)
                                     'face 'transient-value)))
  :transient t
  (interactive)
  (setq agent-log-show-tools
        (pcase agent-log-show-tools
          ('hidden 'collapsed)
          ('collapsed 'visible)
          ('visible 'hidden)))
  (when (derived-mode-p 'agent-log-mode)
    (agent-log--collapse-as-configured))
  (message "Show tools → %s" agent-log-show-tools))

(transient-define-suffix agent-log-toggle-live-update ()
  "Toggle `agent-log-live-update'."
  :description (lambda ()
                 (format "Live update: %s"
                         (propertize (if agent-log-live-update "on" "off")
                                     'face 'transient-value)))
  :transient t
  (interactive)
  (setq agent-log-live-update (not agent-log-live-update))
  (message "Live update → %s" (if agent-log-live-update "on" "off")))

(transient-define-suffix agent-log-toggle-group-by-project ()
  "Toggle `agent-log-group-by-project'."
  :description (lambda ()
                 (format "Group by project: %s"
                         (propertize (if agent-log-group-by-project "on" "off")
                                     'face 'transient-value)))
  :transient t
  (interactive)
  (setq agent-log-group-by-project (not agent-log-group-by-project))
  (message "Group by project → %s"
           (if agent-log-group-by-project "on" "off")))

;;;###autoload (autoload 'agent-log-menu "agent-log" nil t)
(transient-define-prefix agent-log-menu ()
  "Transient menu for Agent Log commands."
  [["Open"
    ("b" "Browse logs" agent-log-browse-sessions)
    ("l" "Open log: latest session" agent-log-open-latest)
    ("c" "Open log: current session" agent-log-open-from-session)
    ("s" "Resume session from current log" agent-log-resume-session)
    ("d" "Open log directory" agent-log-open-directory)]
   ["Navigate"
    :if (lambda () (derived-mode-p 'agent-log-mode))
    ("n" "Next turn" agent-log-next-turn)
    ("p" "Previous turn" agent-log-previous-turn)
    ("TAB" "Toggle section at point" agent-log-toggle-section)
    ("C" "Collapse all sections" agent-log-collapse-all)
    ("E" "Expand all sections" agent-log-expand-all)
    ("G" "Re-render from source" agent-log-refresh)
    ("w" "Copy current turn" agent-log-copy-turn)]
   ["Sync & AI"
    ("y" "Sync all" agent-log-sync-all)
    ("s" "Summarize sessions" agent-log-summarize-sessions)
    ("x" "Stop summarizing" agent-log-stop-summarizing)
    ("r" "Rename sessions from summaries" agent-log-rename-sessions)
    ("/" "Search sessions with AI" agent-log-search)]
   ["Settings"
    ("-t" agent-log-cycle-show-thinking)
    ("-o" agent-log-cycle-show-tools)
    ("-u" agent-log-toggle-live-update)
    ("-g" agent-log-toggle-group-by-project)]])

(provide 'agent-log)
;;; agent-log.el ends here
