;;; claude-log.el --- Browse Claude Code conversation logs  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Pablo Stafforini

;; Author: Pablo Stafforini
;; URL: https://github.com/benthamite/claude-log
;; Version: 0.2.0
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

;; Browse and render Claude Code conversation logs stored as JSONL files.
;; Maintains a mirror directory of pre-rendered Markdown files so that
;; standard tools (consult-ripgrep, Dired, grep) work natively on
;; readable content.
;;
;; Entry points:
;;   `claude-log-browse-sessions'        - pick a session from history
;;   `claude-log-open-latest'            - open the most recent session
;;   `claude-log-open-rendered-directory' - browse rendered files in Dired
;;   `claude-log-sync-all'               - render all unrendered/stale sessions
;;   `claude-log-open-file'              - open a specific JSONL file
;;   `claude-log-resume-session'         - resume session in Claude Code
;;   `claude-log-open-session-at-point'  - open log for session in current buffer

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

;;;;; Customization

(defgroup claude-log nil
  "Browse Claude Code conversation logs."
  :group 'tools
  :prefix "claude-log-")

(defcustom claude-log-directory "~/.claude"
  "Root directory of Claude Code configuration."
  :type 'directory)

(defcustom claude-log-rendered-directory "~/.claude/rendered"
  "Directory where rendered Markdown files are stored."
  :type 'directory)

(defcustom claude-log-show-thinking 'collapsed
  "How to display assistant thinking blocks.
`hidden' omits them entirely, `collapsed' shows them folded under
a heading, `visible' shows them expanded."
  :type '(choice (const :tag "Hidden" hidden)
                 (const :tag "Collapsed" collapsed)
                 (const :tag "Visible" visible)))

(defcustom claude-log-show-tools 'collapsed
  "How to display tool-use and tool-result sections.
`hidden' omits them entirely, `collapsed' shows them folded under
a heading, `visible' shows them expanded."
  :type '(choice (const :tag "Hidden" hidden)
                 (const :tag "Collapsed" collapsed)
                 (const :tag "Visible" visible)))

(defcustom claude-log-timestamp-format "%Y-%m-%d %H:%M:%S"
  "Format string for timestamps in rendered output."
  :type 'string)

(defcustom claude-log-max-tool-input-length 200
  "Maximum characters to show for tool input summaries."
  :type 'integer)

(defcustom claude-log-max-tool-result-length 500
  "Maximum characters to show for tool result content."
  :type 'integer)

(defcustom claude-log-live-update t
  "Whether to watch the JSONL file for live updates."
  :type 'boolean)

(defcustom claude-log-group-by-project t
  "Whether to group sessions by project in the browser.
When non-nil, `claude-log-browse-sessions' first prompts for a
project, then for a session within that project."
  :type 'boolean)

(defcustom claude-log-display-width 60
  "Maximum width of the first-message column in the session browser."
  :type 'integer)

(defcustom claude-log-slug-max-length 50
  "Maximum length of the slug portion of rendered filenames."
  :type 'integer)

(defcustom claude-log-summary-backend nil
  "The gptel backend name for summary generation, e.g. \"Gemini\" or \"Claude\".
When nil, the backend is inferred from `claude-log-summary-model', falling
back to `gptel-backend'."
  :type '(choice (const :tag "Infer from model or use gptel default" nil)
                 (string :tag "Backend name")))

(defcustom claude-log-summary-model nil
  "The gptel model for summary generation, e.g. `claude-haiku-4-5-20251001'.
When nil, defaults to `gptel-model'."
  :type '(choice (const :tag "Use gptel default" nil)
                 (symbol :tag "Model name")))

(defcustom claude-log-summary-max-content-length 8000
  "Maximum characters of conversation text sent to the LLM for summarization."
  :type 'integer)

(defcustom claude-log-sync-on-session-end nil
  "Whether to sync and summarize when a Claude Code session ends.
When non-nil, `claude-log-sync-all' and `claude-log-summarize-sessions'
run automatically after a session terminates.  Requires the `claude-code'
package and a \"Stop\" hook configured in Claude Code settings."
  :type 'boolean
  :set (lambda (sym val)
         (set-default sym val)
         (if val
             (add-hook 'claude-code-event-hook #'claude-log--session-end-handler)
           (remove-hook 'claude-code-event-hook #'claude-log--session-end-handler))))

;;;;; Internal variables

(defvar-local claude-log--source-file nil
  "Path to the JSONL file being displayed.")

(defvar-local claude-log--file-offset 0
  "Byte offset into the JSONL file for incremental reads.")

(defvar-local claude-log--partial-line ""
  "Leftover partial line from the last incremental read.")

(defvar-local claude-log--partial-bytes nil
  "Unibyte string of leftover bytes from an incomplete UTF-8 sequence.
When a chunk boundary splits a multi-byte character, the trailing
bytes are saved here and prepended to the next raw read.")

(defvar-local claude-log--watcher nil
  "File-notify descriptor for live updates.")

(defvar-local claude-log--session-project nil
  "Project name for the current session.")

(defvar-local claude-log--session-date nil
  "Date string for the current session.")

(defvar-local claude-log--session-id nil
  "Session ID (UUID) for the current buffer.")

(defvar-local claude-log--rendered-file nil
  "Path to the rendered .md file for the current session.")

(defvar claude-log--summarize-active nil
  "Non-nil when summary generation is in progress.")

(defvar claude-log--summarize-stop nil
  "When non-nil, stop summary generation after the current request.")

(defvar claude-log--summarize-generation 0
  "Generation counter for summary runs.
Incremented each time `claude-log-summarize-sessions' starts a new run.
Callbacks and timers from a previous generation are ignored, preventing
stale callbacks from forking duplicate chains.")

(defvar claude-log--summarize-request-id nil
  "Nonce for the current in-flight gptel request.
Set before each `gptel-request' and consumed by the first callback
invocation.  Subsequent callbacks for the same request see a mismatch
and are silently ignored, preventing chain forking from streaming.")

;;;;; Entry points

;;;###autoload
(defun claude-log-browse-sessions ()
  "Browse Claude Code sessions and open the selected one.
When `claude-log-group-by-project' is non-nil, first prompts for
a project, then for a session within that project."
  (interactive)
  (let ((sessions (claude-log--read-sessions)))
    (if claude-log-group-by-project
        (claude-log--browse-grouped sessions)
      (claude-log--browse-flat sessions))))

;;;###autoload
(defun claude-log-open-file (file)
  "Open and render the Claude Code JSONL log at FILE."
  (interactive "fJSONL file: ")
  (let* ((file (expand-file-name file))
         (session-id (file-name-sans-extension (file-name-nondirectory file)))
         (entries (claude-log--parse-jsonl-file file))
         (first-msg (claude-log--find-first-message entries))
         (progress (claude-log--find-progress-entry entries))
         (ts-iso (when first-msg (plist-get first-msg :timestamp)))
         (epoch-ms (when (stringp ts-iso)
                     (claude-log--iso-to-epoch-ms ts-iso)))
         (display (or (claude-log--first-user-text entries) ""))
         (project (when progress (or (plist-get progress :cwd) "")))
         (metadata (list :file file
                         :timestamp epoch-ms
                         :project (or project "")
                         :display display)))
    (claude-log--open-rendered session-id metadata)))

;;;###autoload
(defun claude-log-open-latest ()
  "Open the most recent Claude Code session."
  (interactive)
  (let ((sessions (claude-log--read-sessions)))
    (unless sessions
      (user-error "No sessions found"))
    (let* ((latest (car sessions))
           (session-id (car latest))
           (metadata (cdr latest)))
      (claude-log--open-rendered session-id metadata))))

;;;###autoload
(defun claude-log-open-rendered-directory ()
  "Open the rendered Markdown directory in Dired."
  (interactive)
  (let ((dir (expand-file-name claude-log-rendered-directory)))
    (unless (file-directory-p dir)
      (make-directory dir t))
    (dired dir)))

;;;###autoload
(defun claude-log-open-session (session-id)
  "Open the Claude Code session with SESSION-ID."
  (interactive "sSession ID: ")
  (let ((file (claude-log--find-session-file session-id)))
    (unless file
      (user-error "No JSONL file found for session %s" session-id))
    (claude-log-open-file file)))

;;;###autoload
(defun claude-log-sync-all (&optional callback)
  "Render all unrendered or stale sessions.
Uses timers to avoid blocking Emacs.  When CALLBACK is non-nil,
call it with no arguments after the last session is rendered."
  (interactive)
  (let* ((sessions (claude-log--read-sessions))
         (index (claude-log--read-index))
         (pending (claude-log--pending-sessions sessions index)))
    (if (null pending)
        (progn
          (message "All %d sessions up to date" (length sessions))
          (when callback (funcall callback)))
      (message "Syncing %d session(s)..." (length pending))
      (claude-log--sync-next pending 0 (length pending) callback))))

(defun claude-log--pending-sessions (sessions index)
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

(defun claude-log--sync-next (remaining done total &optional callback)
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
          (let ((result (claude-log--render-to-file sid meta)))
            (claude-log--index-update-props
             sid (list :file (car result) :jsonl-size (cdr result))))
        (error (message "Failed to render %s: %s"
                        sid (error-message-string err))))
      (run-with-timer 0 nil #'claude-log--sync-next
                      (cdr remaining) (1+ done) total callback))))

(defun claude-log--activate-mode ()
  "Activate `claude-log-mode' with parent mode hooks suppressed.
Suppresses `markdown-mode-hook', `markdown-view-mode-hook', and
flycheck's global-mode hook to prevent unwanted side effects."
  (let ((markdown-mode-hook nil)
        (markdown-view-mode-hook nil)
        (after-change-major-mode-hook
         (remq 'flycheck-global-mode-enable-in-buffers
               after-change-major-mode-hook)))
    (claude-log-mode)))

;;;;; Index file

(defun claude-log--index-file ()
  "Return the path to the rendered-directory index file."
  (expand-file-name "_index.el" claude-log-rendered-directory))

(defun claude-log--read-index ()
  "Read the index hash table from disk.
Returns an empty hash table if the file does not exist or is corrupt."
  (let ((file (claude-log--index-file)))
    (condition-case err
        (if (file-exists-p file)
            (let ((obj (with-temp-buffer
                         (insert-file-contents file)
                         (read (current-buffer)))))
              (if (hash-table-p obj) obj
                (message "claude-log: index file corrupt (not a hash table), rebuilding")
                (make-hash-table :test #'equal)))
          (make-hash-table :test #'equal))
      (error
       (message "claude-log: failed to read index: %s" (error-message-string err))
       (make-hash-table :test #'equal)))))

(defun claude-log--write-index (index)
  "Write INDEX hash table to disk atomically.
Writes to a temporary file first, then renames to avoid corruption
if Emacs crashes mid-write."
  (let* ((file (claude-log--index-file))
         (dir (file-name-directory file))
         (_ensure (make-directory dir t))
         (tmp (make-temp-file (expand-file-name "_index-tmp" dir) nil ".el")))
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
       (signal (car err) (cdr err))))))

(defun claude-log--index-merge (index session-id props)
  "Merge PROPS into the INDEX entry for SESSION-ID.
Existing properties not in PROPS are preserved."
  (let ((existing (or (gethash session-id index) '())))
    (cl-loop for (key val) on props by #'cddr
             do (setq existing (plist-put existing key val)))
    (puthash session-id existing index)))

(defun claude-log--index-update-props (session-id props)
  "Atomically merge PROPS into the disk index entry for SESSION-ID.
Reads the current index from disk, merges PROPS, and writes back,
ensuring concurrent operations do not clobber each other."
  (let ((index (claude-log--read-index)))
    (claude-log--index-merge index session-id props)
    (claude-log--write-index index)))

(defun claude-log--index-update (session-id rendered-path jsonl-size)
  "Update the index entry for SESSION-ID with RENDERED-PATH and JSONL-SIZE."
  (claude-log--index-update-props
   session-id (list :file rendered-path :jsonl-size jsonl-size)))

;;;;; Slug and filepath

(defun claude-log--slugify (text)
  "Convert TEXT to a filename-safe slug.
Lowercases, replaces non-alphanumeric runs with hyphens,
and truncates to `claude-log-slug-max-length'."
  (let* ((slug (downcase (or text "")))
         (slug (replace-regexp-in-string "[^a-z0-9]+" "-" slug))
         (slug (replace-regexp-in-string "\\`-+\\|-+\\'" "" slug))
         (slug (if (> (length slug) claude-log-slug-max-length)
                   (substring slug 0 claude-log-slug-max-length)
                 slug)))
    (if (string-empty-p slug) "untitled" slug)))

(defun claude-log--rendered-filepath (_session-id metadata)
  "Compute the rendered .md filepath for a session.
METADATA is a plist with :timestamp, :project, :display."
  (let* ((ts (plist-get metadata :timestamp))
         (date-str (if (numberp ts)
                       (format-time-string "%Y-%m-%d_%H-%M"
                                           (seconds-to-time (/ ts 1000.0)))
                     "unknown"))
         (display (or (plist-get metadata :display) ""))
         (slug (claude-log--slugify display))
         (project (claude-log--short-project
                   (or (plist-get metadata :project) "")))
         (project-dir (expand-file-name project claude-log-rendered-directory))
         (filename (format "%s_%s.md" date-str slug)))
    (expand-file-name filename project-dir)))

(defun claude-log--first-user-text (entries)
  "Return the text of the first user message in ENTRIES."
  (when-let* ((first-user (seq-find
                           (lambda (e)
                             (and (equal (plist-get e :type) "user")
                                  (not (claude-log--system-entry-p e))))
                           entries))
              (message (plist-get first-user :message))
              (content (plist-get message :content)))
    (cond
     ((stringp content) content)
     ((listp content)
      (when-let* ((text-item (seq-find
                              (lambda (i)
                                (equal (plist-get i :type) "text"))
                              content)))
        (plist-get text-item :text)))
     (t nil))))

(defun claude-log--iso-to-epoch-ms (ts)
  "Convert ISO 8601 timestamp TS to epoch milliseconds."
  (condition-case nil
      (truncate (* (float-time (date-to-time ts)) 1000))
    (error nil)))

;;;;; Render to file

(defun claude-log--render-front-matter (session-id jsonl-file jsonl-size)
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

(defun claude-log--extract-session-metadata-from-entries (entries)
  "Extract project and date from ENTRIES as a plist.
Returns (:project SHORT-NAME :date DATE-STRING)."
  (let* ((first-msg (claude-log--find-first-message entries))
         (progress (claude-log--find-progress-entry entries))
         (date (when first-msg
                 (claude-log--format-iso-timestamp
                  (plist-get first-msg :timestamp))))
         (project (when progress (or (plist-get progress :cwd) ""))))
    (list :project (claude-log--short-project (or project ""))
          :date (or date "unknown"))))

(defun claude-log--render-to-file (session-id metadata &optional output-path)
  "Render the JSONL for SESSION-ID to a Markdown file.
METADATA is a plist with :file, :timestamp, :project, :display.
If OUTPUT-PATH is given, write there; otherwise compute from METADATA.
Returns (RENDERED-PATH . JSONL-SIZE)."
  (let* ((jsonl-file (plist-get metadata :file))
         (entries (claude-log--parse-jsonl-file jsonl-file))
         (conversation (claude-log--filter-conversation entries))
         (rendered-path (or output-path
                            (claude-log--rendered-filepath session-id metadata)))
         (jsonl-size (file-attribute-size (file-attributes jsonl-file)))
         (session-meta (claude-log--extract-session-metadata-from-entries
                        entries)))
    (make-directory (file-name-directory rendered-path) t)
    (with-temp-file rendered-path
      (insert (claude-log--render-front-matter
               session-id jsonl-file jsonl-size))
      (insert (format "# Session: %s — %s\n\n"
                      (plist-get session-meta :project)
                      (plist-get session-meta :date)))
      (dolist (entry conversation)
        (insert (claude-log--render-entry entry))))
    (cons rendered-path jsonl-size)))

(defun claude-log--ensure-rendered (session-id metadata)
  "Ensure SESSION-ID has an up-to-date rendered .md file.
METADATA is a plist with :file, :timestamp, :project, :display.
Returns the path to the rendered file."
  (let* ((index (claude-log--read-index))
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
      (let ((result (claude-log--render-to-file session-id metadata)))
        (claude-log--index-update-props
         session-id (list :file (car result) :jsonl-size (cdr result)))
        (car result)))))

(defun claude-log--open-rendered (session-id metadata)
  "Open the rendered .md file for SESSION-ID.
METADATA is a plist with :file, :timestamp, :project, :display."
  (let* ((rendered-path (claude-log--ensure-rendered session-id metadata))
         (buf (find-file-noselect rendered-path)))
    (with-current-buffer buf
      (claude-log--activate-mode)
      (setq claude-log--source-file (plist-get metadata :file)
            claude-log--session-id session-id
            claude-log--rendered-file rendered-path
            claude-log--session-project (plist-get metadata :project))
      (claude-log--record-offset)
      (when (and claude-log-live-update (not claude-log--watcher))
        (claude-log--start-watcher))
      (claude-log--collapse-as-configured)
      (claude-log--maybe-insert-summary session-id)
      (goto-char (point-min)))
    (pop-to-buffer buf)))

(defun claude-log--append-to-file (file text)
  "Append TEXT to FILE on disk."
  (write-region text nil file t 'quiet))

;;;;; Session browser

(defun claude-log--read-sessions ()
  "Parse `history.jsonl' and return alist of session-id to metadata.
Each value is a plist (:display :timestamp :project :file :file-dir).
The :project field reflects the most recent CWD among sessions
sharing the same file directory, so it stays correct after project
renames or profile migrations."
  (let ((history-file (expand-file-name "history.jsonl" claude-log-directory))
        (sessions (make-hash-table :test #'equal))
        (file-index (claude-log--build-session-file-index)))
    (unless (file-exists-p history-file)
      (user-error "History file not found: %s" history-file))
    (dolist (entry (claude-log--parse-jsonl-file history-file))
      (let ((sid (plist-get entry :sessionId)))
        (when sid
          (puthash sid entry sessions))))
    ;; For each file directory, find the most recent CWD.
    (let ((dir-best-project (make-hash-table :test #'equal)))
      (maphash
       (lambda (sid entry)
         (when-let* ((file (gethash sid file-index))
                     (dir (file-name-directory file))
                     (proj (plist-get entry :project))
                     (ts (plist-get entry :timestamp)))
           (let ((existing (gethash dir dir-best-project)))
             (when (or (null existing)
                       (> (if (numberp ts) ts 0)
                          (if (numberp (car existing)) (car existing) 0)))
               (puthash dir (cons ts proj) dir-best-project)))))
       sessions)
      (let (result)
        (maphash
         (lambda (sid entry)
           (when-let* ((file (gethash sid file-index)))
             (let* ((dir (file-name-directory file))
                    (best (gethash dir dir-best-project))
                    (project (if best (cdr best)
                               (or (plist-get entry :project) ""))))
               (push (list sid
                           :display (or (plist-get entry :display) "")
                           :timestamp (plist-get entry :timestamp)
                           :project project
                           :file-dir dir
                           :file file)
                     result))))
         sessions)
        (sort result (lambda (a b)
                       (let ((ts-a (plist-get (cdr a) :timestamp))
                             (ts-b (plist-get (cdr b) :timestamp)))
                         (> (if (numberp ts-a) ts-a 0)
                            (if (numberp ts-b) ts-b 0)))))))))

(defun claude-log--build-session-file-index ()
  "Build a hash table mapping session-id to JSONL file path.
Scans the projects directory once, which is much faster than
probing per session."
  (let ((index (make-hash-table :test #'equal))
        (projects-dir (expand-file-name "projects" claude-log-directory)))
    (when (file-directory-p projects-dir)
      (dolist (dir (directory-files projects-dir t "^[^.]"))
        (when (file-directory-p dir)
          (dolist (file (directory-files dir t "\\.jsonl\\'"))
            (let ((sid (file-name-sans-extension
                        (file-name-nondirectory file))))
              (puthash sid file index))))))
    index))

(defun claude-log--find-session-file (session-id)
  "Find the JSONL file for SESSION-ID under the projects directory."
  (let ((projects-dir (expand-file-name "projects" claude-log-directory)))
    (when (file-directory-p projects-dir)
      (cl-block nil
        (dolist (dir (directory-files projects-dir t "^[^.]"))
          (when (file-directory-p dir)
            (let ((file (expand-file-name (concat session-id ".jsonl") dir)))
              (when (file-exists-p file)
                (cl-return file)))))))))

(defun claude-log--browse-flat (sessions)
  "Present all SESSIONS in a single `completing-read'."
  (let* ((candidates (claude-log--build-candidates sessions))
         (selected (claude-log--completing-read "Session: " candidates))
         (value (alist-get selected candidates nil nil #'equal))
         (session-id (car value))
         (metadata (cdr value)))
    (claude-log--open-rendered session-id metadata)))

(defun claude-log--browse-grouped (sessions)
  "Present SESSIONS grouped by project: first pick project, then session."
  (let* ((grouped (claude-log--group-by-project sessions))
         (project-names (mapcar #'car grouped))
         (project (claude-log--completing-read "Project: " project-names))
         (project-sessions (alist-get project grouped nil nil #'equal))
         (candidates (claude-log--build-candidates project-sessions))
         (selected (claude-log--completing-read "Session: " candidates))
         (value (alist-get selected candidates nil nil #'equal))
         (session-id (car value))
         (metadata (cdr value)))
    (claude-log--open-rendered session-id metadata)))

(defun claude-log--completing-read (prompt collection)
  "Read from COLLECTION with PROMPT, preserving display order."
  (completing-read prompt
                   (claude-log--preserve-order-table collection)
                   nil t))

(defun claude-log--group-by-project (sessions)
  "Group SESSIONS into an alist of (project-name . sessions).
Groups by the full :project path so sessions that share a
project stay together even across file directories.
Projects are sorted by most recent session timestamp."
  (let ((groups (make-hash-table :test #'equal)))
    (dolist (session sessions)
      (let* ((project (or (plist-get (cdr session) :project) ""))
             (existing (gethash project groups)))
        (puthash project (append existing (list session)) groups)))
    (let (result)
      (maphash (lambda (project group-sessions)
                 (let ((name (claude-log--short-project project)))
                   (push (cons name group-sessions) result)))
               groups)
      ;; Sort by most recent session timestamp.
      ;; Each element is (project (sid . plist) ...), so cadr is the
      ;; first session and cdadr is its metadata plist.
      (sort result (lambda (a b)
                     (let ((ts-a (plist-get (cdadr a) :timestamp))
                           (ts-b (plist-get (cdadr b) :timestamp)))
                       (> (if (numberp ts-a) ts-a 0)
                          (if (numberp ts-b) ts-b 0))))))))

(defun claude-log--build-candidates (sessions)
  "Build an alist of (display-string . (session-id . metadata)) from SESSIONS."
  (let* ((index (claude-log--read-index))
         (proj-width (claude-log--max-project-width sessions))
         ;; date (16) + 2 gaps (2+2) + project + 2 padding = fixed cols
         (fixed-cols (+ 16 2 proj-width 2))
         (summary-width (max 20 (- (frame-width) fixed-cols 1)))
         (fmt (format "%%s  %%-%ds  %%s" proj-width)))
    (mapcar
     (lambda (session)
       (let* ((session-id (car session))
              (meta (cdr session))
              (ts (plist-get meta :timestamp))
              (date (claude-log--format-epoch-ms ts))
              (project (claude-log--short-project (plist-get meta :project)))
              (index-entry (gethash session-id index))
              (oneline (when index-entry
                         (plist-get index-entry :summary-oneline)))
              (label (if oneline
                         (format fmt date project
                                 (claude-log--truncate-string
                                  oneline summary-width))
                       (let ((display (claude-log--normalize-whitespace
                                       (plist-get meta :display))))
                         (format fmt date project
                                 (concat "\"" (claude-log--truncate-string
                                               display (- summary-width 2))
                                         "\""))))))
         (cons label (cons session-id meta))))
     sessions)))

(defun claude-log--max-project-width (sessions)
  "Return the maximum display width of project names in SESSIONS."
  (let ((max-w 0))
    (dolist (session sessions max-w)
      (let* ((project (claude-log--short-project
                       (plist-get (cdr session) :project)))
             (w (string-width project)))
        (when (> w max-w) (setq max-w w))))))

(defun claude-log--short-project (path)
  "Extract a short project name from PATH."
  (if (or (null path) (string-empty-p path))
      "unknown"
    (file-name-nondirectory (directory-file-name path))))

(defun claude-log--format-epoch-ms (ms)
  "Format millisecond epoch timestamp MS as a date-time string."
  (if (numberp ms)
      (format-time-string "%Y-%m-%d %H:%M" (seconds-to-time (/ ms 1000.0)))
    "unknown"))

;;;;; JSONL parsing

(defun claude-log--parse-jsonl-file (file)
  "Parse FILE as JSONL, returning a list of plists.
Malformed lines are silently skipped."
  (let ((lines (claude-log--read-file-lines file)))
    (delq nil
          (mapcar (lambda (line)
                    (condition-case nil
                        (claude-log--parse-json-line line)
                      (error nil)))
                  lines))))

(defun claude-log--read-file-lines (file)
  "Read FILE and return a list of non-empty lines."
  (with-temp-buffer
    (insert-file-contents file)
    (split-string (buffer-string) "\n" t)))

(defun claude-log--parse-json-line (line)
  "Parse a single JSON LINE into a plist."
  (json-parse-string line :object-type 'plist :array-type 'list))

(defun claude-log--filter-conversation (entries)
  "Filter ENTRIES to user and assistant messages, excluding system entries."
  (seq-filter #'claude-log--conversation-entry-p entries))

(defun claude-log--conversation-entry-p (entry)
  "Return non-nil if ENTRY is a genuine conversation message."
  (let ((type (plist-get entry :type)))
    (and (member type '("user" "assistant"))
         (not (claude-log--system-entry-p entry)))))

(defconst claude-log--system-tag-regexp
  (rx bos (0+ space) "<"
      (or "local-command-caveat"
          "local-command-stdout"
          "local-command-stderr"
          "command-name"
          "command-message"
          "task-notification"
          "teammate-message")
      (or ">" " "))
  "Regexp matching system-generated XML tags in user entries.")

(defun claude-log--system-entry-p (entry)
  "Return non-nil if ENTRY is a system-generated message.
These are user-role entries whose string content starts with a
known system XML tag."
  (let* ((content (plist-get (plist-get entry :message) :content)))
    (and (stringp content)
         (string-match-p claude-log--system-tag-regexp content))))

;;;;; Entry helpers

(defun claude-log--find-first-message (entries)
  "Return the first user or assistant entry from ENTRIES."
  (seq-find (lambda (e) (member (plist-get e :type) '("user" "assistant")))
            entries))

(defun claude-log--find-progress-entry (entries)
  "Return the first progress entry from ENTRIES."
  (seq-find (lambda (e) (equal (plist-get e :type) "progress"))
            entries))

;;;;; Rendering

(defun claude-log--render-full ()
  "Render the full JSONL file into the current buffer."
  (let* ((entries (claude-log--parse-jsonl-file claude-log--source-file))
         (conversation (claude-log--filter-conversation entries)))
    (claude-log--extract-session-metadata entries)
    (let ((inhibit-read-only t))
      (erase-buffer)
      (insert (claude-log--render-header))
      (dolist (entry conversation)
        (insert (claude-log--render-entry entry)))
      (claude-log--record-offset)
      (goto-char (point-min))
      (claude-log--collapse-as-configured))))

(defun claude-log--extract-session-metadata (entries)
  "Extract project and date from ENTRIES."
  (when-let* ((first-msg (claude-log--find-first-message entries)))
    (setq claude-log--session-date
          (claude-log--format-iso-timestamp (plist-get first-msg :timestamp))))
  (when-let* ((progress (claude-log--find-progress-entry entries)))
    (setq claude-log--session-project
          (or (plist-get progress :cwd) ""))))

(defun claude-log--render-header ()
  "Return the Markdown header for the session."
  (let ((project (claude-log--short-project
                  (or claude-log--session-project "")))
        (date (or claude-log--session-date "unknown")))
    (format "# Session: %s — %s\n\n" project date)))

(defun claude-log--render-entry (entry)
  "Render a single conversation ENTRY to a Markdown string."
  (let ((message (plist-get entry :message)))
    (if (not message)
        ""
      (let* ((timestamp (plist-get entry :timestamp))
             (role (plist-get message :role))
             (content (plist-get message :content))
             (time-str (claude-log--format-iso-timestamp timestamp)))
        (cond
         ((equal role "user")
          (claude-log--render-user-turn content time-str))
         ((equal role "assistant")
          (claude-log--render-assistant-turn content time-str))
         (t ""))))))

(defun claude-log--render-user-turn (content time-str)
  "Render a user turn with CONTENT and TIME-STR.
If CONTENT contains only tool results and no user text, render
them without a User heading."
  (if (stringp content)
      (format "---\n\n## User — %s\n\n%s\n\n" time-str content)
    (let ((text-parts (claude-log--collect-user-text content))
          (tool-parts (claude-log--collect-tool-results content)))
      (cond
       (text-parts
        (concat (format "---\n\n## User — %s\n\n" time-str)
                (string-join text-parts)
                (string-join tool-parts)))
       (tool-parts
        (string-join tool-parts))
       (t "")))))

(defun claude-log--collect-user-text (content)
  "Collect non-empty text parts from user CONTENT array.
Returns a list of formatted strings, or nil if there is no text."
  (let (parts)
    (dolist (item content)
      (when (equal (plist-get item :type) "text")
        (let ((text (plist-get item :text)))
          (when (and text (not (string-empty-p (string-trim text))))
            (push (format "%s\n\n" text) parts)))))
    (nreverse parts)))

(defun claude-log--collect-tool-results (content)
  "Collect tool result parts from user CONTENT array.
Returns a list of formatted strings, or nil if there are none."
  (let (parts)
    (dolist (item content)
      (when (equal (plist-get item :type) "tool_result")
        (push (claude-log--render-tool-result item) parts)))
    (nreverse parts)))

(defun claude-log--render-assistant-turn (content time-str)
  "Render an assistant turn with CONTENT and TIME-STR.
Returns an empty string if CONTENT produces no visible output."
  (let ((body (claude-log--render-assistant-body content)))
    (if (string-empty-p body)
        ""
      (concat (format "---\n\n## Assistant — %s\n\n" time-str) body))))

(defun claude-log--render-assistant-body (content)
  "Render the body of an assistant turn from CONTENT items."
  (let ((parts '()))
    (when (listp content)
      (dolist (item content)
        (let ((item-type (plist-get item :type)))
          (cond
           ((equal item-type "thinking")
            (push (claude-log--render-thinking item) parts))
           ((equal item-type "text")
            (let ((text (plist-get item :text)))
              (when (and text (not (string-empty-p (string-trim text))))
                (push (format "%s\n\n" text) parts))))
           ((equal item-type "tool_use")
            (push (claude-log--render-tool-use item) parts))))))
    (apply #'concat (nreverse parts))))

(defun claude-log--render-thinking (item)
  "Render a thinking ITEM."
  (let* ((text (or (plist-get item :thinking) ""))
         (truncated (claude-log--truncate-string text claude-log-max-tool-result-length))
         (clean (replace-regexp-in-string "\n\n+" "\n" truncated)))
    (format "#### Thinking\n\n%s\n\n" clean)))

(defun claude-log--render-tool-use (item)
  "Render a tool_use ITEM with a smart summary of its input."
  (let* ((name (plist-get item :name))
         (input (plist-get item :input))
         (summary (claude-log--summarize-tool-input name input)))
    (format "#### Tool: %s\n\n%s\n\n" name summary)))

(defun claude-log--render-tool-result (item)
  "Render a tool_result ITEM."
  (let* ((content (plist-get item :content))
         (text (claude-log--extract-tool-result-text content))
         (truncated (claude-log--truncate-string text claude-log-max-tool-result-length)))
    (format "#### Tool result\n\n> %s\n\n"
            (string-replace "\n" "\n> " truncated))))

(defun claude-log--extract-tool-result-text (content)
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

(defun claude-log--summarize-tool-input (name input)
  "Return a concise summary of INPUT for tool NAME."
  (let ((summary (claude-log--summarize-tool-input-by-name name input)))
    (if (string-empty-p summary)
        (claude-log--summarize-tool-input-generic input)
      summary)))

(defun claude-log--summarize-tool-input-by-name (name input)
  "Return a summary of tool INPUT specific to tool NAME."
  (pcase name
    ((or "Read" "Write")
     (format "> **file_path**: %s" (or (plist-get input :file_path) "?")))
    ("Edit" (claude-log--summarize-edit input))
    ("Bash" (claude-log--summarize-bash input))
    ("Grep" (claude-log--summarize-grep input))
    ("Glob" (claude-log--summarize-glob input))
    ("WebFetch" (claude-log--summarize-web-fetch input))
    ("WebSearch" (claude-log--summarize-web-search input))
    ("Task" (claude-log--summarize-task input))
    (_ "")))

(defun claude-log--summarize-edit (input)
  "Summarize Edit tool INPUT."
  (let ((file (or (plist-get input :file_path) "?"))
        (old (claude-log--truncate-string
              (or (plist-get input :old_string) "")
              claude-log-max-tool-input-length)))
    (format "> **file_path**: %s\n> **old_string**: `%s`" file old)))

(defun claude-log--summarize-bash (input)
  "Summarize Bash tool INPUT."
  (let ((cmd (claude-log--truncate-string
              (or (plist-get input :command) "") claude-log-max-tool-input-length)))
    (format "> ```\n> %s\n> ```" cmd)))

(defun claude-log--summarize-grep (input)
  "Summarize Grep tool INPUT."
  (let ((pattern (or (plist-get input :pattern) "?"))
        (path (or (plist-get input :path) "")))
    (if (string-empty-p path)
        (format "> **pattern**: `%s`" pattern)
      (format "> **pattern**: `%s` in %s" pattern path))))

(defun claude-log--summarize-glob (input)
  "Summarize Glob tool INPUT."
  (format "> **pattern**: `%s`" (or (plist-get input :pattern) "?")))

(defun claude-log--summarize-web-fetch (input)
  "Summarize WebFetch tool INPUT."
  (format "> **url**: %s" (or (plist-get input :url) "?")))

(defun claude-log--summarize-web-search (input)
  "Summarize WebSearch tool INPUT."
  (format "> **query**: %s" (or (plist-get input :query) "?")))

(defun claude-log--summarize-task (input)
  "Summarize Task tool INPUT."
  (let ((desc (or (plist-get input :description) ""))
        (type (or (plist-get input :subagent_type) "")))
    (if (string-empty-p type)
        (format "> %s" desc)
      (format "> **%s**: %s" type desc))))

(defun claude-log--summarize-tool-input-generic (input)
  "Return a generic summary of tool INPUT plist.
Returns an empty string if INPUT is not a proper plist."
  (if (not (and (listp input) (cl-evenp (length input))))
      ""
    (let ((parts '()))
      (cl-loop for (key val) on input by #'cddr
               when (keywordp key)
               do (let* ((k (substring (symbol-name key) 1))
                         (v (claude-log--truncate-string
                             (format "%s" val)
                             claude-log-max-tool-input-length)))
                    (push (format "> **%s**: %s" k v) parts)))
      (string-join (nreverse parts) "\n"))))

;;;;; Timestamps

(defun claude-log--format-iso-timestamp (ts)
  "Format ISO 8601 timestamp TS according to `claude-log-timestamp-format'."
  (if (and (stringp ts) (not (string-empty-p ts)))
      (claude-log--parse-and-format-iso ts)
    "unknown"))

(defun claude-log--parse-and-format-iso (ts)
  "Parse ISO 8601 string TS and format it."
  (condition-case nil
      (let ((time (date-to-time ts)))
        (format-time-string claude-log-timestamp-format time))
    (error ts)))

;;;;; Utilities

(defun claude-log--preserve-order-table (collection)
  "Wrap COLLECTION in a completion table that preserves display order.
COLLECTION is a list of strings or an alist of (string . value)."
  (lambda (string pred action)
    (if (eq action 'metadata)
        '(metadata (display-sort-function . identity)
                   (cycle-sort-function . identity))
      (complete-with-action action collection string pred))))

(defun claude-log--normalize-whitespace (str)
  "Collapse all whitespace in STR into single spaces and trim."
  (string-trim (replace-regexp-in-string "[\n\r\t ]+" " " (or str ""))))

(defun claude-log--truncate-string (str max)
  "Truncate STR to MAX characters, appending ellipsis if needed."
  (if (<= (length str) max)
      str
    (concat (substring str 0 max) "…")))

;;;;; Major mode

(defvar claude-log-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "n" #'claude-log-next-turn)
    (define-key map "p" #'claude-log-previous-turn)
    (define-key map (kbd "TAB") #'claude-log-toggle-section)
    (define-key map "C" #'claude-log-collapse-all-tools)
    (define-key map "E" #'claude-log-expand-all)
    (define-key map "g" #'claude-log-refresh)
    (define-key map "w" #'claude-log-copy-turn)
    (define-key map "r" #'claude-log-resume-session)
    (define-key map "?" #'claude-log-menu)
    (define-key map "q" #'quit-window)
    map)
  "Keymap for `claude-log-mode'.")

(define-derived-mode claude-log-mode markdown-view-mode "Claude-Log"
  "Major mode for viewing Claude Code conversation logs.
\\{claude-log-mode-map}"
  (setq-local outline-regexp "##+ ")
  (setq-local outline-level #'claude-log--outline-level)
  (outline-minor-mode 1)
  (add-to-invisibility-spec '(claude-log-collapsed . t))
  (add-to-invisibility-spec 'claude-log-hidden)
  (add-hook 'kill-buffer-hook #'claude-log--cleanup nil t))

(defun claude-log--outline-level ()
  "Return the outline level based on the number of `#' characters."
  (- (match-end 0) (match-beginning 0) 1))

(defun claude-log--cleanup ()
  "Clean up file watcher and update index when buffer is killed."
  (when claude-log--watcher
    (file-notify-rm-watch claude-log--watcher)
    (setq claude-log--watcher nil))
  (when (and claude-log--session-id claude-log--rendered-file claude-log--source-file)
    (let ((final-size (file-attribute-size
                       (file-attributes claude-log--source-file))))
      (when final-size
        (claude-log--index-update claude-log--session-id
                                  claude-log--rendered-file
                                  final-size)))))

;;;;; Live updates

(defun claude-log--record-offset ()
  "Record the current byte size of the source file."
  (when claude-log--source-file
    (setq claude-log--file-offset
          (file-attribute-size (file-attributes claude-log--source-file)))))

(defun claude-log--start-watcher ()
  "Start watching the JSONL file for change events."
  (setq claude-log--watcher
        (file-notify-add-watch
         claude-log--source-file '(change)
         (let ((buf (current-buffer)))
           (lambda (_event)
             (when (buffer-live-p buf)
               (with-current-buffer buf
                 (claude-log--handle-file-change))))))))

(defun claude-log--handle-file-change ()
  "Handle a change notification on the JSONL file."
  (when (and claude-log--source-file
             (file-exists-p claude-log--source-file))
    (let* ((new-size (file-attribute-size
                      (file-attributes claude-log--source-file)))
           (at-end (>= (point) (point-max))))
      (when (and new-size (> new-size claude-log--file-offset))
        (condition-case err
            (let ((new-text (claude-log--read-bytes-from
                             claude-log--source-file
                             claude-log--file-offset new-size)))
              (setq claude-log--file-offset new-size)
              (claude-log--process-incremental-text new-text at-end))
          (error
           (message "claude-log: error reading incremental update: %s"
                    (error-message-string err))))))))

(defun claude-log--incomplete-utf8-tail-length (unibyte-str)
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

(defun claude-log--read-bytes-from (file start end)
  "Read bytes from FILE between START and END offsets.
Handles incomplete UTF-8 sequences at chunk boundaries by saving
trailing partial bytes in `claude-log--partial-bytes' and
prepending any previously saved bytes."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (when claude-log--partial-bytes
      (insert claude-log--partial-bytes))
    (let ((coding-system-for-read 'raw-text))
      (insert-file-contents file nil start end))
    (let ((tail (claude-log--incomplete-utf8-tail-length
                 (buffer-substring-no-properties (point-min) (point-max)))))
      (if (> tail 0)
          (progn
            (setq claude-log--partial-bytes
                  (buffer-substring-no-properties (- (point-max) tail) (point-max)))
            (delete-region (- (point-max) tail) (point-max)))
        (setq claude-log--partial-bytes nil))
      (decode-coding-region (point-min) (point-max) 'utf-8 t))))

(defun claude-log--process-incremental-text (text at-end)
  "Parse new TEXT from the JSONL file and append rendered entries.
If AT-END is non-nil, scroll to show new content."
  (let* ((combined (concat claude-log--partial-line text))
         (lines (split-string combined "\n")))
    (setq claude-log--partial-line (car (last lines)))
    (let ((complete-lines (butlast lines)))
      (dolist (line complete-lines)
        (unless (string-empty-p line)
          (claude-log--append-rendered-line line))))
    (when at-end
      (goto-char (point-max)))))

(defun claude-log--append-rendered-line (line)
  "Parse LINE as JSON and append its rendering if it is a conversation entry.
Appends to both the buffer and the rendered .md file on disk."
  (when-let* ((entry (claude-log--try-parse-json line)))
    (when (claude-log--conversation-entry-p entry)
      (let ((rendered (claude-log--render-entry entry))
            (inhibit-read-only t))
        (when claude-log--rendered-file
          (claude-log--append-to-file claude-log--rendered-file rendered))
        (save-excursion
          (goto-char (point-max))
          (insert rendered)
          (claude-log--collapse-region
           (- (point-max) (length rendered)) (point-max)))))))

(defun claude-log--try-parse-json (line)
  "Parse LINE as JSON, returning nil if it is not valid JSON."
  (ignore-errors (claude-log--parse-json-line line)))

;;;;; Navigation commands

(defun claude-log-next-turn ()
  "Move point to the next User or Assistant heading."
  (interactive)
  (let ((pos (claude-log--find-turn-heading t)))
    (if pos
        (goto-char pos)
      (message "No more turns"))))

(defun claude-log-previous-turn ()
  "Move point to the previous User or Assistant heading."
  (interactive)
  (let ((pos (claude-log--find-turn-heading nil)))
    (if pos
        (goto-char pos)
      (message "No previous turns"))))

(defun claude-log--find-turn-heading (forward)
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

(defun claude-log-toggle-section ()
  "Toggle the visibility of the section at point."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (cond
     ((looking-at "^####+ ")
      (let* ((heading-end (save-excursion (end-of-line) (point)))
             (ov (cl-find-if (lambda (o) (overlay-get o 'claude-log-section))
                             (overlays-at heading-end))))
        (if ov
            (delete-overlay ov)
          (let ((section-end (claude-log--find-section-end)))
            (when (< heading-end section-end)
              (let ((new-ov (make-overlay heading-end section-end nil t)))
                (overlay-put new-ov 'invisible 'claude-log-collapsed)
                (overlay-put new-ov 'claude-log-section t)))))))
     (t
      (when (bound-and-true-p outline-minor-mode)
        (outline-toggle-children))))))

(defun claude-log-collapse-all-tools ()
  "Collapse all tool-use, tool-result, and thinking sections."
  (interactive)
  (claude-log--remove-section-overlays)
  (claude-log--apply-section-visibility "^####+ " 'collapse))

(defun claude-log-expand-all ()
  "Expand all sections."
  (interactive)
  (let ((inhibit-read-only t))
    (if (fboundp 'outline-show-all)
        (outline-show-all)
      (outline-flag-region (point-min) (point-max) nil))
    (claude-log--remove-section-overlays)))

(defun claude-log--collapse-as-configured ()
  "Collapse or hide sections per user configuration."
  (claude-log--remove-section-overlays)
  (pcase claude-log-show-thinking
    ('collapsed (claude-log--apply-section-visibility "^#### Thinking$" 'collapse))
    ('hidden (claude-log--apply-section-visibility "^#### Thinking$" 'hide)))
  (pcase claude-log-show-tools
    ('collapsed (claude-log--apply-section-visibility "^#### Tool" 'collapse))
    ('hidden (claude-log--apply-section-visibility "^#### Tool" 'hide)))
  (claude-log--hide-empty-turns))

(defun claude-log--find-section-end ()
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

(defun claude-log--apply-section-visibility (regexp action &optional start end)
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
                            (claude-log--find-section-end)))
             (ov-start (if (eq action 'collapse) heading-end heading-start))
             (inv-spec (if (eq action 'collapse)
                           'claude-log-collapsed
                         'claude-log-hidden)))
        (when (< ov-start section-end)
          (let ((ov (make-overlay ov-start section-end nil t)))
            (overlay-put ov 'invisible inv-spec)
            (overlay-put ov 'claude-log-section t)))
        (goto-char section-end)))))

(defun claude-log--collapse-region (start end)
  "Collapse or hide new sections between START and END."
  (pcase claude-log-show-thinking
    ('collapsed (claude-log--apply-section-visibility
                 "^#### Thinking$" 'collapse start end))
    ('hidden (claude-log--apply-section-visibility
              "^#### Thinking$" 'hide start end)))
  (pcase claude-log-show-tools
    ('collapsed (claude-log--apply-section-visibility
                 "^#### Tool" 'collapse start end))
    ('hidden (claude-log--apply-section-visibility
              "^#### Tool" 'hide start end))))

(defun claude-log--remove-section-overlays ()
  "Remove all section visibility overlays from the current buffer."
  (dolist (ov (overlays-in (point-min) (point-max)))
    (when (overlay-get ov 'claude-log-section)
      (delete-overlay ov))))

(defun claude-log--hide-empty-turns ()
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
        (when (claude-log--region-all-invisible-p content-start turn-end)
          (let ((ov (make-overlay turn-start turn-end nil t)))
            (overlay-put ov 'invisible 'claude-log-hidden)
            (overlay-put ov 'claude-log-section t)))))))

(defun claude-log--region-all-invisible-p (start end)
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

(defun claude-log-refresh ()
  "Re-render from JSONL source and reload buffer."
  (interactive)
  (when claude-log--source-file
    (setq claude-log--partial-line "")
    (if (and claude-log--session-id claude-log--rendered-file)
        (let ((metadata (list :file claude-log--source-file
                              :timestamp nil
                              :project (or claude-log--session-project "")
                              :display "")))
          (claude-log--render-to-file
           claude-log--session-id metadata claude-log--rendered-file)
          (let ((inhibit-read-only t))
            (erase-buffer)
            (insert-file-contents claude-log--rendered-file)
            (set-buffer-modified-p nil)
            (goto-char (point-min))
            (claude-log--collapse-as-configured)
            (claude-log--maybe-insert-summary claude-log--session-id)
            (claude-log--record-offset)))
      (claude-log--render-full))))

(defun claude-log-copy-turn ()
  "Copy the current turn (from ## heading to next ##) to the kill ring."
  (interactive)
  (let ((start (claude-log--turn-start))
        (end (claude-log--turn-end)))
    (when (and start end)
      (kill-ring-save start end)
      (message "Turn copied"))))

(defun claude-log--turn-start ()
  "Return the start position of the current turn heading."
  (save-excursion
    (beginning-of-line)
    (if (looking-at "^## ")
        (point)
      (when (re-search-backward "^## " nil t)
        (point)))))

(defun claude-log--turn-end ()
  "Return the end position of the current turn."
  (save-excursion
    (when-let* ((start (claude-log--turn-start)))
      (goto-char start)
      (forward-line 1)
      (if (re-search-forward "^## " nil t)
          (match-beginning 0)
        (point-max)))))

;;;;; Session summaries

(defconst claude-log--summary-system-message
  "You are a concise summarizer. Given a conversation between a user and an AI \
coding assistant, produce a JSON object with exactly two fields:
- \"oneline\": A single-line summary (max 80 characters) capturing the main task \
or topic.
- \"summary\": A paragraph of 3-5 sentences describing what was discussed, what \
was accomplished, and key outcomes.
Respond with ONLY the JSON object, no markdown formatting, no code fences, \
no other text."
  "System message for summary generation.")

(defun claude-log--find-backend-for-model (model)
  "Return the gptel backend that provides MODEL, or nil."
  (cl-loop for (_name . backend) in gptel--known-backends
           when (member model (gptel-backend-models backend))
           return backend))

(defun claude-log--resolve-summary-backend-and-model ()
  "Return (backend . model) for summary generation.
Resolves `claude-log-summary-backend' and `claude-log-summary-model',
inferring the backend from the model when needed."
  (let* ((model (or claude-log-summary-model gptel-model))
         (backend (cond
                   (claude-log-summary-backend
                    (gptel-get-backend claude-log-summary-backend))
                   (claude-log-summary-model
                    (or (claude-log--find-backend-for-model
                         claude-log-summary-model)
                        gptel-backend))
                   (t gptel-backend))))
    (cons backend model)))

(defun claude-log--extract-message-text (content)
  "Extract plain text from message CONTENT, ignoring tool calls and thinking."
  (cond
   ((stringp content) content)
   ((listp content)
    (let ((texts '()))
      (dolist (item content)
        (when (equal (plist-get item :type) "text")
          (let ((text (plist-get item :text)))
            (when (and text (not (string-empty-p (string-trim text))))
              (push text texts)))))
      (string-join (nreverse texts) "\n")))
   (t "")))

(defun claude-log--extract-conversation-text (entries)
  "Extract a condensed text representation of ENTRIES for summarization.
Returns a string with user and assistant messages, truncated to
`claude-log-summary-max-content-length'."
  (let ((parts '())
        (total 0)
        (max-len claude-log-summary-max-content-length))
    (dolist (entry (claude-log--filter-conversation entries))
      (when (< total max-len)
        (let* ((message (plist-get entry :message))
               (role (plist-get message :role))
               (content (plist-get message :content))
               (text (claude-log--extract-message-text content))
               (prefix (if (equal role "user") "User: " "Assistant: "))
               (line (concat prefix text "\n\n")))
          (when (and text (not (string-empty-p (string-trim text))))
            (push line parts)
            (cl-incf total (length line))))))
    (let ((result (string-join (nreverse parts))))
      (if (> (length result) max-len)
          (substring result 0 max-len)
        result))))

(defun claude-log--build-summary-prompt (conversation-text)
  "Build a prompt for summarizing CONVERSATION-TEXT."
  (format "Summarize this conversation:\n\n---\n%s\n---" conversation-text))

(defun claude-log--parse-summary-response (response)
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

(declare-function claude-code--buffer-p "claude-code")

(defvar-local claude-code-extras--status-data nil)

(defun claude-log--active-session-ids ()
  "Return a list of session IDs for live Claude Code sessions.
Requires `claude-code' and `claude-code-extras' for session ID
extraction.  Returns nil if either is unavailable."
  (when (require 'claude-code nil t)
    (let (ids)
      (dolist (buf (buffer-list))
        (when (and (buffer-live-p buf)
                   (claude-code--buffer-p buf)
                   (when-let* ((proc (get-buffer-process buf)))
                     (process-live-p proc)))
          (when-let* ((data (buffer-local-value
                             'claude-code-extras--status-data buf))
                      (sid (plist-get data :session_id)))
            (push sid ids))))
      (delete-dups ids))))

(defun claude-log--sessions-needing-summary (sessions index)
  "Return sessions from SESSIONS that lack a summary in INDEX.
Sessions with a live Claude Code process are excluded by session ID."
  (let ((active-ids (claude-log--active-session-ids)))
    (seq-filter
     (lambda (session)
       (let* ((sid (car session))
              (entry (gethash sid index)))
         (and (not (and entry (plist-get entry :summary-oneline)))
              (not (member sid active-ids)))))
     sessions)))

;;;###autoload
(defun claude-log-summarize-sessions ()
  "Generate AI summaries for all sessions that lack one.
If summary generation is already in progress, stop it instead."
  (interactive)
  (unless (require 'gptel nil t)
    (user-error "Package `gptel' is required for summary generation"))
  (cond
   (claude-log--summarize-active
    (claude-log-stop-summarizing))
   (t
    (let* ((sessions (claude-log--read-sessions))
           (index (claude-log--read-index))
           (pending (claude-log--sessions-needing-summary sessions index)))
      (if (null pending)
          (message "All %d sessions already have summaries" (length sessions))
        (setq claude-log--summarize-active t
              claude-log--summarize-stop nil)
        (cl-incf claude-log--summarize-generation)
        (message "Generating summaries for %d session(s)... (run again to stop)"
                 (length pending))
        (claude-log--summarize-next
         pending 0 (length pending)
         claude-log--summarize-generation))))))

;;;###autoload
(defun claude-log-stop-summarizing ()
  "Stop summary generation immediately.
Any in-flight gptel request will still complete, but its callback
will not spawn further work."
  (interactive)
  (if claude-log--summarize-active
      (progn
        ;; Bump the generation so that any pending callback or timer
        ;; from the current run becomes stale and is silently ignored.
        (cl-incf claude-log--summarize-generation)
        (setq claude-log--summarize-active nil
              claude-log--summarize-stop nil)
        (message "Summary generation stopped"))
    (message "No summary generation in progress")))

(defun claude-log--summarize-next (remaining done total gen)
  "Generate summary for the next session in REMAINING.
DONE sessions processed so far out of TOTAL.  GEN is the
generation counter; if it no longer matches
`claude-log--summarize-generation', this call is stale and does
nothing."
  (when (and claude-log--summarize-active
             (= gen claude-log--summarize-generation))
    (if (or (null remaining) claude-log--summarize-stop)
        (let ((stopped claude-log--summarize-stop))
          (setq claude-log--summarize-active nil
                claude-log--summarize-stop nil)
          (message "Summary generation %s: %d/%d session(s) done"
                   (if stopped "stopped" "complete") done total))
      (let* ((session (car remaining))
             (sid (car session))
             (meta (cdr session))
             (jsonl-file (plist-get meta :file)))
        (condition-case err
            (let* ((entries (claude-log--parse-jsonl-file jsonl-file))
                   (text (claude-log--extract-conversation-text entries)))
              (if (string-empty-p (string-trim text))
                  (progn
                    (claude-log--index-update-props
                     sid (list :summary "(no conversation)"
                               :summary-oneline "(no conversation)"))
                    (claude-log--summarize-next
                     (cdr remaining) (1+ done) total gen))
                (claude-log--summarize-one
                 sid meta text remaining done total gen)))
          (error
           (message "Failed to summarize %s: %s"
                    sid (error-message-string err))
           (run-with-timer 0.1 nil
                           #'claude-log--summarize-next
                           (cdr remaining)
                           (1+ done) total gen)))))))

(defun claude-log--summarize-one (sid meta text remaining done total gen)
  "Send a gptel request to summarize session SID.
META is the session metadata plist.  TEXT is the extracted
conversation text.  REMAINING, DONE, TOTAL, and GEN are
chain-continuation state for `claude-log--summarize-next'."
  (let* ((prompt (claude-log--build-summary-prompt text))
         (resolved (claude-log--resolve-summary-backend-and-model))
         (gptel-backend (car resolved))
         (gptel-model (cdr resolved))
         (gptel-use-tools nil)
         (request-id (cl-gensym "summarize-"))
         (display (claude-log--summarize-display-name meta text sid)))
    (message "Summarizing %d/%d with %s: %s..." (1+ done) total
             gptel-model
             (claude-log--truncate-string display 70))
    (setq claude-log--summarize-request-id request-id)
    (gptel-request prompt
      :system claude-log--summary-system-message
      :callback
      (lambda (response _info)
        (claude-log--summarize-callback
         response request-id sid remaining done total gen)))))

(defun claude-log--summarize-display-name (meta text sid)
  "Return a human-readable display name from META, TEXT, or SID."
  (let ((display (plist-get meta :display)))
    (if (or (null display)
            (string-empty-p display)
            (string-prefix-p "/" display))
        (if (string-match "\\`User: \\(.+\\)" text)
            (match-string 1 text)
          sid)
      display)))

(defun claude-log--summarize-callback (response request-id sid remaining done total gen)
  "Handle the gptel RESPONSE for a summary request.
REQUEST-ID, SID, REMAINING, DONE, TOTAL, and GEN are
chain-continuation state.  Non-string responses (tool-calls,
reasoning blocks) are ignored; only the final string response or
an error (nil) consumes the request guard and advances the chain."
  (when (eq claude-log--summarize-request-id request-id)
    (cond
     ;; Success: got a string response.
     ((stringp response)
      (setq claude-log--summarize-request-id nil)
      (when (and claude-log--summarize-active
                 (= gen claude-log--summarize-generation))
        (let ((parsed (claude-log--parse-summary-response response)))
          (if parsed
              (progn
                (claude-log--index-update-props
                 sid (list :summary (car parsed)
                           :summary-oneline (cdr parsed)))
                (when claude-log-auto-rename-sessions
                  (claude-log--maybe-rename-session sid (cdr parsed))))
            (message "Failed to parse summary for %s" sid)))
        (run-with-timer
         0.1 nil
         #'claude-log--summarize-next
         (cdr remaining)
         (1+ done) total gen)))
     ;; Error: nil response from gptel.  Clear the guard and advance.
     ((null response)
      (setq claude-log--summarize-request-id nil)
      (message "Summary request failed for %s, skipping" sid)
      (when (and claude-log--summarize-active
                 (= gen claude-log--summarize-generation))
        (run-with-timer
         0.1 nil
         #'claude-log--summarize-next
         (cdr remaining)
         (1+ done) total gen))))))

(defun claude-log--maybe-insert-summary (session-id)
  "Insert the AI summary for SESSION-ID into the current buffer, if available."
  (let* ((index (claude-log--read-index))
         (entry (gethash session-id index))
         (summary (when entry (plist-get entry :summary))))
    (when summary
      (let ((inhibit-read-only t))
        (save-excursion
          ;; Remove any existing summary first
          (claude-log--remove-inserted-summary)
          ;; Insert after the # Session: header
          (goto-char (point-min))
          (when (re-search-forward "^# Session:.*\n\n" nil t)
            (let ((start (point)))
              (insert (format "> **Summary**: %s\n\n" summary))
              (put-text-property start (point)
                                 'claude-log-summary t))))))))

(defun claude-log--remove-inserted-summary ()
  "Remove any previously inserted summary from the current buffer."
  (let ((inhibit-read-only t))
    (save-excursion
      (goto-char (point-min))
      (let ((start (text-property-any
                    (point-min) (point-max) 'claude-log-summary t)))
        (when start
          (let ((end (next-single-property-change
                      start 'claude-log-summary nil (point-max))))
            (delete-region start end)))))))

;;;;; Session rename

(defcustom claude-log-auto-rename-sessions nil
  "When non-nil, rename sessions automatically after summarization.
Each time a session receives an AI summary, its one-line summary
is slugified and written as a custom-title entry in the session
JSONL file, making it visible in Claude Code's /resume picker."
  :type 'boolean)

(defun claude-log--session-has-custom-title-p (jsonl-file)
  "Return non-nil if JSONL-FILE already contains a custom-title entry."
  (with-temp-buffer
    (insert-file-contents jsonl-file)
    (goto-char (point-min))
    (search-forward "\"type\":\"custom-title\"" nil t)))

(defun claude-log--append-custom-title (jsonl-file session-id title)
  "Append a custom-title entry to JSONL-FILE for SESSION-ID with TITLE.
Also updates the cached JSONL size in the index so that
`claude-log--ensure-rendered' does not treat the file as stale."
  (let ((entry (json-serialize
                (list :type "custom-title"
                      :customTitle title
                      :sessionId session-id))))
    (write-region (concat entry "\n") nil jsonl-file t 'quiet)
    (when-let* ((new-size (file-attribute-size (file-attributes jsonl-file))))
      (claude-log--index-update-props
       session-id (list :jsonl-size new-size)))))

(defun claude-log--maybe-rename-session (session-id oneline)
  "Rename SESSION-ID from ONELINE summary if appropriate.
Finds the session JSONL file, checks it has no custom-title yet,
and writes ONELINE as the title.  Does nothing if ONELINE is nil,
empty, or the sentinel value."
  (when (and oneline
             (not (string-empty-p oneline))
             (not (equal oneline "(no conversation)")))
    (when-let* ((jsonl-file (claude-log--find-session-file session-id)))
      (unless (claude-log--session-has-custom-title-p jsonl-file)
        (claude-log--append-custom-title
         jsonl-file session-id oneline)))))

;;;###autoload
(defun claude-log-rename-sessions (&optional force)
  "Rename sessions using their AI summaries.
For each session that has a summary in the index but no
custom-title in its JSONL file, write the summary as a
custom-title entry.  This makes the name visible in Claude
Code's /resume picker.

With prefix argument FORCE, overwrite existing custom titles.
This is useful after changing the title format (e.g. from
slugified to full-text titles).

Sessions must be summarized first via `claude-log-summarize-sessions'."
  (interactive "P")
  (let* ((sessions (claude-log--read-sessions))
         (index (claude-log--read-index))
         (renamed 0)
         (skipped 0)
         (no-summary 0))
    (dolist (session sessions)
      (let* ((sid (car session))
             (metadata (cdr session))
             (jsonl-file (plist-get metadata :file))
             (entry (gethash sid index))
             (oneline (when entry (plist-get entry :summary-oneline))))
        (cond
         ((or (null oneline)
              (string-empty-p oneline)
              (equal oneline "(no conversation)"))
          (cl-incf no-summary))
         ((not (file-exists-p jsonl-file))
          (cl-incf skipped))
         ((and (not force)
               (claude-log--session-has-custom-title-p jsonl-file))
          (cl-incf skipped))
         (t
          (let ((entry-json (json-serialize
                             (list :type "custom-title"
                                   :customTitle oneline
                                   :sessionId sid))))
            (write-region (concat entry-json "\n") nil jsonl-file t 'quiet)
            (when-let* ((new-size (file-attribute-size
                                   (file-attributes jsonl-file))))
              (claude-log--index-merge index sid (list :jsonl-size new-size))))
          (cl-incf renamed)))))
    (when (> renamed 0)
      (claude-log--write-index index))
    (message "Renamed %d session(s), skipped %d (already named), %d without summary"
             renamed skipped no-summary)))

;;;;; Session lifecycle integration

(defvar claude-code-event-hook)

(defun claude-log--session-end-handler (message)
  "Handle a Claude Code event MESSAGE, triggering sync on session end.
Intended for use in `claude-code-event-hook'.  Runs `claude-log-sync-all'
followed by `claude-log-summarize-sessions' when `:type' is \"Stop\"."
  (when (eq (plist-get message :type) 'stop)
    ;; Delay briefly to let the JSONL file finish writing.
    (run-with-timer
     1 nil
     (lambda ()
       (claude-log-sync-all
        (lambda ()
          (when (and (require 'gptel nil t)
                     (not claude-log--summarize-active))
            (claude-log-summarize-sessions))))))
    nil))

;;;;; Resume session

(declare-function claude-code--start "claude-code")
(declare-function claude-code--directory "claude-code")
(declare-function claude-code--buffer-p "claude-code")
(declare-function claude-code--extract-directory-from-buffer-name "claude-code")

(defun claude-log--extract-session-id-from-buffer ()
  "Extract session ID from the front-matter comment of the current buffer."
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "<!-- session: \\([^ ]+\\) -->" nil t)
      (match-string 1))))

(defun claude-log--lookup-session-project (session-id)
  "Look up the project directory for SESSION-ID in history.jsonl."
  (let ((history-file (expand-file-name "history.jsonl" claude-log-directory)))
    (when (file-exists-p history-file)
      (catch 'found
        (dolist (entry (claude-log--parse-jsonl-file history-file))
          (when (equal (plist-get entry :sessionId) session-id)
            (throw 'found (plist-get entry :project))))))))

(defun claude-log--session-project-directory (session-id)
  "Return the project directory for SESSION-ID.
Try the buffer-local variable first, then fall back to history.jsonl."
  (or (and claude-log--session-project
           (not (string-empty-p claude-log--session-project))
           (file-directory-p claude-log--session-project)
           claude-log--session-project)
      (when-let* ((project (claude-log--lookup-session-project session-id)))
        (and (not (string-empty-p project))
             (file-directory-p project)
             project))))

(defun claude-log-resume-session ()
  "Resume the Claude Code session for the current buffer."
  (interactive)
  (unless (require 'claude-code nil t)
    (user-error "Package `claude-code' is required but not available"))
  (let ((session-id (or claude-log--session-id
                        (claude-log--extract-session-id-from-buffer))))
    (unless session-id
      (user-error "No session ID found in current buffer"))
    (let ((project-dir (claude-log--session-project-directory session-id)))
      (if project-dir
          (cl-letf (((symbol-function 'claude-code--directory)
                     (lambda () project-dir)))
            (claude-code--start nil (list "--resume" session-id)))
        (claude-code--start nil (list "--resume" session-id))))))

(defun claude-log--encode-project-path (directory)
  "Encode DIRECTORY as Claude Code does for its projects subdirectory.
Replaces `/' and `.' characters with `-'."
  (replace-regexp-in-string
   "[/.]" "-"
   (directory-file-name (expand-file-name directory))))

(defun claude-log--find-project-session-dir (directory)
  "Find the Claude projects subdirectory for DIRECTORY.
Try both the expanded path and its `file-truename'."
  (let ((projects-dir (expand-file-name "projects" claude-log-directory)))
    (cl-loop for path in (delete-dups
                          (list (expand-file-name directory)
                                (file-truename (expand-file-name directory))))
             for encoded = (claude-log--encode-project-path path)
             for dir = (expand-file-name encoded projects-dir)
             when (file-directory-p dir) return dir)))

(defun claude-log--find-latest-jsonl (directory)
  "Find the most recently modified JSONL file in DIRECTORY."
  (let ((files (directory-files directory t "\\.jsonl\\'"))
        latest latest-time)
    (dolist (f files)
      (let ((mtime (float-time
                    (file-attribute-modification-time (file-attributes f)))))
        (when (or (null latest) (> mtime latest-time))
          (setq latest f latest-time mtime))))
    latest))

(defun claude-log--find-session-for-project (directory sessions)
  "Find the latest session in SESSIONS whose project matches DIRECTORY.
SESSIONS should be sorted newest-first (as from `claude-log--read-sessions').
DIRECTORY is compared against each session's :project field using
both the expanded path and `file-truename'."
  (let ((targets (delete-dups
                  (mapcar #'directory-file-name
                          (list (expand-file-name directory)
                                (file-truename (expand-file-name directory)))))))
    (cl-loop for session in sessions
             for project = (plist-get (cdr session) :project)
             when (and (stringp project) (not (string-empty-p project))
                       (member (directory-file-name (expand-file-name project))
                               targets))
             return session)))

;;;###autoload
(defun claude-log-open-session-at-point ()
  "Open the log for the Claude Code session in the current buffer.
The current buffer must be a Claude Code terminal buffer.
If no session directory is found via direct path lookup, fall back
to searching `history.jsonl' for sessions matching the project."
  (interactive)
  (unless (require 'claude-code nil t)
    (user-error "Package `claude-code' is required but not available"))
  (unless (claude-code--buffer-p (current-buffer))
    (user-error "Not in a Claude Code buffer"))
  (let* ((dir (claude-code--extract-directory-from-buffer-name (buffer-name)))
         (session-dir (and dir (claude-log--find-project-session-dir dir)))
         (jsonl (and session-dir (claude-log--find-latest-jsonl session-dir))))
    (if jsonl
        (claude-log-open-file jsonl)
      ;; Fallback: search history.jsonl for sessions matching this project
      (let ((match (claude-log--find-session-for-project
                    dir (claude-log--read-sessions))))
        (unless match
          (user-error "No session log found for %s" (or dir "this buffer")))
        (claude-log--open-rendered (car match) (cdr match))))))

;;;;; Transient menu

(transient-define-suffix claude-log-cycle-show-thinking ()
  "Cycle `claude-log-show-thinking' through hidden → collapsed → visible."
  :description (lambda ()
                 (format "Show thinking: %s" claude-log-show-thinking))
  :transient t
  (interactive)
  (setq claude-log-show-thinking
        (pcase claude-log-show-thinking
          ('hidden 'collapsed)
          ('collapsed 'visible)
          ('visible 'hidden)))
  (when (derived-mode-p 'claude-log-mode)
    (claude-log--collapse-as-configured))
  (message "Show thinking → %s" claude-log-show-thinking))

(transient-define-suffix claude-log-cycle-show-tools ()
  "Cycle `claude-log-show-tools' through hidden → collapsed → visible."
  :description (lambda ()
                 (format "Show tools: %s" claude-log-show-tools))
  :transient t
  (interactive)
  (setq claude-log-show-tools
        (pcase claude-log-show-tools
          ('hidden 'collapsed)
          ('collapsed 'visible)
          ('visible 'hidden)))
  (when (derived-mode-p 'claude-log-mode)
    (claude-log--collapse-as-configured))
  (message "Show tools → %s" claude-log-show-tools))

(transient-define-suffix claude-log-toggle-live-update ()
  "Toggle `claude-log-live-update'."
  :description (lambda ()
                 (format "Live update: %s"
                         (if claude-log-live-update "on" "off")))
  :transient t
  (interactive)
  (setq claude-log-live-update (not claude-log-live-update))
  (message "Live update → %s" (if claude-log-live-update "on" "off")))

(transient-define-suffix claude-log-toggle-group-by-project ()
  "Toggle `claude-log-group-by-project'."
  :description (lambda ()
                 (format "Group by project: %s"
                         (if claude-log-group-by-project "on" "off")))
  :transient t
  (interactive)
  (setq claude-log-group-by-project (not claude-log-group-by-project))
  (message "Group by project → %s"
           (if claude-log-group-by-project "on" "off")))

;;;###autoload (autoload 'claude-log-menu "claude-log" nil t)
(transient-define-prefix claude-log-menu ()
  "Transient menu for Claude Log commands."
  ["Open"
   ("b" "Browse sessions" claude-log-browse-sessions)
   ("l" "Open latest" claude-log-open-latest)
   ("f" "Open file" claude-log-open-file)
   ("d" "Open rendered directory" claude-log-open-rendered-directory)
   ("." "Open session at point" claude-log-open-session-at-point)]
  ["Sync & AI"
   ("S" "Sync all" claude-log-sync-all)
   ("s" "Summarize sessions" claude-log-summarize-sessions)
   ("R" "Rename from summaries" claude-log-rename-sessions)
   ("x" "Stop summarizing" claude-log-stop-summarizing)]
  ["Navigate"
   :if (lambda () (derived-mode-p 'claude-log-mode))
   ("n" "Next turn" claude-log-next-turn)
   ("p" "Previous turn" claude-log-previous-turn)
   ("TAB" "Toggle section" claude-log-toggle-section)
   ("C" "Collapse all tools" claude-log-collapse-all-tools)
   ("E" "Expand all" claude-log-expand-all)
   ("g" "Refresh" claude-log-refresh)
   ("w" "Copy turn" claude-log-copy-turn)
   ("r" "Resume session" claude-log-resume-session)]
  ["Settings"
   ("t" claude-log-cycle-show-thinking)
   ("o" claude-log-cycle-show-tools)
   ("u" claude-log-toggle-live-update)
   ("G" claude-log-toggle-group-by-project)])

(provide 'claude-log)
;;; claude-log.el ends here
