;;; agent-log-claude.el --- Claude Code backend for agent-log  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Pablo Stafforini

;; Author: Pablo Stafforini
;; URL: https://github.com/benthamite/agent-log
;; Version: 0.3.0
;; Package-Requires: ((agent-log "0.3.0"))
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

;; Claude Code backend for agent-log.  Implements all backend-specific
;; methods for reading sessions, parsing entries, and rendering
;; conversations from Claude Code's JSONL format.

;;; Code:

(require 'cl-lib)
(require 'agent-log)

;;;;; Soft dependency: claude-code

(defvar claude-code-event-hook)
(defvar claude-code-extras--status-data)
(declare-function claude-code--start "claude-code")
(declare-function claude-code--directory "claude-code")
(declare-function claude-code--buffer-p "claude-code")
(declare-function claude-code--extract-directory-from-buffer-name "claude-code")

;;;;; Struct definition

(cl-defstruct (agent-log-claude (:constructor agent-log--make-claude)
                                 (:include agent-log-backend)
                                 (:copier nil))
  "Claude Code backend for agent-log.")

;;;;; Constants

(defconst agent-log-claude--system-tag-regexp
  (rx bos (0+ space) "<"
      (or "local-command-caveat"
          "local-command-stdout"
          "local-command-stderr"
          "command-name"
          "command-message"
          "task-notification"
          "teammate-message")
      (or ">" " "))
  "Regexp matching system-generated XML tags in Claude Code user entries.")

(defconst agent-log-claude--status-directory "/tmp/claude-code-status/"
  "Directory where Claude Code writes per-buffer JSON status files.")

;;;;; Generic method implementations

;;;;;; Session discovery

(cl-defmethod agent-log--read-sessions ((backend agent-log-claude))
  "Parse `history.jsonl' and return alist of session-id to metadata.
Each value is a plist (:display :timestamp :project :file :file-dir :backend).
The :project field reflects the most recent CWD among sessions
sharing the same file directory, so it stays correct after project
renames or profile migrations."
  (let ((history-file (expand-file-name "history.jsonl"
                                        (agent-log-backend-directory backend)))
        (sessions (make-hash-table :test #'equal))
        (file-index (agent-log--build-session-file-index backend)))
    (unless (file-exists-p history-file)
      (user-error "History file not found: %s" history-file))
    (dolist (entry (agent-log--parse-jsonl-file history-file))
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
                       (agent-log--timestamp> ts (car existing)))
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
                           :file file
                           :backend backend)
                     result))))
         sessions)
        (sort result (lambda (a b)
                       (agent-log--timestamp>
                        (plist-get (cdr a) :timestamp)
                        (plist-get (cdr b) :timestamp))))))))

(cl-defmethod agent-log--build-session-file-index ((backend agent-log-claude))
  "Build a hash table mapping session-id to JSONL file path.
Scans the projects directory once, which is much faster than
probing per session."
  (let ((index (make-hash-table :test #'equal))
        (projects-dir (expand-file-name "projects"
                                        (agent-log-backend-directory backend))))
    (when (file-directory-p projects-dir)
      (dolist (dir (directory-files projects-dir t "^[^.]"))
        (when (file-directory-p dir)
          (dolist (file (directory-files dir t "\\.jsonl\\'"))
            (let ((sid (file-name-sans-extension
                        (file-name-nondirectory file))))
              (puthash sid file index))))))
    index))

(cl-defmethod agent-log--find-session-file ((backend agent-log-claude) session-id)
  "Find the JSONL file for SESSION-ID under the projects directory."
  (let ((projects-dir (expand-file-name "projects"
                                        (agent-log-backend-directory backend))))
    (when (file-directory-p projects-dir)
      (cl-block nil
        (dolist (dir (directory-files projects-dir t "^[^.]"))
          (when (file-directory-p dir)
            (let ((file (expand-file-name (concat session-id ".jsonl") dir)))
              (when (file-exists-p file)
                (cl-return file)))))))))

;;;;;; Entry normalization and filtering

(cl-defmethod agent-log--normalize-entries ((_backend agent-log-claude) entries)
  "Claude Code entries are already in canonical format."
  entries)

(cl-defmethod agent-log--filter-conversation ((backend agent-log-claude) entries)
  "Filter ENTRIES to user and assistant messages, excluding system entries."
  (seq-filter (lambda (entry) (agent-log--conversation-entry-p backend entry)) entries))

(cl-defmethod agent-log--conversation-entry-p ((backend agent-log-claude) entry)
  "Return non-nil if ENTRY is a genuine conversation message."
  (let ((type (plist-get entry :type)))
    (and (member type '("user" "assistant"))
         (not (agent-log--system-entry-p backend entry)))))

(cl-defmethod agent-log--system-entry-p ((_backend agent-log-claude) entry)
  "Return non-nil if ENTRY is a system-generated message.
These are user-role entries whose string content starts with a
known system XML tag."
  (let* ((content (plist-get (plist-get entry :message) :content)))
    (and (stringp content)
         (string-match-p agent-log-claude--system-tag-regexp content))))

;;;;;; Metadata extraction

(cl-defmethod agent-log--extract-session-metadata ((_backend agent-log-claude) entries)
  "Extract project and date from ENTRIES into buffer-local variables."
  (when-let* ((first-msg (agent-log--find-first-message entries)))
    (setq agent-log--session-date
          (agent-log--format-iso-timestamp (plist-get first-msg :timestamp))))
  (when-let* ((progress (agent-log--find-progress-entry entries))
              (cwd (plist-get progress :cwd))
              ((not (string-empty-p cwd))))
    (setq agent-log--session-project cwd)))

(cl-defmethod agent-log--first-user-text ((backend agent-log-claude) entries)
  "Return the text of the first user message in ENTRIES."
  (when-let* ((first-user (seq-find
                           (lambda (e)
                             (and (equal (plist-get e :type) "user")
                                  (not (agent-log--system-entry-p backend e))))
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

;;;;;; Tool input summaries

(cl-defmethod agent-log--summarize-tool-input-by-name ((_backend agent-log-claude) name input)
  "Return a summary of tool INPUT specific to tool NAME."
  (pcase name
    ((or "Read" "Write")
     (format "> **file_path**: %s" (or (plist-get input :file_path) "?")))
    ("Edit" (agent-log-claude--summarize-edit input))
    ("Bash" (agent-log-claude--summarize-bash input))
    ("Grep" (agent-log-claude--summarize-grep input))
    ("Glob" (agent-log-claude--summarize-glob input))
    ("WebFetch" (agent-log-claude--summarize-web-fetch input))
    ("WebSearch" (agent-log-claude--summarize-web-search input))
    ("Task" (agent-log-claude--summarize-task input))
    (_ "")))

(defun agent-log-claude--summarize-edit (input)
  "Summarize Edit tool INPUT."
  (let ((file (or (plist-get input :file_path) "?"))
        (old (agent-log--truncate-string
              (or (plist-get input :old_string) "")
              agent-log-max-tool-input-length)))
    (format "> **file_path**: %s\n> **old_string**: `%s`" file old)))

(defun agent-log-claude--summarize-bash (input)
  "Summarize Bash tool INPUT."
  (let ((cmd (agent-log--truncate-string
              (or (plist-get input :command) "") agent-log-max-tool-input-length)))
    (format "> ```\n> %s\n> ```" cmd)))

(defun agent-log-claude--summarize-grep (input)
  "Summarize Grep tool INPUT."
  (let ((pattern (or (plist-get input :pattern) "?"))
        (path (or (plist-get input :path) "")))
    (if (string-empty-p path)
        (format "> **pattern**: `%s`" pattern)
      (format "> **pattern**: `%s` in %s" pattern path))))

(defun agent-log-claude--summarize-glob (input)
  "Summarize Glob tool INPUT."
  (format "> **pattern**: `%s`" (or (plist-get input :pattern) "?")))

(defun agent-log-claude--summarize-web-fetch (input)
  "Summarize WebFetch tool INPUT."
  (format "> **url**: %s" (or (plist-get input :url) "?")))

(defun agent-log-claude--summarize-web-search (input)
  "Summarize WebSearch tool INPUT."
  (format "> **query**: %s" (or (plist-get input :query) "?")))

(defun agent-log-claude--summarize-task (input)
  "Summarize Task tool INPUT."
  (let ((desc (or (plist-get input :description) ""))
        (type (or (plist-get input :subagent_type) "")))
    (if (string-empty-p type)
        (format "> %s" desc)
      (format "> **%s**: %s" type desc))))

;;;;;; Message text extraction

(cl-defmethod agent-log--extract-message-text ((_backend agent-log-claude) content)
  "Extract plain text from message CONTENT.
Tool-use and thinking blocks are ignored."
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

;;;;;; Active sessions

(cl-defmethod agent-log--active-session-ids ((_backend agent-log-claude))
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

;;;;;; Resume session

(cl-defmethod agent-log--resume-session ((_backend agent-log-claude) session-id)
  "Resume the Claude Code session SESSION-ID."
  (unless (require 'claude-code nil t)
    (user-error "Package `claude-code' is required but not available"))
  (let* ((project-dir (agent-log-claude--session-project-directory session-id))
         (switches (list "--resume" session-id)))
    (if project-dir
        (cl-letf (((symbol-function 'claude-code--directory)
                   (lambda () project-dir)))
          (claude-code--start nil switches))
      (claude-code--start nil switches))))

;;;;; Claude-specific helper functions

(defun agent-log-claude--session-project-directory (session-id)
  "Return the project directory for SESSION-ID.
Try the buffer-local variable first, then fall back to history.jsonl.
The return value always has a trailing slash to match the format
returned by `claude-code--directory'."
  (when-let* ((dir (or (and agent-log--session-project
                            (not (string-empty-p agent-log--session-project))
                            (file-directory-p agent-log--session-project)
                            agent-log--session-project)
                       (when-let* ((project (agent-log-claude--lookup-session-project session-id)))
                         (and (not (string-empty-p project))
                              (file-directory-p project)
                              project)))))
    (file-name-as-directory dir)))

(defun agent-log-claude--lookup-session-project (session-id)
  "Look up the project directory for SESSION-ID in history.jsonl."
  (let ((history-file (expand-file-name "history.jsonl" agent-log-directory)))
    (when (file-exists-p history-file)
      (catch 'found
        (dolist (entry (agent-log--parse-jsonl-file history-file))
          (when (equal (plist-get entry :sessionId) session-id)
            (throw 'found (plist-get entry :project))))))))

(defun agent-log-claude--encode-project-path (directory)
  "Encode DIRECTORY as Claude Code does for its projects subdirectory.
Replaces `/', `.', and space characters with `-'."
  (replace-regexp-in-string
   "[/. ]" "-"
   (directory-file-name (expand-file-name directory))))

(defun agent-log-claude--find-project-session-dir (directory)
  "Find the Claude projects subdirectory for DIRECTORY.
Try both the expanded path and its `file-truename'."
  (let ((projects-dir (expand-file-name "projects" agent-log-directory)))
    (cl-loop for path in (delete-dups
                          (list (expand-file-name directory)
                                (file-truename (expand-file-name directory))))
             for encoded = (agent-log-claude--encode-project-path path)
             for dir = (expand-file-name encoded projects-dir)
             when (file-directory-p dir) return dir)))

(defun agent-log-claude--find-latest-jsonl (directory)
  "Find the most recently modified JSONL file in DIRECTORY."
  (let ((files (directory-files directory t "\\.jsonl\\'"))
        latest latest-time)
    (dolist (f files)
      (let ((mtime (float-time
                    (file-attribute-modification-time (file-attributes f)))))
        (when (or (null latest) (> mtime latest-time))
          (setq latest f latest-time mtime))))
    latest))

(defun agent-log-claude--read-status-file ()
  "Read the status file for the Claude session in the current buffer.
Return a plist with :session_id and :transcript_path, or nil.
The status file is written by Claude Code to
`agent-log-claude--status-directory', keyed by sanitized buffer name."
  (when-let* ((file (agent-log-claude--status-file-for-buffer))
              ((file-exists-p file)))
    (condition-case nil
        (let* ((json (json-parse-string
                      (with-temp-buffer
                        (insert-file-contents file)
                        (buffer-string))
                      :object-type 'plist))
               (sid (plist-get json :session_id))
               (path (plist-get json :transcript_path)))
          (when (and (stringp sid) (not (string-empty-p sid)))
            (list :session_id sid :transcript_path path)))
      (error nil))))

(defun agent-log-claude--session-id-from-buffer ()
  "Return the session ID for the Claude session in the current buffer.
Read it from the status file that Claude Code writes to
`agent-log-claude--status-directory', keyed by sanitized buffer name."
  (plist-get (agent-log-claude--read-status-file) :session_id))

(defun agent-log-claude--status-file-for-buffer ()
  "Return the status file path for the current buffer."
  (expand-file-name
   (concat (agent-log-claude--sanitize-buffer-name) ".json")
   agent-log-claude--status-directory))

(defun agent-log-claude--sanitize-buffer-name ()
  "Sanitize the current buffer name for use as a filename.
Replace every non-alphanumeric, non-underscore, non-hyphen
character with an underscore."
  (replace-regexp-in-string "[^a-zA-Z0-9_-]" "_" (buffer-name)))

(defun agent-log-claude--find-session-for-project (directory sessions)
  "Find the latest session in SESSIONS whose project matches DIRECTORY.
SESSIONS should be sorted newest-first (as from `agent-log--read-sessions').
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

(defun agent-log-claude--session-has-custom-title-p (jsonl-file)
  "Return non-nil if JSONL-FILE already has a custom-title entry."
  (with-temp-buffer
    (insert-file-contents jsonl-file)
    (goto-char (point-min))
    (re-search-forward "\"type\"\\s-*:\\s-*\"custom-title\"" nil t)))

(defun agent-log-claude--append-custom-title (jsonl-file session-id title &optional index)
  "Append a custom-title entry to JSONL-FILE for SESSION-ID with TITLE.
Also updates the cached JSONL size so that `agent-log--ensure-rendered'
does not treat the file as stale.  When INDEX is non-nil, merge the
new size into it (for batch operations); otherwise write to disk."
  (let ((entry (json-serialize
                (list :type "custom-title"
                      :customTitle title
                      :sessionId session-id))))
    (write-region (concat entry "\n") nil jsonl-file t 'quiet)
    (when-let* ((new-size (file-attribute-size (file-attributes jsonl-file))))
      (if index
          (agent-log--index-merge index session-id (list :jsonl-size new-size))
        (agent-log--index-update-props
         session-id (list :jsonl-size new-size))))))

(defun agent-log-claude--maybe-rename-session (session-id oneline)
  "Rename SESSION-ID from ONELINE summary if appropriate.
Finds the session JSONL file, checks it has no custom-title yet,
and writes ONELINE as the title.  Does nothing if ONELINE is nil,
empty, or the sentinel value."
  (when (and oneline
             (not (string-empty-p oneline))
             (not (equal oneline agent-log--no-conversation-sentinel)))
    (when-let* ((jsonl-file (agent-log--find-session-file session-id)))
      (unless (agent-log-claude--session-has-custom-title-p jsonl-file)
        (agent-log-claude--append-custom-title
         jsonl-file session-id oneline)))))

(defun agent-log-claude--session-end-handler (message)
  "Handle a Claude Code event MESSAGE, triggering sync on session end.
Intended for use in `claude-code-event-hook'.  Runs `agent-log-sync-all'
followed by `agent-log-summarize-sessions' when `:type' is \"Stop\"."
  (when (eq (plist-get message :type) 'stop)
    ;; Delay briefly to let the JSONL file finish writing.
    (run-with-timer
     1 nil
     (lambda ()
       (agent-log-sync-all
        (lambda ()
          (when (and (require 'gptel nil t)
                     (not agent-log--summarize-active))
            (agent-log-summarize-sessions))))))
    nil))

;;;;; Interactive commands

;;;###autoload
(defun agent-log-open-session-at-point ()
  "Open the log for the Claude Code session in the current buffer.
The current buffer must be a Claude Code terminal buffer.
When possible, identify the exact session via the status file;
otherwise fall back to the most recent JSONL in the project
directory or to `history.jsonl'."
  (interactive)
  (unless (require 'claude-code nil t)
    (user-error "Package `claude-code' is required but not available"))
  (unless (claude-code--buffer-p (current-buffer))
    (user-error "Not in a Claude Code buffer"))
  (let* ((dir (claude-code--extract-directory-from-buffer-name (buffer-name)))
         (status (agent-log-claude--read-status-file))
         ;; Primary: use transcript_path from the status file directly.
         (transcript (plist-get status :transcript_path))
         (session-id (plist-get status :session_id))
         (jsonl (or (and transcript (file-exists-p transcript) transcript)
                    ;; Secondary: construct from session-dir + session-id.
                    (let ((session-dir
                           (and dir (agent-log-claude--find-project-session-dir dir))))
                      (or (and session-id session-dir
                               (let ((f (expand-file-name
                                         (concat session-id ".jsonl")
                                         session-dir)))
                                 (and (file-exists-p f) f)))
                          (and session-dir
                               (agent-log-claude--find-latest-jsonl session-dir)))))))
    (if jsonl
        (agent-log-open-file jsonl)
      ;; Fallback: search history.jsonl for sessions matching this project
      (let ((match (agent-log-claude--find-session-for-project
                    dir (agent-log--read-sessions))))
        (unless match
          (user-error "No session log found for %s" (or dir "this buffer")))
        (agent-log--open-rendered (car match) (cdr match))))))

;;;###autoload
(defun agent-log-rename-sessions (&optional force)
  "Rename sessions using their AI summaries.
For each session that has a summary in the index but no
custom-title in its JSONL file, write the summary as a
custom-title entry.  This makes the name visible in Claude
Code's /resume picker.

With prefix argument FORCE, overwrite existing custom titles.
This is useful after changing the title format (e.g. from
slugified to full-text titles).

Sessions must be summarized first via `agent-log-summarize-sessions'."
  (interactive "P")
  (let* ((sessions (agent-log--read-sessions))
         (index (agent-log--read-index))
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
              (equal oneline agent-log--no-conversation-sentinel))
          (cl-incf no-summary))
         ((not (file-exists-p jsonl-file))
          (cl-incf skipped))
         ((and (not force)
               (agent-log-claude--session-has-custom-title-p jsonl-file))
          (cl-incf skipped))
         (t
          (agent-log-claude--append-custom-title jsonl-file sid oneline index)
          (cl-incf renamed)))))
    (when (> renamed 0)
      (agent-log--write-index index))
    (message "Renamed %d session(s), skipped %d (already named), %d without summary"
             renamed skipped no-summary)))

;;;;; Backend registration

(defvar agent-log-claude--instance
  (agent-log--make-claude
   :name "Claude Code"
   :key 'claude-code
   :directory "~/.claude"
   :rendered-directory "~/.claude/rendered"))

(agent-log--register-backend 'claude-code agent-log-claude--instance)

(provide 'agent-log-claude)
;;; agent-log-claude.el ends here
