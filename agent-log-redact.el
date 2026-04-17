;;; agent-log-redact.el --- Secret redaction for rendered agent logs  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Pablo Stafforini

;; Author: Pablo Stafforini
;; URL: https://github.com/benthamite/agent-log
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

;; Redact secrets from agent-log rendered Markdown at render time.
;;
;; Patterns are scanned over each rendered conversation entry before it
;; is written to disk or inserted into a buffer.  Matches are replaced
;; with deterministic placeholders of the form [REDACTED:LABEL:HASH8],
;; where HASH8 is the first 8 hex chars of sha256(secret + salt).  The
;; same secret always produces the same placeholder, preserving the
;; signal "this value appears in N places" without leaking the value.
;;
;; Integration is via :filter-return advice on `agent-log--render-entry',
;; which covers both the full-render path (`agent-log--render-to-file')
;; and the live-update path (`agent-log--append-rendered-line').
;;
;; After loading this file, run M-x agent-log-redact-rebuild-all once to
;; re-render existing sessions through the redactor.  Use M-x
;; agent-log-redact-preview in any rendered log buffer to see what would
;; (or did) match.

;;; Code:

(require 'agent-log)
(require 'cl-lib)

(defgroup agent-log-redact nil
  "Redact secrets from rendered agent-log Markdown."
  :group 'agent-log
  :prefix "agent-log-redact-")

(defcustom agent-log-redact-enabled t
  "Non-nil means redact secrets from rendered agent-log content."
  :type 'boolean)

(defcustom agent-log-redact-patterns
  '(("AKIA[A-Z0-9]\\{16\\}" . "aws-access-key")
    ("gh[ps]_[A-Za-z0-9_]\\{36,\\}" . "github-token")
    ("github_pat_[A-Za-z0-9_]\\{22,\\}" . "github-pat")
    ("xox[bporca]-[A-Za-z0-9-]\\{10,\\}" . "slack-token")
    ("glpat-[A-Za-z0-9_-]\\{20,\\}" . "gitlab-token")
    ("AIza[0-9A-Za-z_-]\\{35\\}" . "google-api-key")
    ("sk-ant-[A-Za-z0-9_-]\\{20,\\}" . "anthropic-key")
    ("sk-[A-Za-z0-9_-]\\{20,\\}" . "sk-api-key")
    ("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+" . "jwt")
    ("\\(?:postgres\\|postgresql\\|mysql\\|mongodb\\|mongodb\\+srv\\|redis\\|amqp\\|amqps\\|mssql\\)://[^:/ \n]+:\\([^@/ \n]+\\)@"
     . "db-password")
    ("\"client_secret\"[[:space:]]*:[[:space:]]*\"\\([A-Za-z0-9_-]\\{20,\\}\\)\""
     . "google-oauth-secret")
    ("-----BEGIN \\(?:RSA \\|EC \\|OPENSSH \\|DSA \\)?PRIVATE KEY-----\\(?:.\\|\n\\)*?-----END [A-Z ]*?PRIVATE KEY-----"
     . "private-key")
    ("\\(?:api[_-]?key\\|api[_-]?secret\\|secret[_-]?key\\|access[_-]?token\\|auth[_-]?token\\|password\\)[[:space:]]*[=:][[:space:]]*[\"']\\([A-Za-z0-9/+=_-]\\{24,\\}\\)[\"']"
     . "hardcoded-secret"))
  "Alist of (REGEX . LABEL) patterns for secret detection.
Entries are applied in order.  If REGEX contains a capture group, only
the first capture group is replaced; otherwise the whole match is
replaced.  Use a capture group when you want to preserve surrounding
context (e.g. the variable name in a `password=VALUE' match)."
  :type '(alist :key-type regexp :value-type string))

(defcustom agent-log-redact-extra-patterns nil
  "User-supplied patterns, appended to `agent-log-redact-patterns'.
Same format as `agent-log-redact-patterns'.  Use this to add site- or
project-specific secret formats without editing the built-in list."
  :type '(alist :key-type regexp :value-type string))

(defcustom agent-log-redact-allowlist nil
  "Literal strings that should never be redacted even if they match.
Use to suppress known false positives (e.g. a public test key that
looks like a real API key)."
  :type '(repeat string))

(defcustom agent-log-redact-hash-salt ""
  "Salt prepended to secrets before hashing for the placeholder suffix.
An empty salt is safe: the 8-char truncation already makes recovery
impractical.  Set a non-empty salt if you want placeholders to differ
across machines (e.g. when the same logs are synced to multiple hosts
and you don't want the hash to act as a cross-host identifier)."
  :type 'string)

(defcustom agent-log-redact-jsonl-roots
  '("~/.claude/projects/" "~/.codex/sessions/")
  "Directories whose .jsonl files are scrubbed by source-level redaction.
`agent-log-redact-scrub-jsonl' walks each root recursively and redacts
every .jsonl it finds, skipping files modified too recently to be safely
scrubbed (see `agent-log-redact-active-session-seconds')."
  :type '(repeat directory))

(defcustom agent-log-redact-active-session-seconds 300
  "Skip JSONL files modified within this many seconds during scrubbing.
Prevents racing with an active Claude Code or Codex session that may
still be appending to its log file."
  :type 'number)

(defvar claude-code-event-hook)

(declare-function agent-log-redact-scrub-jsonl "agent-log-redact")

(defun agent-log-redact--session-end-handler (message)
  "Run `agent-log-redact-scrub-jsonl' on Claude Code session end.
MESSAGE is a Claude Code event plist.  Fires only on `:type' `stop'.
Defers the scrub by `agent-log-redact-active-session-seconds' plus
30 seconds so the just-ended session file ages past the active window."
  (when (and agent-log-auto-redact-sessions
             (eq (plist-get message :type) 'stop))
    (run-with-timer
     (+ agent-log-redact-active-session-seconds 30) nil
     (lambda ()
       (condition-case err
           (agent-log-redact-scrub-jsonl)
         (error (message "agent-log-redact: scheduled scrub failed: %s"
                         (error-message-string err))))))))

(defun agent-log-redact--update-session-end-hook ()
  "Install or remove the session-end scrub hook based on the user option."
  (if agent-log-auto-redact-sessions
      (add-hook 'claude-code-event-hook
                #'agent-log-redact--session-end-handler)
    (remove-hook 'claude-code-event-hook
                 #'agent-log-redact--session-end-handler)))

(defcustom agent-log-auto-redact-sessions nil
  "When non-nil, run `agent-log-redact-scrub-jsonl' after a session ends.
Hooks into Claude Code's event mechanism via `claude-code-event-hook'.
Scrubbing is deferred by `agent-log-redact-active-session-seconds'
plus a small buffer so the just-ended session's JSONL ages past the
active-session window and gets scrubbed on the same run.  Requires
the `claude-code' package.  Codex has no equivalent event hook, so
Codex sessions are only scrubbed by manual invocation."
  :type 'boolean
  :set (lambda (sym val)
         (set-default sym val)
         (agent-log-redact--update-session-end-hook)))

(defun agent-log-redact--hash (secret)
  "Return first 8 hex chars of sha256 of SECRET plus the configured salt."
  (substring (secure-hash 'sha256
                          (concat agent-log-redact-hash-salt secret))
             0 8))

(defun agent-log-redact--placeholder (label secret)
  "Return `[REDACTED:LABEL:HASH]' placeholder for SECRET.
LABEL identifies the secret family (e.g. `aws-access-key')."
  (format "[REDACTED:%s:%s]" label (agent-log-redact--hash secret)))

(defun agent-log-redact-text (text)
  "Return TEXT with secrets replaced by deterministic placeholders.
Applies every entry of `agent-log-redact-patterns' followed by every
entry of `agent-log-redact-extra-patterns', in order.  Matches listed
in `agent-log-redact-allowlist' are left untouched."
  (if (or (null text) (string-empty-p text))
      text
    (let ((case-fold-search t))
      (with-temp-buffer
        (insert text)
        (dolist (entry (append agent-log-redact-patterns
                               agent-log-redact-extra-patterns))
          (agent-log-redact--apply-pattern (car entry) (cdr entry)))
        (buffer-string)))))

(defun agent-log-redact--apply-pattern (regex label)
  "Replace every REGEX match in the current buffer with a LABEL placeholder.
Operates on group 1 if the pattern has one, otherwise the whole match.
Respects `agent-log-redact-allowlist' and skips matches that already
contain a `[REDACTED:...]' placeholder (which would otherwise get
re-hashed on every pass, breaking idempotency)."
  (goto-char (point-min))
  (while (re-search-forward regex nil t)
    (let* ((group (if (match-beginning 1) 1 0))
           (matched (match-string-no-properties group)))
      (unless (or (member matched agent-log-redact-allowlist)
                  (string-match-p "\\[REDACTED:" matched))
        (replace-match (agent-log-redact--placeholder label matched)
                       t t nil group)))))

(defun agent-log-redact--filter-return (rendered &rest _)
  "Filter-return advice: redact secrets in RENDERED entry text.
Pass through unchanged when `agent-log-redact-enabled' is nil."
  (if agent-log-redact-enabled
      (agent-log-redact-text rendered)
    rendered))

(advice-add 'agent-log--render-entry :filter-return
            #'agent-log-redact--filter-return)

(agent-log-redact--update-session-end-hook)

;;;###autoload
(defun agent-log-redact-rebuild-all ()
  "Delete all rendered .md files and re-render through the redactor.
Run this after enabling redaction for the first time, or after changing
`agent-log-redact-patterns' or `agent-log-redact-extra-patterns', so
previously-rendered logs are reprocessed.

The source JSONL files are not touched.  They remain in plain text at
the agent's own location (for Claude Code, under `~/.claude/projects/')
and should be protected with filesystem-level controls."
  (interactive)
  (unless (yes-or-no-p
           "Delete all rendered agent-log .md files and re-render? ")
    (user-error "Aborted"))
  (agent-log-redact--clear-rendered-directory)
  (agent-log-sync-sessions
   (lambda () (message "agent-log-redact: rebuild complete"))))

;;;###autoload
(defun agent-log-redact-existing-in-place ()
  "Redact secrets in every already-rendered .md file, in place.
Iterates `agent-log-rendered-directory', reads each .md, runs it
through `agent-log-redact-text', and rewrites only files whose
content actually changed.  Much faster than
`agent-log-redact-rebuild-all' on large archives because it does not
re-parse JSONL; it only rewrites files that contain matches.

Sessions whose JSONL has grown since last render are not refreshed
by this command — run `agent-log-sync-sessions' afterward to pick up
any new content through the advice-based redactor."
  (interactive)
  (let ((dir (expand-file-name agent-log-rendered-directory))
        (scanned 0)
        (changed 0))
    (dolist (file (directory-files-recursively dir "\\.md\\'"))
      (cl-incf scanned)
      (let* ((original (with-temp-buffer
                         (insert-file-contents file)
                         (buffer-string)))
             (redacted (agent-log-redact-text original)))
        (unless (string= original redacted)
          (cl-incf changed)
          (with-temp-file file (insert redacted)))))
    (message "agent-log-redact: scanned %d file(s), rewrote %d"
             scanned changed)))

;;;###autoload
(defun agent-log-redact-scrub-jsonl ()
  "Redact secrets in every source .jsonl file under the configured roots.
Walks every directory listed in `agent-log-redact-jsonl-roots'
recursively, parses each JSONL line, redacts every string value via
`agent-log-redact-text', and rewrites the file atomically if anything
changed.  Files modified within the last
`agent-log-redact-active-session-seconds' seconds are skipped to avoid
racing with an active session.

JSON object keys are never redacted — only values.  Lines that fail to
parse as JSON are written through unchanged.  The source .jsonl is the
ground truth for session-resume functionality, so redaction happens on
string values only; structure is preserved exactly."
  (interactive)
  (let ((total 0) (scanned 0) (skipped 0) (changed 0))
    (dolist (root agent-log-redact-jsonl-roots)
      (let ((dir (expand-file-name root)))
        (when (file-directory-p dir)
          (dolist (file (directory-files-recursively dir "\\.jsonl\\'"))
            (cl-incf total)
            (if (agent-log-redact--file-recent-p
                 file agent-log-redact-active-session-seconds)
                (cl-incf skipped)
              (cl-incf scanned)
              (when (agent-log-redact--scrub-jsonl-file file)
                (cl-incf changed)))))))
    (message "agent-log-redact: total=%d scanned=%d skipped=%d changed=%d"
             total scanned skipped changed)))

(defun agent-log-redact--file-recent-p (file seconds)
  "Return non-nil if FILE was modified within the last SECONDS."
  (let ((mtime (file-attribute-modification-time (file-attributes file))))
    (< (- (float-time) (float-time mtime)) seconds)))

(defun agent-log-redact--scrub-jsonl-file (file)
  "Rewrite FILE with every JSON string value redacted.
Returns non-nil when the file content changed.  Writes to a sibling
temporary file and atomically renames on success, so a crash mid-write
cannot corrupt the original.  Locking is disabled for the write so
concurrent scrubber runs cannot deadlock on stale lockfiles."
  (let ((changed nil)
        (tmp (concat file ".redact-tmp"))
        (create-lockfiles nil))
    (when (file-exists-p tmp)
      (delete-file tmp))
    (with-temp-buffer
      (let ((coding-system-for-read 'utf-8-unix)
            (coding-system-for-write 'utf-8-unix))
        (insert-file-contents file)
        (let ((scrubbed (agent-log-redact--scrub-jsonl-buffer)))
          (setq changed scrubbed))
        (when changed
          (write-region (point-min) (point-max) tmp nil 'quiet))))
    (when changed
      (rename-file tmp file t))
    changed))

(defun agent-log-redact--scrub-jsonl-buffer ()
  "Redact string values in each JSONL line of the current buffer.
Returns non-nil when any line changed."
  (let ((changed nil))
    (goto-char (point-min))
    (while (not (eobp))
      (let* ((start (line-beginning-position))
             (end (line-end-position))
             (line (buffer-substring-no-properties start end)))
        (unless (string-empty-p line)
          (let ((new (agent-log-redact--scrub-jsonl-line line)))
            (unless (string= line new)
              (setq changed t)
              (delete-region start end)
              (goto-char start)
              (insert new)))))
      (forward-line 1))
    changed))

(defvar agent-log-redact--walk-changed nil
  "Dynamic flag set when `agent-log-redact--walk-json-strings' redacts a value.
Bound fresh for each JSONL line; consulted to decide whether the line
needs re-serializing at all.")

(defun agent-log-redact--scrub-jsonl-line (line)
  "Return LINE with every JSON string value passed through the redactor.
Fast path 1: lines with no pattern match are returned verbatim.
Fast path 2: if the recursive walk finds a match syntactically but
redacts nothing (e.g. the match was inside an already-redacted
placeholder), the original line is returned verbatim too.  Both paths
are required for idempotency — JSON parse + serialize is not
byte-identical for all valid inputs, so unconditional re-serialization
would cause drift across re-runs.  Lines that fail to parse as JSON are
returned unchanged so malformed or truncated entries survive scrubbing."
  (if (not (agent-log-redact--line-matches-any-pattern-p line))
      line
    (condition-case _err
        (let* ((agent-log-redact--walk-changed nil)
               (obj (json-parse-string line
                                       :object-type 'hash-table
                                       :array-type 'array
                                       :null-object nil
                                       :false-object :false))
               (new (agent-log-redact--walk-json-strings obj)))
          (if agent-log-redact--walk-changed
              (json-serialize new
                              :null-object nil
                              :false-object :false)
            line))
      (error line))))

(defun agent-log-redact--line-matches-any-pattern-p (line)
  "Return non-nil if LINE contains a match for any configured pattern."
  (let ((case-fold-search t))
    (catch 'hit
      (dolist (entry (append agent-log-redact-patterns
                             agent-log-redact-extra-patterns))
        (when (string-match-p (car entry) line)
          (throw 'hit t)))
      nil)))

(defun agent-log-redact--walk-json-strings (value)
  "Return VALUE with every string leaf replaced by `agent-log-redact-text'.
Hash-table keys are preserved as-is; only values are redacted.  Sets
`agent-log-redact--walk-changed' when any string is actually rewritten,
so the caller can skip re-serialization if nothing needed redacting."
  (cond
   ((stringp value)
    (let ((new (agent-log-redact-text value)))
      (unless (string= value new)
        (setq agent-log-redact--walk-changed t))
      new))
   ((hash-table-p value)
    (let ((out (make-hash-table :test (hash-table-test value)
                                :size (hash-table-count value))))
      (maphash (lambda (k v)
                 (puthash k (agent-log-redact--walk-json-strings v) out))
               value)
      out))
   ((vectorp value)
    (vconcat (mapcar #'agent-log-redact--walk-json-strings value)))
   (t value)))

(defun agent-log-redact--clear-rendered-directory ()
  "Delete every .md file under `agent-log-rendered-directory' and the index."
  (let ((dir (expand-file-name agent-log-rendered-directory)))
    (when (file-directory-p dir)
      (dolist (f (directory-files-recursively dir "\\.md\\'"))
        (delete-file f))
      (let ((index (expand-file-name "_index.el" dir)))
        (when (file-exists-p index)
          (delete-file index))))))

;;;###autoload
(defun agent-log-redact-preview ()
  "List potential secret matches in the current buffer.
Opens a report buffer showing each match's label, position, and a
truncated preview.  Useful for tuning patterns and the allowlist."
  (interactive)
  (let ((findings (agent-log-redact--collect-findings
                   (buffer-substring-no-properties (point-min) (point-max)))))
    (if (null findings)
        (message "agent-log-redact: no matches in this buffer")
      (agent-log-redact--show-findings findings))))

(defun agent-log-redact--collect-findings (text)
  "Return a list of (LABEL BEG END MATCH) for every pattern match in TEXT."
  (let ((findings nil)
        (case-fold-search t))
    (with-temp-buffer
      (insert text)
      (dolist (entry (append agent-log-redact-patterns
                             agent-log-redact-extra-patterns))
        (let ((regex (car entry))
              (label (cdr entry)))
          (goto-char (point-min))
          (while (re-search-forward regex nil t)
            (let* ((group (if (match-beginning 1) 1 0)))
              (push (list label
                          (match-beginning group)
                          (match-end group)
                          (match-string-no-properties group))
                    findings))))))
    (nreverse findings)))

(defun agent-log-redact--show-findings (findings)
  "Display FINDINGS in a dedicated report buffer."
  (let ((buf (get-buffer-create "*agent-log-redact preview*")))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert (format "%d potential redaction(s):\n\n" (length findings)))
        (dolist (f findings)
          (insert (format "  [%s]\t%s..%s\t%s\n"
                          (nth 0 f) (nth 1 f) (nth 2 f)
                          (truncate-string-to-width
                           (nth 3 f) 60 nil nil t))))
        (goto-char (point-min))
        (special-mode)))
    (pop-to-buffer buf)))

(provide 'agent-log-redact)
;;; agent-log-redact.el ends here
