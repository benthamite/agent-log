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

(require 'cl-lib)

;; `agent-log' loads this library, so requiring it back would be circular.
;; Everything used from it is called at run time.
(declare-function agent-log-sync-sessions "agent-log")
(defvar agent-log-rendered-directory)

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
    ("-----BEGIN \\(?:RSA \\|EC \\|OPENSSH \\|DSA \\)?PRIVATE KEY-----[[:ascii:][:nonascii:]]*?-----END [A-Z ]*?PRIVATE KEY-----"
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

(defcustom agent-log-redact-scrub-state-file
  "~/.claude/agent-log-redact-scrub-state.eld"
  "File where the JSONL scrubber records its last completed run.
It holds the run's cutoff time, a hash of the redaction settings and
the files that failed.  A later run scans only files modified after
the cutoff, plus those failed files, and rescans everything when the
settings hash differs.  Deleting the file forces a full rescan."
  :type 'file)

(defcustom agent-log-redact-opaque-json-keys
  '("encrypted_content" "signature" "ciphertext" "nonce" "mac" "tag")
  "JSON object keys whose string values must never be source-redacted.
These fields commonly hold authenticated ciphertext, signatures, or
other integrity-checked blobs.  Rewriting their contents can make agent
session resume fail even when the replacement is a valid JSON string.
Keys ending in `_signature', `_ciphertext', `_nonce', `_mac', or `_tag'
are also treated as opaque."
  :type '(repeat string))

(defcustom agent-log-redact-opaque-source-types
  '("base64")
  "Values of a JSON `type' field that mark the containing object as opaque.
When the JSONL scrubber encounters a hash-table whose `type' equals one
of these strings, the entire sub-object is preserved byte-for-byte.

The default protects Anthropic image content blocks of the form
\((\"type\" . \"base64\") (\"media_type\" . \"image/png\") (\"data\" . \"...\")),
whose long base64 payload can otherwise contain incidental matches for
secret-detection patterns (e.g. `AKIA[A-Z0-9]\\{16\\}' inside randomized
image bytes).  Replacing those matches with placeholders corrupts the
base64 and breaks session resume."
  :type '(repeat string))

(defvar claude-code-event-hook)

(defvar agent-log-auto-redact-sessions)

(defvar agent-log-redact--source-directory
  (or (and load-file-name (file-name-directory load-file-name))
      default-directory)
  "Directory containing this file, captured at load time.
Used to locate the sibling elpaca builds tree when spawning the
out-of-process scrubber so the subprocess's load-path can find
`agent-log' without running the user's full init.")

(defun agent-log-redact--elpaca-builds-directory ()
  "Return the elpaca builds directory sibling to this file's source tree.
Returns nil if the expected layout is not present (e.g. installed via
a non-elpaca mechanism)."
  (let ((candidate (expand-file-name "../../builds/"
                                     agent-log-redact--source-directory)))
    (and (file-directory-p candidate) candidate)))

(defconst agent-log-redact--scrubber-buffer-name " *agent-log-redact-scrub*"
  "Name of the buffer that collects the background scrubber's output.")

(defvar agent-log-redact--scrubber-process nil
  "The running background scrubber process, or nil.")

(defvar agent-log-redact--scrubber-rerun nil
  "Non-nil when a scrub was requested while one was already running.")

(defun agent-log-redact--request-scrub ()
  "Start the background scrubber, or queue one run if it is running.
At most one scrubber runs at a time.  A request that arrives during a
run is remembered, and a single new run starts when the current one
ends, so it covers files that changed during the run."
  (if (process-live-p agent-log-redact--scrubber-process)
      (setq agent-log-redact--scrubber-rerun t)
    (setq agent-log-redact--scrubber-rerun nil)
    (setq agent-log-redact--scrubber-process
          (agent-log-redact--spawn-scrubber))))

(defun agent-log-redact--spawn-scrubber ()
  "Start an `emacs --batch' subprocess that scrubs JSONL out of process.
Non-blocking: returns immediately.  The subprocess inherits no state
from the running Emacs other than the elpaca builds load-path, which
is reconstructed from this file's location.  Its output goes to the
buffer named by `agent-log-redact--scrubber-buffer-name', and it exits
with status 1 when any file failed to scrub."
  (let ((builds (agent-log-redact--elpaca-builds-directory))
        (buffer (get-buffer-create agent-log-redact--scrubber-buffer-name)))
    (unless builds
      (user-error
       "agent-log-redact: cannot locate elpaca builds directory from %s"
       agent-log-redact--source-directory))
    (with-current-buffer buffer
      (erase-buffer))
    (make-process
     :name "agent-log-redact-scrub"
     :buffer buffer
     :noquery t
     :connection-type 'pipe
     :command
     (list (expand-file-name invocation-name invocation-directory)
           "--batch"
           "--eval"
           (format "(dolist (d (file-expand-wildcards %S)) (add-to-list 'load-path d))"
                   (concat builds "*/"))
           "--eval" "(setq backtrace-on-error-noninteractive nil)"
           "--eval" "(require 'agent-log)"
           "--eval" "(require 'agent-log-redact)"
           "--eval" "(kill-emacs (if (agent-log-redact-scrub-jsonl) 1 0))")
     :sentinel #'agent-log-redact--scrubber-sentinel)))

(defun agent-log-redact--scrubber-sentinel (proc event)
  "Report completion of the background scrubber PROC with EVENT string.
On success, kill the output buffer.  Otherwise keep it and name it in
the message, together with the last line the scrubber printed."
  (when (memq (process-status proc) '(exit signal))
    (let ((status (process-exit-status proc))
          (buffer (process-buffer proc)))
      (if (and (eq (process-status proc) 'exit) (zerop status))
          (progn
            (message "agent-log-redact: background scrub finished: %s"
                     (agent-log-redact--last-output-line buffer))
            (when (buffer-live-p buffer)
              (kill-buffer buffer)))
        (message "agent-log-redact: background scrub failed (exit %d, %s): %s; full output in buffer %S"
                 status (string-trim event)
                 (agent-log-redact--last-output-line buffer)
                 (buffer-name buffer)))
      (when agent-log-redact--scrubber-rerun
        (agent-log-redact--request-scrub)))))

(defun agent-log-redact--last-output-line (buffer)
  "Return the last non-empty line of BUFFER, or \"no output\"."
  (or (and (buffer-live-p buffer)
           (with-current-buffer buffer
             (save-excursion
               (goto-char (point-max))
               (skip-chars-backward " \t\n")
               (let ((line (buffer-substring-no-properties
                            (line-beginning-position) (point))))
                 (unless (string-empty-p line) line)))))
      "no output"))

(defun agent-log-redact--session-end-handler (message)
  "Spawn the background scrubber on Claude Code session end.
MESSAGE is a Claude Code event plist.  Fires only on `:type' `stop'.
Defers the spawn by `agent-log-redact-active-session-seconds' plus 30
seconds so the just-ended session file ages past the active window,
then launches `agent-log-redact-scrub-jsonl' in an `emacs --batch'
subprocess so the running Emacs stays responsive.

Return nil.  Claude Code runs `claude-code-event-hook' until a function
returns non-nil, so returning the timer would hide every stop event from
the functions after this one."
  (when (and (bound-and-true-p agent-log-auto-redact-sessions)
             (eq (plist-get message :type) 'stop))
    (run-with-timer
     (+ agent-log-redact-active-session-seconds 30) nil
     (lambda ()
       (condition-case err
           (agent-log-redact--request-scrub)
         (error (message "agent-log-redact: scheduled scrub failed: %s"
                         (error-message-string err)))))))
  nil)

(defun agent-log-redact--update-session-end-hook ()
  "Install or remove the session-end scrub hook based on the user option.
The option lives in `agent-log', so it is unbound when this library is
loaded alone, as by `agent-remote'; unbound means its default, off."
  (if (bound-and-true-p agent-log-auto-redact-sessions)
      (add-hook 'claude-code-event-hook
                #'agent-log-redact--session-end-handler)
    (remove-hook 'claude-code-event-hook
                 #'agent-log-redact--session-end-handler)))

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
   (lambda (result)
     (if (plist-get result :ok)
         (message "agent-log-redact: rebuild complete")
       (message "agent-log-redact: rebuild failed during %s"
                (plist-get result :stage))))))

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
(defun agent-log-redact-scrub-jsonl (&optional full)
  "Redact secrets in source .jsonl files under the configured roots.
Walks every directory listed in `agent-log-redact-jsonl-roots'
recursively, parses each JSONL line, redacts non-opaque string values
via `agent-log-redact-text', and rewrites the file atomically if
anything changed.  Files modified within the last
`agent-log-redact-active-session-seconds' seconds are skipped to avoid
racing with an active session.

Only files modified since the last completed run, plus the files that
run failed on, are scanned; `agent-log-redact-scrub-state-file' holds
that record.  With FULL non-nil (interactively, a prefix argument), or
when the redaction settings changed since that run, every file is
scanned.

JSON object keys are never redacted, and values whose keys are listed
in `agent-log-redact-opaque-json-keys' are preserved byte-for-byte.
Lines that fail to parse as JSON are written through unchanged.  The
source .jsonl is the ground truth for session-resume functionality, so
redaction must not alter authenticated ciphertext or signature fields.

A file whose scrub signals an error is reported and left unchanged,
and the walk continues with the next file.  Return the list of files
that failed, so a caller such as the background scrubber can exit
with a failure status."
  (interactive "P")
  (let* ((started (float-time))
         (state (unless full (agent-log-redact--read-scrub-state)))
         (cutoff (plist-get state :cutoff))
         (retry (plist-get state :failed))
         (total 0) (scanned 0) (skipped 0) (changed 0) (failed nil))
    (dolist (root agent-log-redact-jsonl-roots)
      (let ((dir (expand-file-name root)))
        (when (file-directory-p dir)
          (dolist (file (directory-files-recursively dir "\\.jsonl\\'"))
            (cl-incf total)
            (if (or (agent-log-redact--file-recent-p
                     file agent-log-redact-active-session-seconds)
                    (and cutoff
                         (not (member file retry))
                         (agent-log-redact--file-older-p file cutoff)))
                (cl-incf skipped)
              (cl-incf scanned)
              (pcase (agent-log-redact--try-scrub-jsonl-file file)
                ('changed (cl-incf changed))
                ('failed (push file failed))))))))
    (agent-log-redact--write-scrub-state
     (- started agent-log-redact-active-session-seconds) failed)
    (message "agent-log-redact: total=%d scanned=%d skipped=%d changed=%d failed=%d"
             total scanned skipped changed (length failed))
    (nreverse failed)))

(defun agent-log-redact--settings-hash ()
  "Return a hash of every setting that decides what the scrubber redacts."
  (secure-hash 'sha256
               (prin1-to-string
                (list agent-log-redact-patterns
                      agent-log-redact-extra-patterns
                      agent-log-redact-allowlist
                      agent-log-redact-opaque-json-keys
                      agent-log-redact-opaque-source-types))))

(defun agent-log-redact--read-scrub-state ()
  "Return the last run's state plist, or nil when it does not apply.
The state does not apply when the file is missing or unreadable, or
when it was recorded under different redaction settings."
  (let ((file (expand-file-name agent-log-redact-scrub-state-file)))
    (when (file-readable-p file)
      (let ((state (condition-case nil
                       (with-temp-buffer
                         (insert-file-contents file)
                         (read (current-buffer)))
                     (error nil))))
        (when (and (listp state)
                   (equal (plist-get state :settings)
                          (agent-log-redact--settings-hash)))
          state)))))

(defun agent-log-redact--write-scrub-state (cutoff failed)
  "Record a completed run with CUTOFF time and the FAILED file list."
  (let ((file (expand-file-name agent-log-redact-scrub-state-file))
        (create-lockfiles nil))
    (make-directory (file-name-directory file) t)
    (with-temp-file file
      (prin1 (list :cutoff cutoff
                   :settings (agent-log-redact--settings-hash)
                   :failed failed)
             (current-buffer)))))

(defun agent-log-redact--try-scrub-jsonl-file (file)
  "Scrub FILE and return `changed', `unchanged' or `failed'.
An error is reported with FILE's name and turned into `failed', so one
unscrubbable file does not stop the scrub of the files after it."
  (condition-case err
      (if (agent-log-redact--scrub-jsonl-file file) 'changed 'unchanged)
    (error
     (message "agent-log-redact: failed to scrub %s: %s"
              file (truncate-string-to-width
                    (error-message-string err) 300 nil nil "..."))
     'failed)))

(defun agent-log-redact--file-recent-p (file seconds)
  "Return non-nil if FILE was modified within the last SECONDS."
  (let ((mtime (file-attribute-modification-time (file-attributes file))))
    (< (- (float-time) (float-time mtime)) seconds)))

(defun agent-log-redact--file-older-p (file time)
  "Return non-nil if FILE was last modified before TIME, in float seconds."
  (< (float-time (file-attribute-modification-time (file-attributes file)))
     time))

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

(defun agent-log-redact--walk-json-strings (value &optional key)
  "Return VALUE with every string leaf replaced by `agent-log-redact-text'.
Hash-table keys are preserved as-is; only non-opaque values are
redacted.  KEY is the JSON object key for VALUE, when available.  Sets
`agent-log-redact--walk-changed' when any string is actually rewritten,
so the caller can skip re-serialization if nothing needed redacting."
  (cond
   ((agent-log-redact--opaque-json-key-p key) value)
   ((agent-log-redact--opaque-json-object-p value) value)
   ((stringp value)
    (let ((new (agent-log-redact-text value)))
      (unless (string= value new)
        (setq agent-log-redact--walk-changed t))
      new))
   ((hash-table-p value)
    (let ((out (make-hash-table :test (hash-table-test value)
                                :size (hash-table-count value))))
      (maphash (lambda (k v)
                 (puthash k (agent-log-redact--walk-json-strings v k) out))
               value)
      out))
   ((vectorp value)
    (vconcat (mapcar #'agent-log-redact--walk-json-strings value)))
   (t value)))

(defun agent-log-redact--opaque-json-object-p (value)
  "Return non-nil when hash-table VALUE marks an opaque content block.
Checks the `type' field against `agent-log-redact-opaque-source-types'."
  (and (hash-table-p value)
       (let ((type (gethash "type" value)))
         (and (stringp type)
              (member type agent-log-redact-opaque-source-types)))))

(defun agent-log-redact--opaque-json-key-p (key)
  "Return non-nil when KEY names an opaque JSON value."
  (and (stringp key)
       (or (member key agent-log-redact-opaque-json-keys)
           (string-match-p
            "\\(?:\\`\\|_\\)\\(?:signature\\|ciphertext\\|nonce\\|mac\\|tag\\)\\'"
            key))))

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
