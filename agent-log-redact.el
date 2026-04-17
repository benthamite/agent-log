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
Respects `agent-log-redact-allowlist'."
  (goto-char (point-min))
  (while (re-search-forward regex nil t)
    (let* ((group (if (match-beginning 1) 1 0))
           (matched (match-string-no-properties group)))
      (unless (member matched agent-log-redact-allowlist)
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
