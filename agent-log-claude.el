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
(require 'seq)
(require 'agent-log)

;;;;; Soft dependency: claude-code

(defvar claude-code-event-hook)
(defvar agent-log-claude--instance)
(defvar agent-log-claude--scan-cache)
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

;;;;; Generic method implementations

;;;;;; Session discovery

(cl-defmethod agent-log--read-sessions ((backend agent-log-claude))
  "Return the sessions Claude Code's own /resume would offer for BACKEND.
The return value is an alist of session-id to metadata, a plist
\(:display :timestamp :updated-timestamp :project :file :file-dir
:backend :source-file-state).  Sessions come from the project folders,
because clients such as Claude Desktop never write `history.jsonl'.  The
history supplies the display text and fills gaps a transcript leaves.
The :project field reflects the most recent CWD among sessions sharing
the same file directory, so it stays correct after project renames or
profile migrations."
  (agent-log-claude--load-scan-cache)
  (when (zerop (hash-table-count agent-log-claude--scan-cache))
    (message "Agent Log: first scan of Claude Code transcripts..."))
  (let* ((directory (agent-log-backend-directory backend))
         (history (agent-log-claude--history-records directory))
         (transcripts (cl-loop
                       for (file . attributes)
                       in (agent-log-claude--list-transcripts directory)
                       for scan = (agent-log-claude--scan-transcript
                                   file attributes)
                       when (agent-log-claude--resumable-p file scan)
                       collect (list file attributes scan)))
         (latest-cwds (agent-log-claude--folder-latest-cwds transcripts)))
    (agent-log-claude--save-scan-cache)
    (sort (cl-loop for (file attributes scan) in transcripts
                   collect (agent-log-claude--session-from-transcript
                            backend file attributes scan history latest-cwds))
          (lambda (a b)
            (agent-log--timestamp> (plist-get (cdr a) :timestamp)
                                   (plist-get (cdr b) :timestamp))))))

(defun agent-log-claude--session-from-transcript
    (backend file attributes scan history latest-cwds)
  "Return the session entry of FILE for BACKEND.
ATTRIBUTES are FILE's attributes and SCAN its transcript scan.  HISTORY
is the table from `agent-log-claude--history-records' and LATEST-CWDS
the table from `agent-log-claude--folder-latest-cwds'."
  (let* ((session-id (file-name-base file))
         (record (gethash session-id history))
         (dir (file-name-directory file))
         (mtime-ms (* 1000 (float-time
                            (file-attribute-modification-time attributes))))
         (timestamp (or (plist-get scan :first-timestamp)
                        (plist-get record :timestamp)
                        mtime-ms)))
    (list session-id
          :display (or (plist-get record :last-display)
                       (plist-get scan :text)
                       "")
          :timestamp timestamp
          :updated-timestamp (or (plist-get scan :last-timestamp) timestamp)
          :project (or (gethash dir latest-cwds)
                       (plist-get record :project)
                       "")
          :file-dir dir
          :file file
          :backend backend
          :source-file-state (cons (file-attribute-size attributes) mtime-ms))))

(defun agent-log-claude--folder-latest-cwds (transcripts)
  "Return a table of each transcript folder's most recent CWD.
TRANSCRIPTS is a list of (FILE ATTRIBUTES SCAN)."
  (let ((latest (make-hash-table :test #'equal))
        (latest-times (make-hash-table :test #'equal)))
    (cl-loop
     for (file _attributes scan) in transcripts
     for dir = (file-name-directory file)
     for cwd = (plist-get scan :last-cwd)
     for time = (or (plist-get scan :last-timestamp) 0)
     when (and cwd (or (not (gethash dir latest))
                       (> time (gethash dir latest-times))))
     do (puthash dir cwd latest)
     (puthash dir time latest-times))
    latest))

;;;;;;; Transcript listing

(defconst agent-log-claude--session-file-regexp
  (rx bos (= 8 hex) "-" (= 4 hex) "-" (= 4 hex) "-" (= 4 hex) "-" (= 12 hex)
      ".jsonl" eos)
  "Regexp matching the transcript file names Claude Code treats as sessions.")

(defconst agent-log-claude--resume-window-bytes 65536
  "Bytes Claude Code's /resume reads from each end of a transcript.
Its filters look only at these windows, so the same bytes decide here.")

(defconst agent-log-claude--probe-bytes 16384
  "Bytes read first from a transcript to recognize an Agent SDK session.
Most transcripts on a busy machine are those, and /resume hides them.")

(defconst agent-log-claude--timestamp-regexp
  "\"timestamp\": ?\"\\([-0-9T:.Z+]+\\)\""
  "Regexp matching a transcript's raw timestamp field.")

(defconst agent-log-claude--text-limit 300
  "Characters of a transcript's first user text kept for display.")

(defvar agent-log-claude--scan-cache (make-hash-table :test #'equal)
  "Transcript scans by file name, as (SIZE MTIME . SCAN).
A scan is valid while its file's size and modification time are
unchanged, so listing thousands of transcripts only costs a stat each.")

(defvar agent-log-claude--scan-cache-loaded nil
  "Non-nil once the saved transcript scans have been read this session.")

(defvar agent-log-claude--scan-cache-dirty nil
  "Non-nil when `agent-log-claude--scan-cache' has unsaved scans.")

(defvar agent-log-claude--scan-cache-saved-at 0
  "When the transcript scans were last saved, in seconds since the epoch.")

(defconst agent-log-claude--scan-cache-save-interval 60
  "Minimum seconds between saves of the transcript scans.
A scan missed by a save is only redone later, and an active session
changes its transcript constantly, so saving every change gains nothing.")

(defconst agent-log-claude--scan-cache-version 1
  "Format of the saved transcript scans; other versions are ignored.")

(defun agent-log-claude--scan-cache-file ()
  "Return the file that keeps transcript scans between Emacs sessions."
  (expand-file-name "_claude-transcript-scans.el"
                    agent-log-rendered-directory))

(defun agent-log-claude--load-scan-cache ()
  "Read the saved transcript scans into the cache, once per session.
A first scan of a large store takes seconds on the main thread, so it
should happen once rather than after every Emacs start.  A batch Emacs
neither reads nor writes this file: it only scans what it is asked about."
  (unless (or agent-log-claude--scan-cache-loaded noninteractive)
    (setq agent-log-claude--scan-cache-loaded t)
    (agent-log-claude--read-scan-cache-file)))

(defun agent-log-claude--read-scan-cache-file ()
  "Merge the saved transcript scans into the cache, ignoring a bad file."
  (let ((file (agent-log-claude--scan-cache-file)))
    (when (file-readable-p file)
      (condition-case err
          (let ((saved (with-temp-buffer
                         (let ((coding-system-for-read 'utf-8-unix))
                           (insert-file-contents file))
                         (read (current-buffer)))))
            (when (equal (car saved) agent-log-claude--scan-cache-version)
              (pcase-dolist (`(,path . ,value) (cdr saved))
                (unless (gethash path agent-log-claude--scan-cache)
                  (puthash path value agent-log-claude--scan-cache)))))
        (error
         (message "Agent Log ignored unreadable %s: %s"
                  file (error-message-string err)))))))

(defun agent-log-claude--save-scan-cache ()
  "Save the transcript scans if they changed and the last save is old enough."
  (when (and agent-log-claude--scan-cache-dirty
             (not noninteractive)
             (> (- (float-time) agent-log-claude--scan-cache-saved-at)
                agent-log-claude--scan-cache-save-interval))
    (agent-log-claude--write-scan-cache-file)))

(defun agent-log-claude--write-scan-cache-file ()
  "Atomically write the transcript scans, reporting a failure only as a message."
  (let* ((file (agent-log-claude--scan-cache-file))
         (temp (concat file ".tmp"))
         (coding-system-for-write 'utf-8-unix)
         (entries nil))
    (maphash (lambda (path value) (push (cons path value) entries))
             agent-log-claude--scan-cache)
    (condition-case err
        (progn
          (make-directory (file-name-directory file) t)
          (with-temp-file temp
            (let ((print-length nil) (print-level nil))
              (prin1 (cons agent-log-claude--scan-cache-version entries)
                     (current-buffer))))
          (rename-file temp file t)
          (setq agent-log-claude--scan-cache-dirty nil
                agent-log-claude--scan-cache-saved-at (float-time)))
      (error
       (message "Agent Log could not save %s: %s"
                file (error-message-string err))))))

(defun agent-log-claude--list-transcripts (directory)
  "Return (FILE . ATTRIBUTES) for each session file under DIRECTORY."
  (let ((projects (expand-file-name "projects" directory)))
    (when (file-directory-p projects)
      (cl-loop
       for folder in (directory-files projects t "\\`[^.]" t)
       when (file-directory-p folder)
       nconc (cl-loop
              for (file . attributes)
              in (directory-files-and-attributes
                  folder t "\\.jsonl\\'" t 'integer)
              when (and (null (file-attribute-type attributes))
                        (string-match-p agent-log-claude--session-file-regexp
                                        (file-name-nondirectory file)))
              collect (cons file attributes))))))

(defun agent-log-claude--scan-transcript (file &optional attributes)
  "Return the scan of FILE, reusing the cached one if FILE is unchanged.
ATTRIBUTES are FILE's attributes when the caller already has them.  See
`agent-log-claude--read-transcript-scan' for the scan's contents."
  (when-let* ((attributes (or attributes (file-attributes file 'integer))))
    (let* ((state (list (file-attribute-size attributes)
                        (file-attribute-modification-time attributes)))
           (cached (gethash file agent-log-claude--scan-cache)))
      (if (equal state (seq-take cached 2))
          (nthcdr 2 cached)
        (let ((scan (agent-log-claude--read-transcript-scan
                     file (car state))))
          (puthash file (append state scan) agent-log-claude--scan-cache)
          (setq agent-log-claude--scan-cache-dirty t)
          scan)))))

(defun agent-log-claude--read-transcript-scan (file size)
  "Return what the session list needs from FILE, whose size is SIZE.
Only bounded windows are read, so a transcript of any size costs about
the same.  The result is a plist with :hidden, non-nil when /resume never
offers the session; :continued-in, the session that superseded this one;
:has-messages; :first-cwd and :last-cwd; :first-timestamp and
:last-timestamp in epoch milliseconds; and :text, the first user text."
  (let ((probe (agent-log-claude--read-window
                file 0 agent-log-claude--probe-bytes)))
    (if (agent-log-claude--sdk-entrypoint-p
         (agent-log-claude--first-entrypoint probe))
        (list :hidden t
              :has-messages (agent-log-claude--records-message-p probe ""))
      (agent-log-claude--read-full-scan file size))))

(defun agent-log-claude--read-full-scan (file size)
  "Return the scan of FILE, of SIZE bytes, once no quick check has hidden it."
  (let* ((window agent-log-claude--resume-window-bytes)
         (cut (> size window))
         (head (agent-log-claude--read-window file 0 window))
         (tail (if cut
                   (agent-log-claude--read-window file (- size window) size)
                 head))
         (message-p (agent-log-claude--records-message-p head tail)))
    (if (agent-log-claude--hidden-by-resume-p head tail)
        (list :hidden t :has-messages message-p)
      (let* ((fields (agent-log-claude--head-fields head cut))
             (wide-p (and cut
                          (or (null (plist-get fields :cwd))
                              (null (plist-get fields :text))
                              (not message-p))))
             (wide-head (and wide-p
                             (agent-log-claude--read-window
                              file 0 agent-log--metadata-head-bytes)))
             (wide-cut (> size agent-log--metadata-head-bytes))
             (fields (if wide-p
                         (agent-log-claude--head-fields wide-head wide-cut)
                       fields))
             (tail-lines (agent-log-claude--window-lines tail cut nil))
             (first-cwd (plist-get fields :cwd)))
        (list :hidden (agent-log-claude--loop-session-p fields)
              :continued-in (agent-log-claude--continued-in tail tail-lines)
              :has-messages (or message-p
                                (and wide-p
                                     (or wide-cut
                                         (agent-log-claude--records-message-p
                                          wide-head ""))))
              :first-cwd first-cwd
              :last-cwd (or (agent-log-claude--last-cwd tail-lines) first-cwd)
              :first-timestamp (plist-get fields :timestamp)
              :last-timestamp (agent-log-claude--last-timestamp tail)
              :text (plist-get fields :text))))))

(defun agent-log-claude--read-window (file beg end)
  "Return bytes BEG to END of FILE as a unibyte string.
Searching undecoded bytes is far faster; a line is decoded when parsed."
  (let ((coding-system-for-read 'no-conversion)
        (file-name-handler-alist nil))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert-file-contents file nil beg end)
      (buffer-string))))

(defun agent-log-claude--window-lines (window head-cut tail-cut)
  "Return the complete non-empty lines of WINDOW.
HEAD-CUT and TAIL-CUT say whether WINDOW starts or ends mid-line, in
which case that partial line is dropped."
  (let ((lines (split-string window "\n")))
    (when head-cut (setq lines (cdr lines)))
    (when tail-cut (setq lines (butlast lines)))
    (seq-remove #'string-empty-p lines)))

(defun agent-log-claude--parse-line (line)
  "Return LINE parsed as a JSON object, or nil if it is malformed."
  (ignore-errors
    (agent-log--parse-json-line (decode-coding-string line 'utf-8))))

(defun agent-log-claude--hidden-by-resume-p (head tail)
  "Return non-nil if /resume hides a session given its windows HEAD and TAIL.
The checks read the raw JSON text as /resume does.  A quoted key inside a
JSON string has escaped quotes, so these patterns cannot match one."
  (or (string-search "\"isSidechain\":true" head)
      (string-search "\"isSidechain\": true" head)
      (string-match-p "\"teamName\": ?\"[^\"]" head)
      (member (agent-log-claude--session-kind head)
              '("daemon" "daemon-worker"))
      (agent-log-claude--sdk-entrypoint-p
       (or (agent-log-claude--first-entrypoint head)
           (agent-log-claude--last-entrypoint tail)))))

(defun agent-log-claude--sdk-entrypoint-p (entrypoint)
  "Return non-nil if ENTRYPOINT is one of the Agent SDK's, hidden by /resume."
  (member entrypoint '("sdk-cli" "sdk-ts" "sdk-py")))

(defun agent-log-claude--session-kind (head)
  "Return the session kind recorded on the first message line of HEAD."
  (let* ((key (string-search "\"parentUuid\":" head))
         (start (and key (let ((newline (cl-position ?\n head :end key
                                                     :from-end t)))
                           (if newline (1+ newline) 0))))
         (end (and key (or (string-search "\n" head key) (length head))))
         (text (if key (substring head start end) head)))
    (when (string-match "\"sessionKind\": ?\"\\([^\"]*\\)\"" text)
      (match-string 1 text))))

(defconst agent-log-claude--entrypoint-regexp
  "\"entrypoint\": ?\"\\([^\"]*\\)\""
  "Regexp matching a transcript's raw entrypoint field.")

(defun agent-log-claude--first-entrypoint (head)
  "Return the entrypoint first recorded in window HEAD."
  (when (string-match agent-log-claude--entrypoint-regexp head)
    (match-string 1 head)))

(defun agent-log-claude--last-entrypoint (tail)
  "Return the entrypoint last recorded in window TAIL."
  (let ((start 0) entrypoint)
    (while (string-match agent-log-claude--entrypoint-regexp tail start)
      (setq entrypoint (match-string 1 tail)
            start (match-end 0)))
    entrypoint))

(defun agent-log-claude--records-message-p (head tail)
  "Return non-nil if windows HEAD or TAIL hold a conversation message.
/resume does not offer a transcript with only bookkeeping records."
  (or (string-search "\"parentUuid\":" head)
      (string-search "\"parentUuid\":" tail)))

(defun agent-log-claude--head-fields (head tail-cut)
  "Return the first CWD, timestamp and user text in window HEAD.
The result is a plist with :cwd, :timestamp, :text and :first-prompt, the
text of the first real user prompt.  TAIL-CUT says whether HEAD ends
mid-line.  Lines are taken one at a time, since these fields usually lie
in the first few, and only those that may hold a wanted field are parsed."
  (let ((start 0) cwd timestamp text first-prompt prompt-seen)
    (while (and start (not (and cwd timestamp text)))
      (let* ((newline (string-search "\n" head start))
             (line (when (or newline (not tail-cut))
                     (substring head start newline)))
             (prompt-line (and line (agent-log-claude--user-prompt-line-p line))))
        (setq start (and newline (1+ newline)))
        (when (or prompt-line
                  (and line (null cwd) (string-search "\"cwd\":" line)))
          (when-let* ((entry (agent-log-claude--parse-line line)))
            (setq cwd (or cwd (agent-log-claude--non-empty
                               (plist-get entry :cwd))))
            (when (and prompt-line
                       (agent-log-claude--user-prompt-entry-p entry))
              (let ((prompt (agent-log-claude--entry-text entry)))
                (unless prompt-seen
                  (setq prompt-seen t first-prompt prompt))
                (setq timestamp (or timestamp (plist-get entry :timestamp)))
                (unless (agent-log--system-entry-p
                         agent-log-claude--instance entry)
                  (setq text (or text prompt)))))))))
    (list :cwd cwd
          :timestamp (agent-log-claude--timestamp-ms
                      (or timestamp (agent-log-claude--first-timestamp head)))
          :text (and text (agent-log--truncate-string
                           text agent-log-claude--text-limit))
          :first-prompt first-prompt)))

(defun agent-log-claude--first-timestamp (head)
  "Return the first raw timestamp in window HEAD, or nil."
  (when (string-match agent-log-claude--timestamp-regexp head)
    (match-string 1 head)))

(defun agent-log-claude--non-empty (string)
  "Return STRING if it is a non-empty string, else nil."
  (and (stringp string) (not (string-empty-p string)) string))

(defun agent-log-claude--timestamp-ms (timestamp)
  "Return ISO 8601 TIMESTAMP in epoch milliseconds, or nil."
  (and (stringp timestamp)
       (ignore-errors (agent-log--iso-to-epoch-ms timestamp))))

(defun agent-log-claude--user-prompt-line-p (line)
  "Return non-nil if LINE may be a prompt the user typed."
  (and (string-match-p "\"type\": ?\"user\"" line)
       (not (string-search "\"tool_result\"" line))))

(defun agent-log-claude--user-prompt-entry-p (entry)
  "Return non-nil if ENTRY is a prompt rather than injected user text."
  (and (equal (plist-get entry :type) "user")
       (not (eq (plist-get entry :isMeta) t))
       (not (eq (plist-get entry :isCompactSummary) t))
       (agent-log-claude--entry-text entry)))

(defun agent-log-claude--entry-text (entry)
  "Return the text of user ENTRY, or nil if it has none."
  (agent-log-claude--non-empty
   (agent-log--extract-message-text
    agent-log-claude--instance
    (plist-get (plist-get entry :message) :content))))

(defun agent-log-claude--loop-session-p (fields)
  "Return non-nil if head FIELDS show a session that /loop started."
  (when-let* ((prompt (plist-get fields :first-prompt)))
    (string-search "<command-name>/loop</command-name>" prompt)))

(defun agent-log-claude--continued-in (tail tail-lines)
  "Return the session this one continued in, per window TAIL, or nil.
TAIL-LINES are TAIL's complete lines.  A conversation turn recorded after
the marker cancels it."
  (when (string-search "\"continuedInSessionId\":" tail)
    (cl-loop
     for line in (reverse tail-lines)
     when (or (string-search "\"continuedInSessionId\":" line)
              (string-match-p "\"type\": ?\"\\(?:user\\|assistant\\)\"" line))
     do (when-let* ((entry (agent-log-claude--parse-line line)))
          (cl-return (and (equal (plist-get entry :type) "continued-in")
                          (plist-get entry :continuedInSessionId)))))))

(defun agent-log-claude--last-cwd (tail-lines)
  "Return the last top-level CWD recorded in TAIL-LINES, or nil."
  (cl-loop
   for line in (reverse tail-lines)
   when (string-search "\"cwd\":" line)
   thereis (when-let* ((entry (agent-log-claude--parse-line line)))
             (agent-log-claude--non-empty (plist-get entry :cwd)))))

(defun agent-log-claude--last-timestamp (tail)
  "Return the latest timestamp in window TAIL in epoch milliseconds, or nil.
The raw text is searched because a transcript's last line can be longer
than the window, which leaves no complete line to parse.  The window's
end is tried first, because nearly every transcript has one there."
  (let ((end-bytes (max 0 (- (length tail) agent-log-claude--probe-bytes))))
    (agent-log-claude--timestamp-ms
     (or (agent-log-claude--latest-timestamp-from tail end-bytes)
         (agent-log-claude--latest-timestamp-from tail 0)))))

(defun agent-log-claude--latest-timestamp-from (window start)
  "Return the latest raw timestamp in WINDOW at or after byte START, or nil."
  (let (latest)
    (while (string-match agent-log-claude--timestamp-regexp window start)
      (let ((timestamp (match-string 1 window)))
        (when (or (null latest) (string> timestamp latest))
          (setq latest timestamp)))
      (setq start (match-end 0)))
    latest))

(defun agent-log-claude--resumable-p (file scan)
  "Return non-nil if /resume would offer FILE, whose scan is SCAN."
  (and (not (plist-get scan :hidden))
       (plist-get scan :has-messages)
       (not (agent-log-claude--superseded-p file scan))))

(defun agent-log-claude--superseded-p (file scan)
  "Return non-nil if SCAN of FILE names a successor holding messages."
  (when-let* ((successor (plist-get scan :continued-in))
              (successor-scan (agent-log-claude--scan-transcript
                               (expand-file-name (concat successor ".jsonl")
                                                 (file-name-directory file)))))
    (plist-get successor-scan :has-messages)))

;;;;;;; History records

(defvar agent-log-claude--history-cache nil
  "The last history read, as (FILE SIZE MTIME OFFSET . TABLE).
OFFSET is the byte after the last complete line read into TABLE.  The
history is append-only and tens of megabytes long, so only what was
appended since the last read needs parsing.")

(defun agent-log-claude--history-records (directory)
  "Return a table of session id to the records of DIRECTORY's history.
Each value is a plist: :project, :timestamp and :display from the
session's first entry and :last-display from its last.  A missing history
gives an empty table, because not every client writes one."
  (let* ((file (expand-file-name "history.jsonl" directory))
         (attributes (file-attributes file 'integer))
         (size (and attributes (file-attribute-size attributes)))
         (mtime (and attributes (file-attribute-modification-time attributes)))
         (cache agent-log-claude--history-cache)
         (reusable (and cache attributes
                        (equal (car cache) file)
                        (>= size (nth 1 cache)))))
    (cond
     ((null attributes) (make-hash-table :test #'equal))
     ((and reusable (equal size (nth 1 cache)) (equal mtime (nth 2 cache)))
      (nthcdr 4 cache))
     (t
      (let* ((table (if reusable (nthcdr 4 cache)
                      (make-hash-table :test #'equal)))
             (offset (agent-log-claude--read-history-into
                      table file (if reusable (nth 3 cache) 0) size)))
        (setq agent-log-claude--history-cache
              (append (list file size mtime offset) table))
        table)))))

(defun agent-log-claude--read-history-into (table file offset size)
  "Merge the entries of FILE between bytes OFFSET and SIZE into TABLE.
Return the byte after the last complete line read."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((file-name-handler-alist nil)
          (coding-system-for-read 'no-conversion))
      (insert-file-contents file nil offset size))
    (goto-char (point-max))
    (let ((end (if (search-backward "\n" nil t) (1+ (point)) (point-min))))
      (dolist (line (split-string
                     (decode-coding-string
                      (buffer-substring-no-properties (point-min) end) 'utf-8)
                     "\n" t))
        (when-let* ((entry (agent-log-claude--parse-line line)))
          (agent-log-claude--add-history-entry table entry)))
      (+ offset (1- end)))))

(defun agent-log-claude--add-history-entry (table entry)
  "Merge history ENTRY into TABLE."
  (when-let* ((session-id (plist-get entry :sessionId)))
    (let ((record (gethash session-id table))
          (display (plist-get entry :display)))
      (puthash session-id
               (if record
                   (plist-put record :last-display display)
                 (list :project (plist-get entry :project)
                       :timestamp (plist-get entry :timestamp)
                       :display display
                       :last-display display))
               table))))

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
  (when-let* ((timestamp (agent-log--find-session-timestamp entries)))
    (setq agent-log--session-date
          (agent-log--format-iso-timestamp timestamp)))
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

(cl-defmethod agent-log--metadata-fallback-from-file
  ((backend agent-log-claude) file)
  "Return metadata for FILE from its transcript scan and Claude's history.
The history is consulted only for what the transcript does not record."
  (when-let* ((session-id (agent-log--session-id-from-file backend file)))
    (let* ((scan (agent-log-claude--scan-transcript file))
           (cwd (plist-get scan :first-cwd))
           (timestamp (plist-get scan :first-timestamp))
           (text (plist-get scan :text))
           (entry (unless (and cwd timestamp text)
                    (agent-log-claude--lookup-history-entry session-id))))
      (when (or cwd timestamp text entry)
        (list :project (or cwd (plist-get entry :project) "")
              :timestamp (or timestamp (plist-get entry :timestamp))
              :display (or text (plist-get entry :display) "")
              :backend backend
              :file file)))))

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

(cl-defmethod agent-log--summary-line-candidate-p ((_backend agent-log-claude) line)
  "Return non-nil if LINE may contain Claude summary text."
  (string-match-p
   "\"type\"[[:space:]]*:[[:space:]]*\"\\(?:user\\|assistant\\)\""
   line))

;;;;;; Active sessions

(cl-defmethod agent-log--active-session-ids
  ((_backend agent-log-claude) &optional _sessions)
  "Return a list of session IDs for live Claude Code sessions.
Standalone Agent Log has no reliable live-identity source for Claude
Code, so this returns nil; the optional agent integration in
`agent-log-agent.el' overrides it with the authoritative answer."
  nil)

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
                       (agent-log-claude--source-file-project-directory)
                       (when-let* ((project (agent-log-claude--lookup-session-project session-id)))
                         (and (not (string-empty-p project))
                              (file-directory-p project)
                              project)))))
    (file-name-as-directory dir)))

(defun agent-log-claude--source-file-project-directory ()
  "Return the existing project directory implied by `agent-log--source-file'."
  (when-let* ((file agent-log--source-file)
              ((file-exists-p file))
              (encoded (file-name-nondirectory
                        (directory-file-name
                         (file-name-directory file)))))
    (agent-log-claude--find-existing-encoded-project encoded)))

(defun agent-log-claude--find-existing-encoded-project (encoded)
  "Return an existing directory whose Claude encoding is ENCODED."
  (cl-loop for root in (delete-dups
                        (list "/" (expand-file-name "~")))
           thereis
           (agent-log-claude--find-encoded-project-below root encoded 12)))

(defun agent-log-claude--find-encoded-project-below (directory encoded depth)
  "Find an existing project matching ENCODED below DIRECTORY within DEPTH."
  (when (and (>= depth 0) (file-directory-p directory))
    (let ((dir (file-name-as-directory directory)))
      (cond
       ((equal (agent-log-claude--encode-project-path dir) encoded)
        dir)
       ((zerop depth) nil)
       (t
        (cl-loop for child in (agent-log-claude--directory-children dir encoded)
                 thereis
                 (agent-log-claude--find-encoded-project-below
                  child encoded (1- depth))))))))

(defun agent-log-claude--directory-children (directory encoded)
  "Return child directories of DIRECTORY whose encodings may match ENCODED."
  (cl-loop for child in (ignore-errors
                          (directory-files directory t directory-files-no-dot-files-regexp))
           for child-encoded = (agent-log-claude--encode-project-path child)
           when (and (file-directory-p child)
                     (not (file-symlink-p child))
                     (or (equal child-encoded encoded)
                         (string-prefix-p (concat child-encoded "-") encoded)))
           collect child))

(defun agent-log-claude--lookup-session-project (session-id)
  "Look up the project directory for SESSION-ID in history.jsonl."
  (when-let* ((entry (agent-log-claude--lookup-history-entry session-id)))
    (plist-get entry :project)))

(defun agent-log-claude--lookup-history-entry (session-id)
  "Look up SESSION-ID in Claude history.jsonl."
  (gethash session-id (agent-log-claude--history-records agent-log-directory)))

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

(defun agent-log-claude--session-id-from-buffer ()
  "Return the session ID for the Claude session in the current buffer.
Resolve the buffer's session file — through the agent integration when
available, otherwise the standalone heuristics — and derive the id from
its file name."
  (when-let* ((backend (agent-log--get-backend 'claude-code))
              (file (agent-log--current-buffer-session-file backend)))
    (agent-log--session-id-from-file backend file)))

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
  "Return non-nil if JSONL-FILE already has a custom-title entry.
Only reads the last 4 KB of the file, since custom-title entries
are appended at the end."
  (agent-log-claude--file-tail-matches-p
   jsonl-file "\"type\"\\s-*:\\s-*\"custom-title\""))

(defun agent-log-claude--file-tail-matches-p (file regexp &optional tail-bytes)
  "Return non-nil if the tail of FILE matches REGEXP.
Reads the last TAIL-BYTES bytes (default 4096).  Falls back to
reading the entire file when it is smaller than TAIL-BYTES."
  (when-let* ((attrs (file-attributes file))
              (size (file-attribute-size attrs)))
    (let ((offset (max 0 (- size (or tail-bytes 4096)))))
      (with-temp-buffer
        (insert-file-contents file nil offset size)
        (goto-char (point-min))
        (re-search-forward regexp nil t)))))

(defun agent-log-claude--append-custom-title (jsonl-file session-id title &optional index)
  "Append a custom-title entry to JSONL-FILE for SESSION-ID with TITLE.
Also updates the cached JSONL size so that `agent-log--ensure-rendered'
does not treat the file as stale.  When INDEX is non-nil, merge the
new size into it (for batch operations); otherwise write to disk."
  (let ((entry (json-serialize
                (list :type "custom-title"
                      :customTitle (agent-log-claude--sanitize-for-json title)
                      :sessionId (agent-log-claude--sanitize-for-json session-id)))))
    (write-region (concat entry "\n") nil jsonl-file t 'quiet)
    (when-let* ((new-size (file-attribute-size (file-attributes jsonl-file))))
      (let ((props (list :jsonl-size new-size :custom-title t)))
        (if index
            (agent-log--index-merge index session-id props)
          (agent-log--index-update-props session-id props))))))

(defun agent-log-claude--sanitize-for-json (str)
  "Return STR as a multibyte string without text properties.
Unibyte strings containing raw UTF-8 bytes (as returned by some
JSON parsers) are decoded; text properties are stripped."
  (setq str (substring-no-properties str))
  (if (multibyte-string-p str) str
    (decode-coding-string str 'utf-8)))

(defun agent-log-claude--maybe-rename-session
    (session-id oneline &optional previous-oneline)
  "Rename SESSION-ID from ONELINE summary if appropriate.
Finds the session JSONL file and writes ONELINE when no custom title
exists.  If PREVIOUS-ONELINE matches the latest existing custom title,
append ONELINE as an updated title.
Does nothing if ONELINE is nil, empty, or the sentinel value."
  (when (and oneline
             (not (string-empty-p oneline))
             (not (equal oneline agent-log--no-conversation-sentinel)))
    (when-let* ((jsonl-file (agent-log--find-session-file-any session-id)))
      (when (agent-log-claude--should-write-summary-title-p
             jsonl-file previous-oneline)
        (agent-log-claude--append-custom-title
         jsonl-file session-id oneline)))))

(defun agent-log-claude--should-write-summary-title-p
    (jsonl-file previous-oneline)
  "Return non-nil if JSONL-FILE should receive a summary title.
PREVIOUS-ONELINE is the previous summary title, if one existed."
  (let ((latest-title (agent-log-claude--latest-custom-title jsonl-file)))
    (or (null latest-title)
        (and previous-oneline
             (not (string-empty-p previous-oneline))
             (equal latest-title previous-oneline)))))

(defun agent-log-claude--latest-custom-title (jsonl-file)
  "Return the latest custom title in JSONL-FILE, or nil."
  (cl-loop for line in (reverse (agent-log--read-file-lines jsonl-file))
           for entry = (ignore-errors (json-parse-string line
                                                         :object-type 'plist))
           when (and (equal (plist-get entry :type) "custom-title")
                     (plist-get entry :customTitle))
           return (plist-get entry :customTitle)))

(defun agent-log-claude--session-end-handler (message)
  "Handle a Claude Code event MESSAGE, triggering actions on session end.
Intended for use in `claude-code-event-hook'.  Runs the automatic
session-end actions when `:type' is \"Stop\", according to
`agent-log-auto-sync-sessions' and
`agent-log-auto-summarize-sessions'."
  (when (eq (plist-get message :type) 'stop)
    (run-with-timer
     1 nil
     (lambda ()
       (agent-log--auto-session-end-actions
        (agent-log-claude--session-id-from-event message))))
    nil))

(defun agent-log-claude--session-id-from-event (message)
  "Return the Claude session ID associated with event MESSAGE."
  (when-let* ((buffer-name (plist-get message :buffer-name))
              (buffer (get-buffer buffer-name)))
    (with-current-buffer buffer
      (agent-log-claude--session-id-from-buffer))))

;;;;; Current-buffer session detection

(cl-defmethod agent-log--current-buffer-p ((_backend agent-log-claude))
  "Return non-nil if the current buffer is a Claude Code terminal buffer."
  (and (require 'claude-code nil t)
       (claude-code--buffer-p (current-buffer))))

(cl-defmethod agent-log--current-buffer-session-file ((backend agent-log-claude))
  "Return the JSONL file for the Claude Code session in the current buffer.
BACKEND is the Claude Code backend instance.  Match visible terminal
text against project transcripts, then fall back to the most recent
JSONL in the project directory, then to a session in `history.jsonl'
whose project matches the buffer directory.  The optional agent
integration short-circuits these heuristics with the authoritative
session id."
  (let* ((dir (claude-code--extract-directory-from-buffer-name (buffer-name)))
         (session-dir (and dir (agent-log-claude--find-project-session-dir dir))))
    (or (and session-dir (agent-log-claude--visible-session-file session-dir))
        (and session-dir (agent-log-claude--find-latest-jsonl session-dir))
        (when-let* ((match (and dir
                                (agent-log-claude--find-session-for-project
                                 dir (agent-log--read-sessions backend)))))
          (plist-get (cdr match) :file)))))

(defun agent-log-claude--visible-session-file (directory)
  "Return the JSONL file in DIRECTORY matching visible Claude buffer text."
  (when-let* ((files (directory-files directory t "\\.jsonl\\'"))
              (snippets (agent-log-claude--visible-session-snippets)))
    (agent-log-claude--best-file-containing-snippets files snippets)))

(defun agent-log-claude--visible-session-snippets ()
  "Return distinctive transcript snippets visible in the current buffer."
  (let* ((start (max (point-min) (- (point-max) 12000)))
         (text (buffer-substring-no-properties start (point-max)))
         (lines (nreverse (split-string text "\n" t))))
    (seq-take
     (cl-loop for line in lines
              for snippet = (agent-log-claude--normalize-visible-snippet line)
              when (agent-log-claude--visible-snippet-line-p snippet line)
              collect snippet)
     8)))

(defun agent-log-claude--visible-snippet-line-p (line raw-line)
  "Return non-nil if LINE from RAW-LINE is useful for transcript matching."
  (and (or (>= (length line) 40)
           (and (string-match-p "\\`[[:space:]]*⏺" raw-line)
                (>= (length line) 20)))
       (not (string-match-p "\\`[[:space:]─&_]+\\'" line))
       (not (string-prefix-p "⏵" line))
       (not (string-prefix-p "⧉" line))
       (not (string-match-p "Pontificating.*·" line))
       (not (string-match-p "\\`\\(?:Searching for\\|Read [0-9]+ files?\\) "
                            line))))

(defun agent-log-claude--normalize-visible-snippet (line)
  "Return a searchable transcript snippet from visible terminal LINE."
  (let ((text (string-trim line)))
    (setq text (replace-regexp-in-string "\\`[⏺❯][[:space:]]*" "" text))
    (setq text (replace-regexp-in-string "\\`[•*-][[:space:]]+" "" text))
    (setq text (replace-regexp-in-string "\\`[0-9]+[.)][[:space:]]+" "" text))
    (setq text (replace-regexp-in-string "`" "" text))
    (string-trim (replace-regexp-in-string "[[:space:]]+" " " text))))

(defun agent-log-claude--best-file-containing-snippets (files snippets)
  "Return the unique best FILES match for SNIPPETS, or nil."
  (let ((best-file nil)
        (best-score 0)
        (tied nil))
    (dolist (file files)
      (let ((score (agent-log-claude--file-snippet-score file snippets)))
        (cond
         ((> score best-score)
          (setq best-file file
                best-score score
                tied nil))
         ((and (> score 0) (= score best-score))
          (setq tied t)))))
    (and (> best-score 0) (not tied) best-file)))

(defun agent-log-claude--file-snippet-score (file snippets)
  "Return the number of SNIPPETS found in FILE."
  (if (not (and file (file-readable-p file)))
      0
    (with-temp-buffer
      (insert-file-contents file)
      (goto-char (point-min))
      (while (search-forward "`" nil t)
        (replace-match "" t t))
      (cl-count-if
       (lambda (snippet)
         (goto-char (point-min))
         (search-forward snippet nil t))
       snippets))))

;;;;; Interactive commands

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
  (let* ((sessions (agent-log--read-all-sessions))
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
               (agent-log-claude--session-already-titled-p entry jsonl-file))
          (agent-log-claude--cache-custom-title-flag index sid entry)
          (cl-incf skipped))
         (t
          (agent-log-claude--append-custom-title jsonl-file sid oneline index)
          (cl-incf renamed)))))
    (agent-log--write-index index)
    (message "Renamed %d session(s), skipped %d (already named), %d without summary"
             renamed skipped no-summary)))

(defun agent-log-claude--session-already-titled-p (index-entry jsonl-file)
  "Return non-nil if the session is already titled.
Check INDEX-ENTRY for a cached flag first; fall back to reading
the tail of JSONL-FILE."
  (or (plist-get index-entry :custom-title)
      (agent-log-claude--session-has-custom-title-p jsonl-file)))

(defun agent-log-claude--cache-custom-title-flag (index sid entry)
  "Store `:custom-title t' in INDEX for SID when ENTRY lacks it.
Avoids redundant file-tail reads on future runs."
  (unless (plist-get entry :custom-title)
    (agent-log--index-merge index sid (list :custom-title t))))

;;;;; Icon

(defconst agent-log-claude--icon-svg
  "<svg fill=\"none\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><path clip-rule=\"evenodd\" d=\"M20.998 10.949H24v3.102h-3v3.028h-1.487V20H18v-2.921h-1.487V20H15v-2.921H9V20H7.488v-2.921H6V20H4.487v-2.921H3V14.05H0V10.95h3V5h17.998v5.949zM6 10.949h1.488V8.102H6v2.847zm10.51 0H18V8.102h-1.49v2.847z\" fill=\"#D97757\" fill-rule=\"evenodd\"/></svg>"
  "SVG source for the Claude Code icon (Clawd pixel art).
Source: lobehub/lobe-icons (MIT).")

;;;;; Backend registration

(defvar agent-log-claude--instance
  (agent-log--make-claude
   :name "Claude Code"
   :key 'claude-code
   :directory "~/.claude"
   :rendered-directory "~/.claude/rendered"
   :icon-svg agent-log-claude--icon-svg
   :icon-fallback "CC"))

(agent-log--register-backend 'claude-code agent-log-claude--instance)

(provide 'agent-log-claude)
;;; agent-log-claude.el ends here
