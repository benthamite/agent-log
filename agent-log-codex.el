;;; agent-log-codex.el --- Codex backend for agent-log  -*- lexical-binding: t; -*-

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

;; Codex backend for agent-log.  Implements all backend-specific methods
;; for reading sessions, parsing entries, and rendering conversations
;; from Codex's JSONL format.
;;
;; Codex stores session data in `~/.codex/':
;;   - `history.jsonl' — one line per user message: {session_id, ts, text}
;;   - `sessions/YYYY/MM/DD/rollout-DATE-SESSION_ID.jsonl' — full transcripts
;;
;; Each transcript line is an envelope: {timestamp, type, payload}.
;; Payload types include session_meta, turn_context, event_msg, and
;; response_item (which itself has subtypes: message, reasoning,
;; function_call, function_call_output, web_search_call,
;; custom_tool_call, custom_tool_call_output).

;;; Code:

(require 'cl-lib)
(require 'agent-log)

;;;;; Struct definition

(cl-defstruct (agent-log-codex (:constructor agent-log--make-codex)
                                (:include agent-log-backend)
                                (:copier nil))
  "Codex backend for agent-log.")

;;;;; Constants

(defconst agent-log-codex--system-text-regexp
  (rx bos (0+ space) "<"
      (or "environment_context"
          "permissions"
          "turn_aborted"
          "collaboration_mode")
      (or ">" " "))
  "Regexp matching system-generated XML tags in Codex user entries.")

(defconst agent-log-codex--session-id-regexp
  (rx "-" (group (= 8 hex) "-" (= 4 hex) "-" (= 4 hex) "-"
               (= 4 hex) "-" (= 12 hex)) ".jsonl" eos)
  "Regexp extracting a session UUID from a Codex rollout filename.")

;;;;; Generic method implementations

;;;;;; Session discovery

(cl-defmethod agent-log--read-sessions ((backend agent-log-codex))
  "Parse `history.jsonl' and session files, return alist of sessions.
Each value is a plist (:display :timestamp :project :file :file-dir :backend)."
  (let* ((history-file (expand-file-name "history.jsonl"
                                         (agent-log-backend-directory backend)))
         (file-index (agent-log--build-session-file-index backend))
         (history (make-hash-table :test #'equal))
         (meta-cache (make-hash-table :test #'equal))
         result)
    ;; Parse history.jsonl to get first-message text and earliest timestamp.
    (when (file-exists-p history-file)
      (dolist (entry (agent-log--parse-jsonl-file history-file))
        (let ((sid (plist-get entry :session_id))
              (ts (plist-get entry :ts))
              (text (plist-get entry :text)))
          (when sid
            (let ((existing (gethash sid history)))
              (if existing
                  ;; Keep earliest timestamp.
                  (when (and (numberp ts)
                             (< ts (plist-get existing :ts)))
                    (puthash sid (list :ts ts
                                      :text (plist-get existing :text))
                             history))
                (puthash sid (list :ts ts :text (or text "")) history)))))))
    ;; For each session file, build metadata.
    (maphash
     (lambda (sid file)
       (let* ((hist (gethash sid history))
              (ts-sec (when hist (plist-get hist :ts)))
              (ts-ms (when (numberp ts-sec) (* ts-sec 1000)))
              (display (when hist (plist-get hist :text)))
              (session-meta (agent-log-codex--read-session-meta file))
              (cwd (or (plist-get session-meta :cwd) ""))
              ;; Fall back to session_meta timestamp if history has none.
              (ts-ms (or ts-ms
                         (agent-log--iso-to-epoch-ms
                          (plist-get session-meta :timestamp))))
              (display (or display "")))
         (puthash sid session-meta meta-cache)
         (push (list sid
                     :display display
                     :timestamp ts-ms
                     :project cwd
                     :file-dir (file-name-directory file)
                     :file file
                     :backend backend)
               result)))
     file-index)
    (sort result (lambda (a b)
                   (agent-log--timestamp>
                    (plist-get (cdr a) :timestamp)
                    (plist-get (cdr b) :timestamp))))))

(cl-defmethod agent-log--build-session-file-index ((backend agent-log-codex))
  "Build a hash table mapping session-id to JSONL file path.
Scans the sessions directory tree."
  (let ((index (make-hash-table :test #'equal))
        (sessions-dir (expand-file-name "sessions"
                                        (agent-log-backend-directory backend))))
    (when (file-directory-p sessions-dir)
      (dolist (file (directory-files-recursively sessions-dir "\\.jsonl\\'"))
        (when (string-match agent-log-codex--session-id-regexp file)
          (puthash (match-string 1 file) file index))))
    index))

(cl-defmethod agent-log--find-session-file ((backend agent-log-codex) session-id)
  "Find the JSONL file for SESSION-ID under the sessions directory."
  (let ((sessions-dir (expand-file-name "sessions"
                                        (agent-log-backend-directory backend))))
    (when (file-directory-p sessions-dir)
      (cl-block nil
        (dolist (file (directory-files-recursively sessions-dir "\\.jsonl\\'"))
          (when (string-match-p (regexp-quote session-id) file)
            (cl-return file)))))))

;;;;;; Entry normalization

(cl-defmethod agent-log--normalize-entries ((_backend agent-log-codex) entries)
  "Normalize Codex ENTRIES to the canonical agent-log format.
Each Codex entry is an envelope {timestamp, type, payload}.
This converts them to the format expected by the rendering pipeline:
  (:type ROLE :message (:role ROLE :content CONTENT) :timestamp TS)
and merges consecutive entries of the same role into single turns."
  (let (normalized)
    (dolist (entry entries)
      (when-let* ((item (agent-log-codex--normalize-entry entry)))
        (push item normalized)))
    (agent-log-codex--merge-consecutive-turns (nreverse normalized))))

(defun agent-log-codex--normalize-entry (entry)
  "Normalize a single Codex ENTRY to canonical format, or nil to skip."
  (let ((type (plist-get entry :type))
        (ts (plist-get entry :timestamp))
        (payload (plist-get entry :payload)))
    (pcase type
      ("session_meta"
       ;; Synthesize a progress entry for metadata extraction.
       (list :type "progress"
             :cwd (plist-get payload :cwd)
             :timestamp (or (plist-get payload :timestamp) ts)))
      ("response_item"
       (agent-log-codex--normalize-response-item payload ts))
      (_ nil))))

(defun agent-log-codex--normalize-response-item (payload ts)
  "Normalize a response_item PAYLOAD with timestamp TS."
  (let ((item-type (plist-get payload :type))
        (role (plist-get payload :role)))
    (pcase item-type
      ("message"
       (pcase role
         ("user"
          (when-let* ((content (agent-log-codex--normalize-content
                                (plist-get payload :content)))
                      ((agent-log-codex--content-non-empty-p content)))
            (list :type "user"
                  :message (list :role "user" :content content)
                  :timestamp ts)))
         ("assistant"
          (when-let* ((content (agent-log-codex--normalize-content
                                (plist-get payload :content)))
                      ((agent-log-codex--content-non-empty-p content)))
            (list :type "assistant"
                  :message (list :role "assistant" :content content)
                  :timestamp ts)))
         ("developer" nil)            ; system instructions, skip
         (_ nil)))
      ("function_call"
       (let* ((name (plist-get payload :name))
              (args-str (plist-get payload :arguments))
              (input (agent-log-codex--parse-arguments args-str)))
         (list :type "assistant"
               :message (list :role "assistant"
                              :content (list (list :type "tool_use"
                                                   :name name
                                                   :input input)))
               :timestamp ts)))
      ("function_call_output"
       (let ((output (or (plist-get payload :output) "")))
         (list :type "user"
               :message (list :role "user"
                              :content (list (list :type "tool_result"
                                                   :content output)))
               :timestamp ts)))
      ("web_search_call"
       (let* ((action (plist-get payload :action))
              (query (when action (plist-get action :query))))
         (list :type "assistant"
               :message (list :role "assistant"
                              :content (list (list :type "tool_use"
                                                   :name "WebSearch"
                                                   :input (list :query (or query "")))))
               :timestamp ts)))
      ("custom_tool_call"
       (let ((name (plist-get payload :name))
             (input-str (plist-get payload :input)))
         (list :type "assistant"
               :message (list :role "assistant"
                              :content (list (list :type "tool_use"
                                                   :name (or name "custom_tool")
                                                   :input (list :input (or input-str "")))))
               :timestamp ts)))
      ("custom_tool_call_output"
       (let ((output (or (plist-get payload :output) "")))
         (list :type "user"
               :message (list :role "user"
                              :content (list (list :type "tool_result"
                                                   :content output)))
               :timestamp ts)))
      ("reasoning"
       ;; Codex reasoning is encrypted; extract summary if available.
       (let ((summary (plist-get payload :summary)))
         (when (and (listp summary) summary)
           (let ((text (mapconcat
                        (lambda (s) (or (plist-get s :text) ""))
                        summary "")))
             (unless (string-empty-p text)
               (list :type "assistant"
                     :message (list :role "assistant"
                                    :content (list (list :type "thinking"
                                                         :thinking text)))
                     :timestamp ts))))))
      (_ nil))))

(defun agent-log-codex--normalize-content (content)
  "Normalize Codex message CONTENT to canonical format.
Converts `input_text' and `output_text' items to `text' items,
and strips system-generated XML blocks."
  (cond
   ((stringp content) content)
   ((listp content)
    (let (items)
      (dolist (item content)
        (let ((type (plist-get item :type)))
          (pcase type
            ((or "input_text" "output_text")
             (let ((text (plist-get item :text)))
               (unless (and (stringp text)
                            (string-match-p
                             agent-log-codex--system-text-regexp text))
                 (push (list :type "text" :text text) items))))
            (_ (push item items)))))
      (nreverse items)))
   (t content)))

(defun agent-log-codex--content-non-empty-p (content)
  "Return non-nil if CONTENT has meaningful data.
A string is non-empty if it is non-blank; a list is non-empty
if it has at least one element."
  (cond
   ((stringp content) (not (string-empty-p (string-trim content))))
   ((listp content) (consp content))
   (t nil)))

(defun agent-log-codex--parse-arguments (args-string)
  "Parse a Codex function_call arguments JSON string into a plist.
Returns nil if parsing fails."
  (when (and (stringp args-string) (not (string-empty-p args-string)))
    (condition-case nil
        (json-parse-string args-string :object-type 'plist)
      (error nil))))

(defun agent-log-codex--merge-consecutive-turns (entries)
  "Merge consecutive ENTRIES of the same role into single turns.
This groups tool calls with their preceding assistant message and
tool results with their following user message, matching Claude's
turn-based format."
  (let (result current)
    (dolist (entry entries)
      (let ((type (plist-get entry :type)))
        (if (and current (equal type (plist-get current :type))
                 ;; Only merge user/assistant, not progress.
                 (member type '("user" "assistant")))
            ;; Merge content into current turn.
            (let* ((cur-msg (plist-get current :message))
                   (cur-content (plist-get cur-msg :content))
                   (new-msg (plist-get entry :message))
                   (new-content (plist-get new-msg :content))
                   (merged (agent-log-codex--merge-content
                            cur-content new-content)))
              (plist-put cur-msg :content merged))
          ;; Different role or non-mergeable; push current, start new.
          (when current (push current result))
          (setq current (copy-tree entry)))))
    (when current (push current result))
    (nreverse result)))

(defun agent-log-codex--merge-content (a b)
  "Merge two content values A and B.
Both may be strings or lists of content items."
  (let ((a-list (if (stringp a) (list (list :type "text" :text a))
                  (if (listp a) a nil)))
        (b-list (if (stringp b) (list (list :type "text" :text b))
                  (if (listp b) b nil))))
    (append a-list b-list)))

;;;;;; Entry filtering

(cl-defmethod agent-log--filter-conversation ((backend agent-log-codex) entries)
  "Filter ENTRIES to user and assistant messages, excluding system entries."
  (seq-filter (lambda (entry) (agent-log--conversation-entry-p backend entry))
              entries))

(cl-defmethod agent-log--conversation-entry-p ((backend agent-log-codex) entry)
  "Return non-nil if ENTRY is a genuine conversation message."
  (let ((type (plist-get entry :type)))
    (and (member type '("user" "assistant"))
         (not (agent-log--system-entry-p backend entry)))))

(cl-defmethod agent-log--system-entry-p ((_backend agent-log-codex) entry)
  "Return non-nil if ENTRY is a system-generated message.
These are user-role entries whose text starts with system XML tags,
or entries containing only tool results with no user text."
  (let* ((message (plist-get entry :message))
         (content (plist-get message :content)))
    (cond
     ;; String content starting with system XML.
     ((stringp content)
      (string-match-p agent-log-codex--system-text-regexp content))
     ;; List content: system if ALL text items start with system XML.
     ((listp content)
      (let ((text-items (seq-filter
                         (lambda (item)
                           (equal (plist-get item :type) "text"))
                         content)))
        (and text-items
             (seq-every-p
              (lambda (item)
                (let ((text (plist-get item :text)))
                  (and (stringp text)
                       (string-match-p agent-log-codex--system-text-regexp
                                       text))))
              text-items))))
     (t nil))))

;;;;;; Metadata extraction

(cl-defmethod agent-log--extract-session-metadata ((_backend agent-log-codex) entries)
  "Extract project and date from ENTRIES into buffer-local variables."
  (when-let* ((first-msg (agent-log--find-first-message entries)))
    (setq agent-log--session-date
          (agent-log--format-iso-timestamp (plist-get first-msg :timestamp))))
  (when-let* ((progress (agent-log--find-progress-entry entries))
              (cwd (plist-get progress :cwd))
              ((not (string-empty-p cwd))))
    (setq agent-log--session-project cwd)))

(cl-defmethod agent-log--first-user-text ((backend agent-log-codex) entries)
  "Return the text of the first genuine user message in ENTRIES."
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
      (let ((texts '()))
        (dolist (item content)
          (when (equal (plist-get item :type) "text")
            (let ((text (plist-get item :text)))
              (when (and (stringp text)
                         (not (string-match-p
                               agent-log-codex--system-text-regexp text)))
                (push text texts)))))
        (car (nreverse texts))))
     (t nil))))

;;;;;; Tool input summaries

(cl-defmethod agent-log--summarize-tool-input-by-name ((_backend agent-log-codex) name input)
  "Return a summary of tool INPUT specific to tool NAME."
  (pcase name
    ("exec_command"
     (agent-log-codex--summarize-exec-command input))
    ("apply_patch"
     (agent-log-codex--summarize-apply-patch input))
    ("WebSearch"
     (format "> **query**: %s" (or (plist-get input :query) "?")))
    (_ "")))

(defun agent-log-codex--summarize-exec-command (input)
  "Summarize exec_command tool INPUT."
  (let ((cmd (agent-log--truncate-string
              (or (plist-get input :cmd) "") agent-log-max-tool-input-length))
        (workdir (plist-get input :workdir)))
    (if workdir
        (format "> ```\n> %s\n> ```\n> **workdir**: %s" cmd workdir)
      (format "> ```\n> %s\n> ```" cmd))))

(defun agent-log-codex--summarize-apply-patch (input)
  "Summarize apply_patch tool INPUT."
  (let ((patch (or (plist-get input :input) "")))
    ;; Extract file paths from patch header lines.
    (let ((files '()))
      (dolist (line (split-string patch "\n"))
        (when (string-match "^\\*\\*\\* \\(Add\\|Update\\|Delete\\) File: \\(.+\\)" line)
          (push (format "%s: %s" (match-string 1 line) (match-string 2 line))
                files)))
      (if files
          (format "> %s" (string-join (nreverse files) "\n> "))
        (format "> %s" (agent-log--truncate-string
                        patch agent-log-max-tool-input-length))))))

;;;;;; Message text extraction

(cl-defmethod agent-log--extract-message-text ((_backend agent-log-codex) content)
  "Extract plain text from message CONTENT.
Tool-use, tool-result, and thinking blocks are ignored."
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

(cl-defmethod agent-log--active-session-ids ((_backend agent-log-codex))
  "Return a list of session IDs for live Codex sessions.
Currently returns nil as there is no integration with a running
Codex process."
  nil)

;;;;;; Resume session

(cl-defmethod agent-log--resume-session ((_backend agent-log-codex) session-id)
  "Resume the Codex session SESSION-ID."
  (let* ((project-dir (or agent-log--session-project
                          default-directory))
         (default-directory (if (and project-dir
                                     (file-directory-p project-dir))
                                project-dir
                              default-directory)))
    (compile (format "codex --resume %s" (shell-quote-argument session-id))
             t)))

;;;;; Codex-specific helper functions

(defconst agent-log-codex--session-meta-read-bytes 65536
  "Bytes to read from a session file to capture the first line.
The session_meta line includes the full system prompt and is
typically 15-20KB.")

(defun agent-log-codex--read-session-meta (file)
  "Read the session_meta entry from the first line of FILE.
Returns a plist with at least :id, :cwd, and :timestamp, or nil."
  (condition-case nil
      (with-temp-buffer
        (insert-file-contents file nil 0
                              agent-log-codex--session-meta-read-bytes)
        (goto-char (point-min))
        (when-let* ((eol (line-end-position))
                    ((< eol (point-max))) ;; ensure we got a full line
                    (line (buffer-substring-no-properties (point) eol))
                    (parsed (agent-log--try-parse-json line))
                    ((equal (plist-get parsed :type) "session_meta")))
          (plist-get parsed :payload)))
    (error nil)))

;;;;; Backend registration

(defvar agent-log-codex--instance
  (agent-log--make-codex
   :name "Codex"
   :key 'codex
   :directory "~/.codex"
   :rendered-directory "~/.codex/rendered"))

(agent-log--register-backend 'codex agent-log-codex--instance)

(provide 'agent-log-codex)
;;; agent-log-codex.el ends here
