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
;; Codex exposes the interactive session catalog through app-server
;; `thread/list'.  Each catalog entry names the exact full transcript,
;; normally under `CODEX_HOME/sessions/YYYY/MM/DD/'.
;;
;; Each transcript line is an envelope: {timestamp, type, payload}.
;; Payload types include session_meta, turn_context, event_msg, and
;; response_item (which itself has subtypes: message, reasoning,
;; function_call, function_call_output, web_search_call,
;; custom_tool_call, custom_tool_call_output).

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'agent-log)

(declare-function codex--start-subcommand "codex" (subcommand &optional args extra-args))
(declare-function codex--app-server-launch-resume-session "codex-app-server" (session-id))
(declare-function codex--app-server-send-resume "codex-app-server" (method thread))
(declare-function codex--app-server-insert-status "codex-app-server" (text))
(declare-function codex--cache-session-transcript "codex" (session-id file))
(declare-function codex--buffer-p "codex" (buffer))
(declare-function codex--buffer-directory-for "codex" (buffer))
(declare-function agent-codex--effective-codex-home "agent-codex" ())
(defvar agent-log-codex--instance)
(defvar codex-terminal-backend)
(defvar codex-program "codex")
(defvar codex-event-hook nil
  "Hook run for Codex lifecycle events.")
(defvar codex-start-hook nil
  "Hook run when a Codex session starts.")

(defvar agent-log-codex--exact-resume-paths
  (make-hash-table :test #'equal)
  "Catalog transcript paths pending an Agent Log app-server resume.")

(defvar-local agent-log-codex--buffer-session-id nil
  "Codex session ID last reported for the current buffer.")

(defvar-local agent-log-codex--buffer-session-file nil
  "Codex transcript file last resolved for the current buffer.")

(declare-function agent-log--session-end-hook-needed-p "agent-log")

;;;;; Struct definition

(cl-defstruct (agent-log-codex (:constructor agent-log--make-codex)
                                (:include agent-log-backend)
                                (:copier nil))
  "Codex backend for agent-log.")

;;;;; Constants

(defconst agent-log-codex--system-text-regexp
  (rx bos (0+ space)
      (or (seq "<"
               (or "environment_context"
                   "permissions"
                   "recommended_plugins"
                   "turn_aborted"
                   "collaboration_mode"
                   "INSTRUCTIONS")
               (or ">" " "))
          "# AGENTS.md instructions"))
  "Regexp matching system-generated text in Codex user entries.")

(defconst agent-log-codex--uuid-regexp
  (rx (= 8 hex) "-" (= 4 hex) "-" (= 4 hex) "-"
      (= 4 hex) "-" (= 12 hex))
  "Regexp matching a Codex session UUID.")

(defconst agent-log-codex--session-id-regexp
  (rx "-" (group (= 8 hex) "-" (= 4 hex) "-" (= 4 hex) "-"
               (= 4 hex) "-" (= 12 hex)) ".jsonl" eos)
  "Regexp extracting a session UUID from a Codex rollout filename.")

(defconst agent-log-codex--session-start-match-window-ms (* 5 60 1000)
  "Maximum launch-time delta for matching a Codex process to a session.")

(defcustom agent-log-codex-app-server-timeout 15
  "Seconds to wait for a Codex app-server catalog response."
  :type 'number
  :group 'agent-log)

(defconst agent-log-codex--thread-list-page-size 1000
  "Number of canonical Codex threads requested per catalog page.")

(defun agent-log-codex--effective-home (backend)
  "Return the Codex home whose native registry BACKEND should mirror.
When the user's account-aware Agent integration is loaded, use the
same resolved account home it supplies to new Codex processes.
Otherwise honor `CODEX_HOME' and finally BACKEND's configured home."
  (file-name-as-directory
   (expand-file-name
    (or (and (fboundp 'agent-codex--effective-codex-home)
             (agent-codex--effective-codex-home))
        (getenv "CODEX_HOME")
        (agent-log-backend-directory backend)))))

(cl-defmethod agent-log--backend-source-directories
  ((backend agent-log-codex))
  "Return the effective Codex transcript root for BACKEND."
  (list (expand-file-name "sessions"
                          (agent-log-codex--effective-home backend))))

;;;;; Generic method implementations

;;;;;; Session discovery

(cl-defmethod agent-log--read-sessions ((backend agent-log-codex))
  "Read Codex's canonical interactive thread catalog for BACKEND.
Each value is a plist (:display :timestamp :project :file :file-dir
:backend :source)."
  (sort
   (delq nil
         (mapcar (lambda (thread)
                   (agent-log-codex--thread-session backend thread))
                 (agent-log-codex--thread-list backend)))
   (lambda (a b)
     (agent-log--timestamp>
      (plist-get (cdr a) :timestamp)
      (plist-get (cdr b) :timestamp)))))

(defun agent-log-codex--thread-session (backend thread)
  "Convert canonical Codex THREAD into an Agent Log session for BACKEND."
  (let ((session-id (alist-get 'id thread))
        (file (alist-get 'path thread))
        (created-at (alist-get 'createdAt thread)))
    (when (and (stringp session-id)
               (stringp file)
               (not (string-empty-p file)))
      (setq file (expand-file-name file))
      (list session-id
            :display (or (alist-get 'preview thread) "")
            :timestamp (and (numberp created-at) (* created-at 1000))
            :project (or (alist-get 'cwd thread) "")
            :file-dir (file-name-directory file)
            :file file
            :backend backend
            :source-file-state
            (and (file-exists-p file)
                 (agent-log-codex--session-file-state file))
            :source (alist-get 'source thread)
            :thread-source (alist-get 'threadSource thread)))))

(defun agent-log-codex--thread-list (backend)
  "Return every Codex thread that native Resume would offer for BACKEND.
Read indexed state first, as native Resume does, and fall back to the
rollout scan-and-repair path when the initial indexed page is empty.
Agent Log omits `cwd', because it lists every project, and follows every
cursor because it lists the whole catalog rather than one page."
  (let* ((home (agent-log-codex--effective-home backend))
         (process-environment
          (cons (concat "CODEX_HOME=" (directory-file-name home))
                (cl-remove-if
                 (lambda (entry)
                   (string-prefix-p "CODEX_HOME=" entry))
                 process-environment)))
         (stderr-buffer (generate-new-buffer " *agent-log-codex-stderr*"))
         (process
          (make-process
           :name "agent-log-codex-catalog"
           :command (list codex-program "app-server" "--stdio")
           :connection-type 'pipe
           :coding 'utf-8-emacs
           :stderr stderr-buffer
           :noquery t
           :filter #'agent-log-codex--catalog-process-filter))
         (request-id 0)
         (seen-ids (make-hash-table :test #'equal))
         (seen-cursors (make-hash-table :test #'equal))
         (state-db-only t)
         (first-page t)
         cursor
         threads)
    (unwind-protect
        (progn
          (agent-log-codex--catalog-request
           process (cl-incf request-id) "initialize"
           '((clientInfo
              (name . "agent-log")
              (title . "Agent Log")
              (version . "0.3.0"))))
          (let (done)
            (while (not done)
              (let* ((params
                      `((limit . ,agent-log-codex--thread-list-page-size)
                        (sortKey . "updated_at")
                        (sortDirection . "desc")
                        (useStateDbOnly . ,(if state-db-only
                                               t
                                             :json-false))
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
                      (error "Codex thread catalog repeated cursor %s"
                             next-cursor))
                     (t
                      (puthash next-cursor t seen-cursors)
                      (setq cursor next-cursor)))))))
          threads))
      (agent-log-codex--stop-catalog-process process stderr-buffer))))

(defun agent-log-codex--catalog-process-filter (process output)
  "Accumulate and decode newline-delimited app-server OUTPUT from PROCESS."
  (let ((pending (concat (or (process-get process 'pending-output) "")
                         output))
        line)
    (while (string-match "\n" pending)
      (setq line (substring pending 0 (match-beginning 0))
            pending (substring pending (match-end 0)))
      (unless (string-empty-p line)
        (condition-case err
            (process-put
             process 'messages
             (nconc (process-get process 'messages)
                    (list
                     (json-parse-string
                      line :object-type 'alist :array-type 'list
                      :null-object nil :false-object nil))))
          (error
           (process-put process 'protocol-error
                        (error-message-string err))))))
    (process-put process 'pending-output pending)))

(defun agent-log-codex--catalog-request (process id method params)
  "Send METHOD with PARAMS and ID to catalog PROCESS, returning its result."
  (process-send-string
   process
   (concat
    (json-encode `((id . ,id) (method . ,method) (params . ,params)))
    "\n"))
  (let ((deadline (+ (float-time) agent-log-codex-app-server-timeout))
        response)
    (while (and (not response)
                (process-live-p process)
                (< (float-time) deadline))
      (setq response
            (seq-find (lambda (message)
                        (equal (alist-get 'id message) id))
                      (process-get process 'messages)))
      (unless response
        (accept-process-output process 0.05)))
    (when-let* ((protocol-error (process-get process 'protocol-error)))
      (error "Codex app-server returned malformed catalog data: %s"
             protocol-error))
    (unless response
      (error "Codex app-server did not answer %s within %.1f seconds"
             method agent-log-codex-app-server-timeout))
    (when-let* ((rpc-error (alist-get 'error response)))
      (error "Codex %s failed: %s"
             method (or (alist-get 'message rpc-error) rpc-error)))
    (alist-get 'result response)))

(defun agent-log-codex--stop-catalog-process (process stderr-buffer)
  "Stop catalog PROCESS and dispose of its STDERR-BUFFER."
  (when (process-live-p process)
    (set-process-query-on-exit-flag process nil)
    (delete-process process))
  (when (buffer-live-p (process-buffer process))
    (let ((kill-buffer-query-functions nil))
      (kill-buffer (process-buffer process))))
  (when (buffer-live-p stderr-buffer)
    (when-let* ((stderr-process (get-buffer-process stderr-buffer)))
      (set-process-query-on-exit-flag stderr-process nil)
      (when (process-live-p stderr-process)
        (delete-process stderr-process)))
    (let ((kill-buffer-query-functions nil))
      (kill-buffer stderr-buffer))))

(defun agent-log-codex--session-file-state (file)
  "Return source file state for FILE."
  (agent-log--session-file-state (list :file file)))

(cl-defmethod agent-log--build-session-file-index ((backend agent-log-codex))
  "Build a hash table mapping session-id to JSONL file path.
Scans the sessions directory tree."
  (let ((index (make-hash-table :test #'equal))
        (sessions-dir (car (agent-log--backend-source-directories backend))))
    (when (file-directory-p sessions-dir)
      (dolist (file (directory-files-recursively sessions-dir "\\.jsonl\\'"))
        (when (string-match agent-log-codex--session-id-regexp file)
          (puthash (match-string 1 file) file index))))
    index))

(cl-defmethod agent-log--find-session-file ((backend agent-log-codex) session-id)
  "Find the JSONL file for SESSION-ID under the sessions directory."
  (let ((sessions-dir (car (agent-log--backend-source-directories backend))))
    (when (file-directory-p sessions-dir)
      (cl-block nil
        (dolist (file (directory-files-recursively sessions-dir "\\.jsonl\\'"))
          (when (string-match-p (regexp-quote session-id) file)
            (cl-return file)))))))

(cl-defmethod agent-log--session-id-from-file ((_backend agent-log-codex) file)
  "Extract the Codex session UUID from FILE.
Codex rollout filenames have the form `rollout-DATE-UUID.jsonl'; this
returns just the UUID portion."
  (if (string-match agent-log-codex--session-id-regexp file)
      (match-string 1 file)
    (file-name-sans-extension (file-name-nondirectory file))))

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
These are user-role entries whose text starts with known system
preambles, or entries containing only tool results with no user text."
  (let* ((message (plist-get entry :message))
         (content (plist-get message :content)))
    (cond
     ;; String content starting with a known system preamble.
     ((stringp content)
      (string-match-p agent-log-codex--system-text-regexp content))
     ;; List content: system if all text items start with a known preamble.
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
  (when-let* ((timestamp (agent-log--find-session-timestamp entries)))
    (setq agent-log--session-date
          (agent-log--format-iso-timestamp timestamp)))
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

(cl-defmethod agent-log--summary-line-candidate-p ((_backend agent-log-codex) line)
  "Return non-nil if LINE may contain Codex summary text."
  (and (string-match-p
        "\"type\"[[:space:]]*:[[:space:]]*\"response_item\"" line)
       (string-match-p
        "\"type\"[[:space:]]*:[[:space:]]*\"message\"" line)
       (string-match-p
        "\"role\"[[:space:]]*:[[:space:]]*\"\\(?:user\\|assistant\\)\""
        line)
       (not (string-match-p "# AGENTS\\.md instructions\\|<INSTRUCTIONS"
                            line))))

;;;;;; Active sessions

(cl-defmethod agent-log--active-session-ids ((backend agent-log-codex))
  "Return a list of session IDs for live Codex sessions.
Active Codex terminal buffers are matched to transcript files using
the same project and launch-time heuristic as
`agent-log--current-buffer-session-file'."
  (when (require 'codex nil t)
    (let ((sessions (agent-log--read-sessions backend))
          ids)
      (dolist (buffer (buffer-list))
        (when-let* (((codex--buffer-p buffer))
                    (process (get-buffer-process buffer))
                    ((process-live-p process)))
          (with-current-buffer buffer
            (when-let* ((file (agent-log-codex--buffer-session-file
                               backend sessions)))
              (push (agent-log--session-id-from-file
                     backend file)
                    ids)))))
      (delete-dups ids))))

(defun agent-log-codex--session-end-handler (message)
  "Handle a Codex event MESSAGE, triggering actions on Stop."
  (when (equal (plist-get message :type) "Stop")
    (run-with-timer
     1 nil
     (lambda ()
       (agent-log--auto-session-end-actions
        (agent-log-codex--session-id-from-event message))))
    nil))

(defun agent-log-codex--session-id-from-event (message)
  "Return the Codex session ID associated with event MESSAGE."
  (when-let* ((buffer-name (plist-get message :buffer-name))
              (buffer (get-buffer buffer-name)))
    (with-current-buffer buffer
      (when-let* ((backend agent-log-codex--instance)
                  (file (agent-log-codex--buffer-session-file
                         backend
                         (lambda () (agent-log--read-sessions backend)))))
        (agent-log--session-id-from-file backend file)))))

;;;;;; Resume session

(defun agent-log-codex--exact-resume-advice (original session-id)
  "Resume SESSION-ID at its exact Agent Log catalog path.
ORIGINAL is Codex's ordinary ID-only app-server resume function.  Use
it only for calls that did not originate in Agent Log."
  (if-let* ((transcript
             (gethash session-id agent-log-codex--exact-resume-paths)))
      (progn
        (remhash session-id agent-log-codex--exact-resume-paths)
        (if (file-readable-p transcript)
            (codex--app-server-send-resume
             "thread/resume"
             `((id . ,session-id) (path . ,transcript)))
          (codex--app-server-insert-status
           (format "Codex transcript disappeared before resume: %s"
                   transcript))))
    (funcall original session-id)))

(defun agent-log-codex--install-exact-resume-advice ()
  "Make Agent Log app-server resumes path-exact."
  (when (and (fboundp 'codex--app-server-begin-resume-session-id)
             (not
              (advice-member-p
               #'agent-log-codex--exact-resume-advice
               'codex--app-server-begin-resume-session-id)))
    (advice-add 'codex--app-server-begin-resume-session-id
                :around #'agent-log-codex--exact-resume-advice)))

(cl-defmethod agent-log--resume-session ((backend agent-log-codex) session-id)
  "Resume the Codex session SESSION-ID."
  (agent-log-codex--prepare-resume backend session-id)
  (let* ((project-dir (or agent-log--session-project
                          default-directory))
         (default-directory (if (and project-dir
                                     (file-directory-p project-dir))
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

(defun agent-log-codex--prepare-resume (backend session-id)
  "Validate SESSION-ID against the canonical catalog of BACKEND and prepare.
Record the session's project in `agent-log--session-project', cache the
canonical transcript with the codex package, and, when the effective
`codex-terminal-backend' is `app-server', register the transcript so
the resume is path-exact.  Return the project directory recorded in the
catalog, or nil when it names no usable directory.  Signal a
`user-error' when SESSION-ID is not in the catalog, the codex package
is unavailable, or the transcript is unreadable."
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
                 (stringp agent-log--session-project)
                 (not (string-empty-p agent-log--session-project))
                 (file-directory-p agent-log--session-project))
        agent-log--session-project))))

;;;;;; Current-buffer session detection

(cl-defmethod agent-log--current-buffer-p ((_backend agent-log-codex))
  "Return non-nil if the current buffer is a Codex terminal buffer."
  (and (require 'codex nil t)
       (codex--buffer-p (current-buffer))))

(cl-defmethod agent-log--current-buffer-session-file ((backend agent-log-codex))
  "Return the JSONL file for the Codex session in the current buffer.
BACKEND is the Codex backend instance.  Resumed sessions expose their
session ID in the process command, so use that as the primary key.  For
fresh sessions, fall back to matching a top-level session whose recorded
CWD matches the buffer's directory and whose session timestamp is near
the terminal process start time."
  (agent-log-codex--buffer-session-file
   backend (lambda () (agent-log--read-sessions backend))))

(defun agent-log-codex--buffer-session-file (backend read-sessions)
  "Return the JSONL file for current Codex buffer using BACKEND.
READ-SESSIONS is either a function of no arguments returning the session
catalog, or the catalog itself.  A function is called at most once, and
only when the buffer's own records cannot name the session, because
reading the catalog starts a Codex app-server process."
  (let ((catalog 'unread))
    (cl-flet ((sessions ()
                (when (eq catalog 'unread)
                  (setq catalog (if (functionp read-sessions)
                                    (funcall read-sessions)
                                  read-sessions)))
                catalog))
      (or (agent-log-codex--recorded-buffer-session-file backend)
          (when-let* ((sid (agent-log-codex--buffer-resumed-session-id)))
            (agent-log--find-session-file backend sid))
          (when-let* ((dir (codex--buffer-directory-for (current-buffer))))
            (let* ((process-start-ms
                    (agent-log-codex--buffer-process-start-ms))
                   (match (agent-log-codex--find-session-for-project
                           dir (sessions) process-start-ms)))
              (plist-get (cdr match) :file)))
          (agent-log-codex--visible-session-file (sessions))))))

(defun agent-log-codex--recorded-buffer-session-file (backend)
  "Return the current buffer's recorded transcript file for BACKEND."
  (or (and agent-log-codex--buffer-session-file
           (file-exists-p agent-log-codex--buffer-session-file)
           agent-log-codex--buffer-session-file)
      (when-let* ((sid agent-log-codex--buffer-session-id)
                  (file (agent-log--find-session-file backend sid)))
        (setq-local agent-log-codex--buffer-session-file file))))

(defun agent-log-codex--buffer-resumed-session-id ()
  "Return the explicit resumed Codex session ID for the current buffer."
  (when-let* ((process (get-buffer-process (current-buffer))))
    (agent-log-codex--resumed-session-id-from-command
     (process-command process))))

(defun agent-log-codex--resumed-session-id-from-command (command)
  "Return the session ID from Codex resume COMMAND, or nil.
COMMAND is a process command list such as that returned by
`process-command'."
  (when-let* ((resume-tail (cdr (member "resume" command)))
              (session-id (car resume-tail))
              ((string-match-p
                (concat "\\`" agent-log-codex--uuid-regexp "\\'")
                session-id)))
    session-id))

(defun agent-log-codex--find-session-for-project
    (directory sessions &optional target-timestamp-ms)
  "Find the latest session in SESSIONS whose project matches DIRECTORY.
SESSIONS should be sorted newest-first (as from
`agent-log--read-sessions').  DIRECTORY is compared against each
session's :project field using both the expanded path and
`file-truename'.  When TARGET-TIMESTAMP-MS is non-nil, return the
matching session whose timestamp is closest to it, provided the
timestamp is within `agent-log-codex--session-start-match-window-ms'."
  (let* ((targets (agent-log-codex--directory-match-targets directory))
         (matches
          (cl-remove-if-not
           (lambda (session)
             (agent-log-codex--session-in-directory-p session targets))
           sessions)))
    (if (numberp target-timestamp-ms)
        (agent-log-codex--nearest-session-by-timestamp
         matches target-timestamp-ms)
      (car matches))))

(defun agent-log-codex--session-in-directory-p (session targets)
  "Return non-nil when SESSION's project is one of TARGETS."
  (let ((project (plist-get (cdr session) :project)))
    (and (stringp project)
         (not (string-empty-p project))
         (member (directory-file-name (expand-file-name project))
                 targets))))

(defun agent-log-codex--nearest-session-by-timestamp
    (sessions target-timestamp-ms)
  "Return the session in SESSIONS launched nearest TARGET-TIMESTAMP-MS."
  (car
   (sort
    (cl-remove-if-not
     (lambda (session)
       (agent-log-codex--timestamp-near-p
        (plist-get (cdr session) :timestamp) target-timestamp-ms))
     sessions)
    (lambda (a b)
      (< (agent-log-codex--timestamp-distance
          (plist-get (cdr a) :timestamp) target-timestamp-ms)
         (agent-log-codex--timestamp-distance
          (plist-get (cdr b) :timestamp) target-timestamp-ms))))))

(defun agent-log-codex--timestamp-near-p (timestamp target-timestamp-ms)
  "Return non-nil when TIMESTAMP is near TARGET-TIMESTAMP-MS."
  (and (numberp timestamp)
       (<= (agent-log-codex--timestamp-distance
            timestamp target-timestamp-ms)
           agent-log-codex--session-start-match-window-ms)))

(defun agent-log-codex--timestamp-distance (timestamp target-timestamp-ms)
  "Return absolute distance between TIMESTAMP and TARGET-TIMESTAMP-MS."
  (abs (- timestamp target-timestamp-ms)))

(defun agent-log-codex--visible-session-file (sessions)
  "Return the transcript matching the visible Codex buffer text in SESSIONS."
  (when-let* ((dir (codex--buffer-directory-for (current-buffer)))
              (candidates (agent-log-codex--project-sessions dir sessions))
              (snippets (agent-log-codex--visible-session-snippets)))
    (cl-loop for snippet in snippets
             thereis
             (cl-loop for session in candidates
                      for file = (plist-get (cdr session) :file)
                      when (agent-log-codex--file-contains-p file snippet)
                      return file))))

(defun agent-log-codex--project-sessions (directory sessions)
  "Return the SESSIONS whose project matches DIRECTORY."
  (let ((targets (agent-log-codex--directory-match-targets directory)))
    (cl-remove-if-not
     (lambda (session)
       (agent-log-codex--session-in-directory-p session targets))
     sessions)))

(defun agent-log-codex--visible-session-snippets ()
  "Return distinctive transcript snippets visible in the current buffer."
  (let* ((start (max (point-min) (- (point-max) 12000)))
         (text (buffer-substring-no-properties start (point-max)))
         (lines (nreverse (split-string text "\n" t))))
    (seq-take
     (cl-remove-if-not
      #'agent-log-codex--visible-snippet-line-p
      (mapcar #'agent-log-codex--normalize-visible-snippet lines))
     8)))

(defun agent-log-codex--visible-snippet-line-p (line)
  "Return non-nil if LINE is useful for matching a visible transcript."
  (and (>= (length line) 40)
       (not (string-prefix-p "›" line))
       (not (string-match-p "\\`[[:space:]─]+\\'" line))
       (not (string-match-p "gpt-[0-9].*·" line))))

(defun agent-log-codex--normalize-visible-snippet (line)
  "Return a searchable transcript snippet from visible terminal LINE."
  (let ((text (string-trim line)))
    (setq text (replace-regexp-in-string "\\`[•*-][[:space:]]+" "" text))
    (setq text (replace-regexp-in-string "\\`[0-9]+[.)][[:space:]]+" "" text))
    (setq text (replace-regexp-in-string "`" "" text))
    (string-trim (replace-regexp-in-string "[[:space:]]+" " " text))))

(defun agent-log-codex--file-contains-p (file text)
  "Return non-nil if FILE contains TEXT."
  (when (and file (file-readable-p file))
    (with-temp-buffer
      (insert-file-contents file)
      (goto-char (point-min))
      (while (search-forward "`" nil t)
        (replace-match "" t t))
      (goto-char (point-min))
      (search-forward text nil t))))

(defun agent-log-codex--buffer-process-start-ms ()
  "Return the current buffer's process start time in milliseconds."
  (when-let* ((process (get-buffer-process (current-buffer)))
              (pid (process-id process))
              (attributes (process-attributes pid))
              (start (alist-get 'start attributes)))
    (round (* 1000 (float-time start)))))

(defun agent-log-codex--directory-match-targets (directory)
  "Return a deduplicated list of canonical forms of DIRECTORY for matching."
  (delete-dups
   (mapcar #'directory-file-name
           (list (expand-file-name directory)
                 (file-truename (expand-file-name directory))))))

;;;;; Codex-specific helper functions

(defun agent-log-codex--session-event-handler (message)
  "Record Codex session identity from hook MESSAGE.
Always return nil so other `codex-event-hook' handlers still run."
  (when-let* ((sid (agent-log-codex--session-id-from-hook-message message))
              (buffer (get-buffer (plist-get message :buffer-name))))
    (with-current-buffer buffer
      (setq-local agent-log-codex--buffer-session-id sid)
      (setq-local agent-log-codex--buffer-session-file
                  (when agent-log-codex--instance
                    (agent-log--find-session-file
                     agent-log-codex--instance sid)))))
  nil)

(defun agent-log-codex--session-id-from-hook-message (message)
  "Return the Codex session ID from hook MESSAGE."
  (let* ((json-data (plist-get message :json-data))
         (data (if (stringp json-data)
                   (agent-log--try-parse-json json-data)
                 json-data))
         (sid (or (plist-get data :session_id)
                  (plist-get data :sessionId))))
    (and (stringp sid)
         (string-match-p
          (concat "\\`" agent-log-codex--uuid-regexp "\\'")
          sid)
         sid)))

(defun agent-log-codex--clear-buffer-session ()
  "Clear recorded Codex session identity in the current buffer."
  (setq-local agent-log-codex--buffer-session-id nil)
  (setq-local agent-log-codex--buffer-session-file nil))

(defun agent-log-codex--install-hooks (&optional session-end)
  "Install Agent Log hooks for Codex.
When SESSION-END is non-nil, also install the Stop-event handler
that runs automatic sync and summary actions.  The session identity
handler and start cleanup hook are installed unconditionally because
they are needed to resolve the current Codex buffer to its transcript."
  (add-hook 'codex-event-hook #'agent-log-codex--session-event-handler)
  (if session-end
      (add-hook 'codex-event-hook #'agent-log-codex--session-end-handler)
    (remove-hook 'codex-event-hook #'agent-log-codex--session-end-handler))
  (add-hook 'codex-start-hook #'agent-log-codex--clear-buffer-session))

(defun agent-log-codex--ensure-hooks (&rest _)
  "Reinstall Agent Log's Codex hooks if another package reset them."
  (agent-log-codex--install-hooks
   (agent-log--session-end-hook-needed-p)))

(defun agent-log-codex--install-dispatch-advice ()
  "Ensure Agent Log hooks are present before Codex dispatches an event."
  (when (fboundp 'codex-handle-hook)
    (advice-add 'codex-handle-hook
                :before #'agent-log-codex--ensure-hooks)))

;;;;; Icon

(defconst agent-log-codex--icon-svg
  "<svg fill=\"currentColor\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z\"/></svg>"
  "SVG source for the Codex icon (OpenAI knot).
Source: SVG Repo (CC0).")

;;;;; Backend registration

(defvar agent-log-codex--instance
  (agent-log--make-codex
   :name "Codex"
   :key 'codex
   :directory "~/.codex"
   :rendered-directory "~/.codex/rendered"
   :icon-svg agent-log-codex--icon-svg
   :icon-fallback "CX"))

(agent-log--register-backend 'codex agent-log-codex--instance)

(agent-log-codex--install-hooks
 (agent-log--session-end-hook-needed-p))
(agent-log-codex--install-dispatch-advice)
(with-eval-after-load 'codex
  (agent-log-codex--install-dispatch-advice))

(provide 'agent-log-codex)
;;; agent-log-codex.el ends here
