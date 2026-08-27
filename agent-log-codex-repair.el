;;; agent-log-codex-repair.el --- Detached Codex catalog repair  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Pablo Stafforini

;; This file is not part of GNU Emacs.

;;; Commentary:

;; This small batch-Emacs helper performs Codex's app-server handshake and
;; rollout repair outside the interactive Emacs process.  Its caller redirects
;; all output and imposes an operating-system timeout.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'seq)
(require 'subr-x)

(defconst agent-log-codex-repair--request-timeout 110
  "Seconds to wait for one app-server response.")

(defconst agent-log-codex-repair--page-size 1000
  "Number of Codex threads requested per catalog page.")

(defun agent-log-codex-repair--filter (process output)
  "Decode newline-delimited app-server OUTPUT from PROCESS."
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
                    (list (json-parse-string
                           line :object-type 'alist :array-type 'list
                           :null-object nil :false-object nil))))
          (error
           (process-put process 'protocol-error
                        (error-message-string err))))))
    (process-put process 'pending-output pending)))

(defun agent-log-codex-repair--request (process id method params)
  "Send METHOD with PARAMS and ID to PROCESS, returning its result."
  (process-send-string
   process
   (concat (json-encode `((id . ,id) (method . ,method) (params . ,params)))
           "\n"))
  (let ((deadline (+ (float-time) agent-log-codex-repair--request-timeout))
        response)
    (while (and (not response) (process-live-p process)
                (< (float-time) deadline))
      (setq response
            (seq-find (lambda (message) (equal (alist-get 'id message) id))
                      (process-get process 'messages)))
      (unless response
        (accept-process-output process 0.05)))
    (when-let* ((protocol-error (process-get process 'protocol-error)))
      (error "Codex app-server returned malformed data: %s" protocol-error))
    (unless response
      (error "Codex app-server did not answer %s" method))
    (when-let* ((rpc-error (alist-get 'error response)))
      (error "Codex %s failed: %s"
             method (or (alist-get 'message rpc-error) rpc-error)))
    (alist-get 'result response)))

(defun agent-log-codex-repair--notify-initialized (process)
  "Tell PROCESS that the app-server handshake is complete."
  (process-send-string
   process
   (concat (json-encode
            '((method . "initialized") (params . #s(hash-table))))
           "\n")))

(defun agent-log-codex-repair--thread-list (process)
  "Return the repaired, fully paginated thread catalog from PROCESS."
  ;; Pay for archive scanning once, then paginate the repaired state DB.
  (agent-log-codex-repair--request
   process 2 "thread/list"
   '((limit . 1)
     (sortKey . "updated_at")
     (sortDirection . "desc")
     (useStateDbOnly . :json-false)))
  (let ((request-id 2)
        (seen-ids (make-hash-table :test #'equal))
        (seen-cursors (make-hash-table :test #'equal))
        cursor
        threads
        done)
    (while (not done)
      (let* ((result
              (agent-log-codex-repair--request
               process (cl-incf request-id) "thread/list"
               `((limit . ,agent-log-codex-repair--page-size)
                 (sortKey . "updated_at")
                 (sortDirection . "desc")
                 (useStateDbOnly . t)
                 ,@(when cursor `((cursor . ,cursor))))))
             (page (append (alist-get 'data result) nil))
             (next-cursor (alist-get 'nextCursor result)))
        (dolist (thread page)
          (let ((id (alist-get 'id thread)))
            (unless (and (stringp id) (gethash id seen-ids))
              (when (stringp id)
                (puthash id t seen-ids))
              (setq threads (nconc threads (list thread))))))
        (cond
         ((not (stringp next-cursor))
          (setq done t))
         ((gethash next-cursor seen-cursors)
          (error "Codex thread catalog repeated cursor %s" next-cursor))
         (t
          (puthash next-cursor t seen-cursors)
          (setq cursor next-cursor)))))
    threads))

(defun agent-log-codex-repair--validate-catalog (threads)
  "Reject THREADS unless they contain the rollout that triggered repair."
  (when-let* ((expected (getenv "AGENT_LOG_EXPECTED_ROLLOUT"))
              ((not (string-empty-p expected)))
              ((not (seq-some
                     (lambda (thread) (equal (alist-get 'id thread) expected))
                     threads))))
    (error "Repaired Codex catalog omits expected rollout %s" expected))
  threads)

(defun agent-log-codex-repair--write-cache (threads)
  "Atomically write THREADS to `AGENT_LOG_CODEX_CACHE'."
  (let* ((cache (or (getenv "AGENT_LOG_CODEX_CACHE")
                    (error "AGENT_LOG_CODEX_CACHE is unset")))
         (directory (file-name-directory cache))
         temporary)
    (make-directory directory t)
    (setq temporary (make-temp-file (expand-file-name ".catalog-" directory)))
    (unwind-protect
        (progn
          (let ((coding-system-for-write 'utf-8-unix))
            (with-temp-file temporary
              (insert (json-encode `((version . 1) (threads . ,threads))))
              (insert "\n")))
          (rename-file temporary cache t)
          (setq temporary nil))
      (when (and temporary (file-exists-p temporary))
        (delete-file temporary)))))

(defun agent-log-codex-repair-run ()
  "Repair the catalog under `CODEX_HOME', then exit.
This entry point is intended for a separate batch Emacs process."
  (let* ((codex-program (or (getenv "AGENT_LOG_CODEX_PROGRAM") "codex"))
         (stderr-buffer (generate-new-buffer " *agent-log-codex-repair-stderr*"))
         (process
          (make-process
           :name "agent-log-codex-repair-app-server"
           :command (list codex-program "app-server" "--stdio")
           :connection-type 'pipe
           :coding 'utf-8-unix
           :stderr stderr-buffer
           :noquery t
           :filter #'agent-log-codex-repair--filter)))
    (unwind-protect
        (progn
          (agent-log-codex-repair--request
           process 1 "initialize"
           '((clientInfo
              (name . "agent-log")
              (title . "Agent Log")
              (version . "0.4.0"))))
          (agent-log-codex-repair--notify-initialized process)
          (agent-log-codex-repair--write-cache
           (agent-log-codex-repair--validate-catalog
            (agent-log-codex-repair--thread-list process))))
      (when (process-live-p process)
        (delete-process process))
      (when (buffer-live-p (process-buffer process))
        (kill-buffer (process-buffer process)))
      (when (buffer-live-p stderr-buffer)
        (kill-buffer stderr-buffer)))))

(provide 'agent-log-codex-repair)
;;; agent-log-codex-repair.el ends here
