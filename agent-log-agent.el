;;; agent-log-agent.el --- Bridge to the agent live-session package -*- lexical-binding: t -*-

;; Author: Pablo Stafforini
;; Maintainer: Pablo Stafforini

;; This file is not part of GNU Emacs

;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation, either version 3 of the
;; License, or (at your option) any later version.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Optional integration between Agent Log, which owns the durable
;; session archive, and the `agent' package, which owns live session
;; control.  Loaded from agent-log.el only when the `agent' feature is
;; present, so neither package requires the other.  Every Agent Log
;; reference to `agent' lives here, and only public `agent' API is
;; used: `agent-session', `agent-session-id', `agent-session-backend',
;; `agent-session-buffers', `agent-session-display-state',
;; `agent-backend', `agent-session-create', `agent-start-session', and
;; the `agent-session-annotation-function' rendering hook.  That hook
;; holds one function rather than a list, and loading this file claims
;; it outright, so the last integration loaded is the one that
;; annotates the switcher.  Agent Log backend keys equal agent backend
;; symbols, so no mapping is needed.

;;; Code:

(require 'cl-lib)
(require 'agent-log)
(require 'agent)

(declare-function agent-log-claude--session-project-directory
                  "agent-log-claude" (session-id))
(declare-function agent-log-codex--prepare-resume
                  "agent-log-codex" (backend session-id))

;;;; Live-session identity

(defun agent-log-agent--session-info (backend-key session-id)
  "Return live info for SESSION-ID under BACKEND-KEY, or nil.
The result is a plist (:buffer BUFFER :state STATE) built from the
agent package's authoritative session identity and display state."
  (cl-loop for buffer in (agent-session-buffers)
           for session = (agent-session buffer)
           when (and session
                     (eq (agent-session-backend session) backend-key)
                     (equal (agent-session-id session) session-id))
           return (list :buffer buffer
                        :state (agent-session-display-state buffer))))

(defun agent-log-agent--session-info-table ()
  "Return an equal-tested table describing every live agent session."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (buffer (agent-session-buffers) table)
      (when-let* ((session (agent-session buffer))
                  (backend-key (agent-session-backend session))
                  (session-id (agent-session-id session)))
        (puthash (cons backend-key session-id)
                 (list :buffer buffer
                       :state (agent-session-display-state buffer))
                 table)))))

(setq agent-log-live-session-info-function #'agent-log-agent--session-info
      agent-log-live-session-info-table-function
      #'agent-log-agent--session-info-table)

;;;; Switcher annotations

(defun agent-log-agent--session-annotation (buffer)
  "Return the stored one-line summary of BUFFER's session, or nil.
Live sessions are summarized by the background sweep, which does not
know they are live, so the text can lag the conversation by hours.  A
session too new to have been summarized has no annotation at all."
  (when-let* ((session (agent-session buffer))
              (session-id (agent-session-id session)))
    (agent-log-session-oneline session-id)))

(setq agent-session-annotation-function
      #'agent-log-agent--session-annotation)

(defvar agent-log-agent--oneline-refresh-timer nil
  "Idle timer refreshing the session one-line summary cache.")

;; Declared here because the two functions below read the option while
;; the `defcustom' that defines it comes after them, and they have to:
;; its `:set' runs when the option is declared, so the function it
;; calls must already exist.  Without this declaration those reads are
;; free variable references, which `byte-compile-error-on-warn' turns
;; into a build failure.
(defvar agent-log-oneline-refresh-idle-delay)

(defun agent-log-agent--oneline-refresh-enabled-p ()
  "Return non-nil when the one-line cache should be refreshed on idle."
  (and (numberp agent-log-oneline-refresh-idle-delay)
       (> agent-log-oneline-refresh-idle-delay 0)))

(defun agent-log-agent--update-oneline-refresh-timer (&rest _)
  "Install or cancel the session one-line cache refresh timer."
  (when (timerp agent-log-agent--oneline-refresh-timer)
    (cancel-timer agent-log-agent--oneline-refresh-timer))
  (setq agent-log-agent--oneline-refresh-timer nil)
  (when (agent-log-agent--oneline-refresh-enabled-p)
    (setq agent-log-agent--oneline-refresh-timer
          (run-with-idle-timer agent-log-oneline-refresh-idle-delay t
                               #'agent-log-refresh-session-onelines))))

(defcustom agent-log-oneline-refresh-idle-delay 5
  "Seconds of idleness before refreshing the session one-line cache.
The session switcher reads that cache, so it never waits on the index
file.  A firing whose index is unchanged costs one `file-attributes'
call; a firing whose index has changed rereads and reparses the whole
index, which takes roughly 90 ms on a 6 MB archive.  A shorter delay
therefore pays that reparse sooner after each write, and a longer one
keeps a summary written moments ago out of the switcher for longer.

Set this option to nil, or to a number that is not positive, to stop
refreshing on idle; the switcher then shows whatever the cache last
held."
  :type '(choice (const :tag "Disable idle refresh" nil)
                 (number :tag "Seconds"))
  :group 'agent-log
  ;; This `:set' is also what installs the timer at load, so no
  ;; separate installation call follows: declaring an option runs its
  ;; `:set', with the value the user's init already gave it when there
  ;; is one, and reloading this file runs it again, cancelling the
  ;; previous timer first.
  :set (lambda (sym val)
         (set-default sym val)
         (agent-log-agent--update-oneline-refresh-timer)))

(cl-defmethod agent-log--current-buffer-session-file :around
  ((backend agent-log-backend))
  "Resolve the transcript from the agent-recorded native session id.
Fall back to BACKEND's own heuristics when the current buffer is not an
agent session, its id is not yet known, or the id's transcript is not
on disk."
  (or (when-let* ((session (agent-session (current-buffer)))
                  (id (agent-session-id session))
                  ((eq (agent-session-backend session)
                       (agent-log-backend-key backend))))
        (agent-log--find-session-file backend id))
      (cl-call-next-method)))

(cl-defmethod agent-log--active-session-ids :around
  ((backend agent-log-backend) &optional _sessions)
  "Report live session ids from the agent package's registry.
Agent tracks every live buffer of the backends it registers, so its
answer replaces BACKEND's standalone heuristics whenever agent
registers the same backend key; ids agent has not learned yet are
simply absent until the backend reports them."
  (let ((key (agent-log-backend-key backend)))
    (if (agent-backend key)
        (delete-dups
         (cl-loop for buffer in (agent-session-buffers)
                  for session = (agent-session buffer)
                  when (and session
                            (eq (agent-session-backend session) key)
                            (agent-session-id session))
                  collect (agent-session-id session)))
      (cl-call-next-method))))

;;;; Resume routing

(with-eval-after-load 'agent-log-claude
  (cl-defmethod agent-log--resume-session :around
    ((_backend agent-log-claude) session-id)
    "Prefer the live buffer, then the agent dispatcher, then the direct path."
    (cond
     ((agent-log-agent--switch-to-live 'claude-code session-id))
     ((agent-backend 'claude-code)
      (agent-log-agent--resume
       'claude-code
       (agent-log-claude--session-project-directory session-id)
       session-id))
     (t (cl-call-next-method)))))

(with-eval-after-load 'agent-log-codex
  (cl-defmethod agent-log--resume-session :around
    ((backend agent-log-codex) session-id)
    "Prefer the live buffer, then the agent dispatcher, then the direct path.
The catalog validation, transcript caching, and app-server exact-path
registration from `agent-log-codex--prepare-resume' apply on the agent
path too, because `codex-start-session' reaches the same resume entry
point the exact-path advice covers."
    (cond
     ((agent-log-agent--switch-to-live 'codex session-id))
     ((agent-backend 'codex)
      (agent-log-agent--resume
       'codex
       (agent-log-codex--prepare-resume backend session-id)
       session-id))
     (t (cl-call-next-method)))))

(defun agent-log-agent--switch-to-live (backend-key session-id)
  "Switch to SESSION-ID's live buffer; return non-nil when it was live.
BACKEND-KEY names the backend whose live sessions are searched.  This
is the duplicate guard: resuming a session that already has a live
buffer would start a second process on the same conversation."
  (when-let* ((live (agent-log-agent--session-info backend-key session-id))
              (buffer (plist-get live :buffer)))
    (pop-to-buffer buffer)
    (message "Session %s is already live (%s); switched to its buffer"
             session-id (plist-get live :state))
    t))

(defun agent-log-agent--resume (backend-key directory session-id)
  "Resume SESSION-ID through `agent-start-session'.
BACKEND-KEY names the agent backend and DIRECTORY the project
directory, or nil for the backend's ambient default.  Routing through
the agent dispatcher preserves account handling, lifecycle
registration, teardown, and state tracking for the resumed session."
  (agent-start-session
   (agent-session-create
    :backend backend-key
    :directory (and directory
                    (file-name-as-directory
                     (abbreviate-file-name directory))))
   :resume-id session-id))

(provide 'agent-log-agent)
;;; agent-log-agent.el ends here
