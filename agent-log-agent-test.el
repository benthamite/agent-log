;;; agent-log-agent-test.el --- Tests for the agent bridge  -*- lexical-binding: t; -*-

;; Tests for agent-log-agent.el, the optional bridge to the `agent'
;; package.  They live apart from agent-log-test.el so that the main
;; suite stays loadable without `agent' installed; `make test-bridge'
;; runs this file, and only this file requires `agent'.

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'agent)
(require 'agent-log)
(require 'agent-log-agent)

;;;;; Test helpers

(defmacro agent-log-agent-test--with-session (session &rest body)
  "Execute BODY with `agent-session' returning SESSION for any buffer.
Binding the accessor rather than building a live session buffer keeps
these tests independent of how `agent' decides a buffer is a session."
  (declare (indent 1) (debug t))
  `(cl-letf (((symbol-function 'agent-session) (lambda (&optional _buffer)
                                                 ,session)))
     ,@body))

(defmacro agent-log-agent-test--with-onelines (entries &rest body)
  "Execute BODY with ENTRIES as the one-line summary cache.
ENTRIES is an alist of (SESSION-ID . ONELINE)."
  (declare (indent 1) (debug t))
  `(let ((agent-log--session-oneline-cache (make-hash-table :test #'equal)))
     (dolist (entry ,entries)
       (puthash (car entry) (cdr entry) agent-log--session-oneline-cache))
     ,@body))

;;;;; Switcher annotations

(ert-deftest agent-log-agent-test-annotation/returns-stored-summary ()
  "Annotate a live session with the summary stored under its id."
  (agent-log-agent-test--with-onelines '(("s1" . "Fix the parser"))
    (agent-log-agent-test--with-session (agent-session-create
                                         :backend 'claude-code :id "s1")
      (should (equal (agent-log-agent--session-annotation (current-buffer))
                     "Fix the parser")))))

(ert-deftest agent-log-agent-test-annotation/no-session-is-nil ()
  "Return nil for a buffer that is not an agent session."
  (agent-log-agent-test--with-onelines '(("s1" . "Fix the parser"))
    (agent-log-agent-test--with-session nil
      (should-not (agent-log-agent--session-annotation (current-buffer))))))

(ert-deftest agent-log-agent-test-annotation/no-session-id-is-nil ()
  "Return nil for a session whose id `agent' has not learned yet.
A session buffer exists from the moment the process starts, but its id
arrives later, so this is the ordinary state of a new session rather
than an error."
  (agent-log-agent-test--with-onelines '(("s1" . "Fix the parser"))
    (agent-log-agent-test--with-session (agent-session-create
                                         :backend 'claude-code :id nil)
      (should-not (agent-log-agent--session-annotation (current-buffer))))))

(ert-deftest agent-log-agent-test-annotation/unsummarized-session-is-nil ()
  "Return nil for a live session the archive has not summarized."
  (agent-log-agent-test--with-onelines '(("s1" . "Fix the parser"))
    (agent-log-agent-test--with-session (agent-session-create
                                         :backend 'claude-code :id "s2")
      (should-not (agent-log-agent--session-annotation (current-buffer))))))

(ert-deftest agent-log-agent-test-annotation/is-installed ()
  "Install the annotation provider into the rendering hook of `agent'."
  (should (eq agent-session-annotation-function
              #'agent-log-agent--session-annotation)))

(provide 'agent-log-agent-test)
;;; agent-log-agent-test.el ends here
