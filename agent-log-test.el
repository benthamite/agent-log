;;; agent-log-test.el --- Tests for agent-log  -*- lexical-binding: t; -*-

;; Tests for agent-log.el: JSONL parsing, rendering, index management,
;; tool summarization, UTF-8 handling, timestamps, and session metadata.

;;; Code:

(require 'ert)
(require 'agent-log)
(require 'agent-log-claude)
(require 'agent-log-codex)
(require 'agent-log-redact)

;;;;; Test helpers

(defvar agent-log-test--claude-backend agent-log-claude--instance
  "Claude backend instance for use in tests.")

(defvar agent-log-test--dir nil
  "Temporary directory for the current test.")

(defmacro agent-log-test--with-temp-dir (&rest body)
  "Execute BODY with a temporary directory bound to `agent-log-test--dir'.
Cleans up afterwards."
  (declare (indent 0) (debug t))
  `(let ((agent-log-test--dir (make-temp-file "agent-log-test-" t)))
     (unwind-protect
         (progn ,@body)
       (delete-directory agent-log-test--dir t))))

(defun agent-log-test--write-file (name content)
  "Write CONTENT to file NAME under `agent-log-test--dir'."
  (let ((path (expand-file-name name agent-log-test--dir)))
    (make-directory (file-name-directory path) t)
    (with-temp-file path
      (insert content))
    path))

(defun agent-log-test--make-entry (type role content &optional timestamp)
  "Build a conversation entry plist.
TYPE is \"user\" or \"assistant\", ROLE matches, CONTENT is
the message content (string or list)."
  (let ((entry (list :type type
                     :message (list :role role :content content))))
    (when timestamp
      (plist-put entry :timestamp timestamp))
    entry))

(defun agent-log-test--user-entry (content &optional timestamp)
  "Build a user conversation entry with CONTENT."
  (agent-log-test--make-entry "user" "user" content timestamp))

(defun agent-log-test--assistant-entry (content &optional timestamp)
  "Build an assistant conversation entry with CONTENT."
  (agent-log-test--make-entry "assistant" "assistant" content timestamp))

(defun agent-log-test--summary-entry (metadata oneline &optional summary)
  "Return a current summary index entry for METADATA and ONELINE.
SUMMARY defaults to ONELINE."
  (pcase-let ((`(,size . ,mtime) (agent-log--session-jsonl-state metadata)))
    (list :summary (or summary oneline)
          :summary-oneline oneline
          :summary-conversation-hash
          (agent-log--session-conversation-hash metadata)
          :summary-jsonl-size size
          :summary-jsonl-mtime mtime)))

(defun agent-log-test--legacy-summary-entry (metadata oneline &optional summary)
  "Return a v1 summary index entry for METADATA and ONELINE.
SUMMARY defaults to ONELINE."
  (let* ((backend (plist-get metadata :backend))
         (file (plist-get metadata :file))
         (text (agent-log--conversation-text-from-file file backend)))
    (list :summary (or summary oneline)
          :summary-oneline oneline
          :summary-conversation-hash
          (agent-log--conversation-text-hash-with-version text 1))))

;;;;; JSONL parsing

(ert-deftest agent-log-test-parse-json-line/simple-object ()
  "Parses a simple JSON object into a plist."
  (let ((result (agent-log--parse-json-line "{\"type\":\"user\",\"id\":1}")))
    (should (equal (plist-get result :type) "user"))
    (should (equal (plist-get result :id) 1))))

(ert-deftest agent-log-test-parse-json-line/nested-object ()
  "Parses nested JSON into nested plists."
  (let ((result (agent-log--parse-json-line
                 "{\"message\":{\"role\":\"user\",\"content\":\"hello\"}}")))
    (should (equal (plist-get (plist-get result :message) :role) "user"))
    (should (equal (plist-get (plist-get result :message) :content) "hello"))))

(ert-deftest agent-log-test-parse-json-line/array ()
  "Parses JSON arrays as lists."
  (let ((result (agent-log--parse-json-line "{\"items\":[1,2,3]}")))
    (should (equal (plist-get result :items) '(1 2 3)))))

(ert-deftest agent-log-test-parse-json-line/invalid-json ()
  "Signals an error for invalid JSON."
  (should-error (agent-log--parse-json-line "not json")))

(ert-deftest agent-log-test-parse-json-line/empty-string ()
  "Signals an error for empty string."
  (should-error (agent-log--parse-json-line "")))

(ert-deftest agent-log-test-parse-json-line/unicode ()
  "Handles Unicode characters in JSON."
  (let ((result (agent-log--parse-json-line "{\"text\":\"café ☕ 日本語\"}")))
    (should (equal (plist-get result :text) "café ☕ 日本語"))))

(ert-deftest agent-log-test-read-file-lines/normal ()
  "Reads non-empty lines from a file."
  (agent-log-test--with-temp-dir
    (let ((path (agent-log-test--write-file "test.jsonl"
                                              "line1\nline2\nline3\n")))
      (should (equal (agent-log--read-file-lines path)
                     '("line1" "line2" "line3"))))))

(ert-deftest agent-log-test-read-file-lines/empty-lines-skipped ()
  "Empty lines between content are skipped."
  (agent-log-test--with-temp-dir
    (let ((path (agent-log-test--write-file "test.jsonl"
                                              "line1\n\nline2\n")))
      (should (equal (agent-log--read-file-lines path)
                     '("line1" "line2"))))))

(ert-deftest agent-log-test-parse-jsonl-file/valid-entries ()
  "Parses multiple valid JSONL entries."
  (agent-log-test--with-temp-dir
    (let* ((content (concat "{\"type\":\"user\"}\n"
                            "{\"type\":\"assistant\"}\n"))
           (path (agent-log-test--write-file "test.jsonl" content))
           (result (agent-log--parse-jsonl-file path)))
      (should (= (length result) 2))
      (should (equal (plist-get (car result) :type) "user"))
      (should (equal (plist-get (cadr result) :type) "assistant")))))

(ert-deftest agent-log-test-parse-jsonl-file/malformed-lines-skipped ()
  "Malformed JSON lines are silently skipped."
  (agent-log-test--with-temp-dir
    (let* ((content (concat "{\"type\":\"user\"}\n"
                            "NOT VALID JSON\n"
                            "{\"type\":\"assistant\"}\n"))
           (path (agent-log-test--write-file "test.jsonl" content))
           (result (agent-log--parse-jsonl-file path)))
      (should (= (length result) 2)))))

(ert-deftest agent-log-test-parse-jsonl-file/all-malformed ()
  "Returns empty list when all lines are malformed."
  (agent-log-test--with-temp-dir
    (let* ((path (agent-log-test--write-file "test.jsonl"
                                              "bad\nalso bad\n"))
           (result (agent-log--parse-jsonl-file path)))
      (should (null result)))))

(ert-deftest agent-log-test-try-parse-json/valid ()
  "Returns parsed result for valid JSON."
  (should (equal (plist-get (agent-log--try-parse-json "{\"a\":1}") :a) 1)))

(ert-deftest agent-log-test-try-parse-json/invalid ()
  "Returns nil for invalid JSON."
  (should (null (agent-log--try-parse-json "invalid"))))

;;;;; Entry classification

(ert-deftest agent-log-test-conversation-entry-p/user ()
  "Recognizes user entries."
  (let ((entry (list :type "user" :message (list :content "hello"))))
    (should (agent-log--conversation-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-conversation-entry-p/assistant ()
  "Recognizes assistant entries."
  (let ((entry (list :type "assistant" :message (list :content "hi"))))
    (should (agent-log--conversation-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-conversation-entry-p/progress-excluded ()
  "Excludes progress entries."
  (let ((entry (list :type "progress")))
    (should-not (agent-log--conversation-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-conversation-entry-p/system-entry-excluded ()
  "Excludes system-generated user entries."
  (let ((entry (list :type "user"
                     :message (list :content "<command-name>/commit</command-name>"))))
    (should-not (agent-log--conversation-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/command-name ()
  "Detects <command-name> system tag."
  (let ((entry (list :message (list :content "<command-name>/commit</command-name>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/task-notification ()
  "Detects <task-notification> system tag."
  (let ((entry (list :message (list :content "<task-notification>done</task-notification>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/teammate-message ()
  "Detects <teammate-message> system tag."
  (let ((entry (list :message (list :content "<teammate-message from=\"agent\">hi</teammate-message>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/local-command-stdout ()
  "Detects <local-command-stdout> system tag."
  (let ((entry (list :message (list :content "<local-command-stdout>output</local-command-stdout>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/normal-user-message ()
  "Does not flag normal user messages as system."
  (let ((entry (list :message (list :content "Fix the bug in main.py"))))
    (should-not (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/non-string-content ()
  "Does not flag entries with non-string content as system."
  (let ((entry (list :message (list :content '((:type "text" :text "hello"))))))
    (should-not (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/leading-whitespace ()
  "Detects system tags with leading whitespace."
  (let ((entry (list :message (list :content "  <command-name>/foo</command-name>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-system-entry-p/tag-with-space-after ()
  "Detects system tags that have a space after the tag name (e.g. attributes)."
  (let ((entry (list :message (list :content "<command-message type=\"info\">hello</command-message>"))))
    (should (agent-log--system-entry-p agent-log-test--claude-backend entry))))

(ert-deftest agent-log-test-filter-conversation/mixed-entries ()
  "Filters to only user and assistant entries, excluding system entries."
  (let* ((entries (list (list :type "progress" :cwd "/tmp")
                        (list :type "user" :message (list :content "hello"))
                        (list :type "user" :message (list :content "<command-name>/foo</command-name>"))
                        (list :type "assistant" :message (list :content "hi"))
                        (list :type "result")))
         (filtered (agent-log--filter-conversation agent-log-test--claude-backend entries)))
    (should (= (length filtered) 2))
    (should (equal (plist-get (car filtered) :type) "user"))
    (should (equal (plist-get (cadr filtered) :type) "assistant"))))

;;;;; Entry helpers

(ert-deftest agent-log-test-find-first-message/user-first ()
  "Finds the first user message."
  (let* ((entries (list (list :type "progress" :cwd "/tmp")
                        (list :type "user" :message (list :role "user"))
                        (list :type "assistant" :message (list :role "assistant"))))
         (result (agent-log--find-first-message entries)))
    (should (equal (plist-get result :type) "user"))))

(ert-deftest agent-log-test-find-first-message/assistant-first ()
  "Finds assistant entry when no user entry precedes it."
  (let* ((entries (list (list :type "progress")
                        (list :type "assistant" :message (list :role "assistant"))))
         (result (agent-log--find-first-message entries)))
    (should (equal (plist-get result :type) "assistant"))))

(ert-deftest agent-log-test-find-first-message/empty ()
  "Returns nil for empty entries."
  (should (null (agent-log--find-first-message nil))))

(ert-deftest agent-log-test-find-progress-entry/found ()
  "Finds progress entry."
  (let* ((entries (list (list :type "user")
                        (list :type "progress" :cwd "/home/user")))
         (result (agent-log--find-progress-entry entries)))
    (should (equal (plist-get result :cwd) "/home/user"))))

(ert-deftest agent-log-test-find-progress-entry/not-found ()
  "Returns nil when no progress entry exists."
  (let ((entries (list (list :type "user"))))
    (should (null (agent-log--find-progress-entry entries)))))

(ert-deftest agent-log-test-find-session-timestamp/first-message ()
  "Uses the first conversation timestamp when present."
  (let ((entries (list (list :type "progress"
                             :timestamp "2023-11-14T11:00:00Z")
                       (list :type "user"
                             :timestamp "2023-11-14T12:00:00Z"))))
    (should (equal (agent-log--find-session-timestamp entries)
                   "2023-11-14T12:00:00Z"))))

(ert-deftest agent-log-test-find-session-timestamp/progress-fallback ()
  "Falls back to the progress timestamp before conversation starts."
  (let ((entries (list (list :type "progress"
                             :timestamp "2023-11-14T11:00:00Z"))))
    (should (equal (agent-log--find-session-timestamp entries)
                   "2023-11-14T11:00:00Z"))))

(ert-deftest agent-log-test-first-user-text/string-content ()
  "Extracts text from string content."
  (let ((entries (list (list :type "user"
                             :message (list :content "Fix the bug")))))
    (should (equal (agent-log--first-user-text agent-log-test--claude-backend entries) "Fix the bug"))))

(ert-deftest agent-log-test-first-user-text/list-content ()
  "Extracts text from list content."
  (let ((entries (list (list :type "user"
                             :message (list :content
                                            (list (list :type "text"
                                                        :text "Hello world")))))))
    (should (equal (agent-log--first-user-text agent-log-test--claude-backend entries) "Hello world"))))

(ert-deftest agent-log-test-first-user-text/skips-system-entries ()
  "Skips system entries to find first genuine user text."
  (let ((entries (list (list :type "user"
                             :message (list :content "<command-name>/foo</command-name>"))
                       (list :type "user"
                             :message (list :content "Real question")))))
    (should (equal (agent-log--first-user-text agent-log-test--claude-backend entries) "Real question"))))

(ert-deftest agent-log-test-first-user-text/no-user-entries ()
  "Returns nil when no user entries exist."
  (let ((entries (list (list :type "assistant"
                             :message (list :content "response")))))
    (should (null (agent-log--first-user-text agent-log-test--claude-backend entries)))))

(ert-deftest agent-log-test-first-user-text/mixed-content-types ()
  "Finds text in content that mixes tool_result and text items."
  (let ((entries (list (list :type "user"
                             :message (list :content
                                            (list (list :type "tool_result"
                                                        :content "result")
                                                  (list :type "text"
                                                        :text "My question")))))))
    (should (equal (agent-log--first-user-text agent-log-test--claude-backend entries) "My question"))))

;;;;; Slugification

(ert-deftest agent-log-test-slugify/normal-text ()
  "Converts normal text to a slug."
  (should (equal (agent-log--slugify "Fix the bug in main.py")
                 "fix-the-bug-in-main-py")))

(ert-deftest agent-log-test-slugify/special-characters ()
  "Replaces special characters with hyphens."
  (should (equal (agent-log--slugify "Hello, World! @#$%")
                 "hello-world")))

(ert-deftest agent-log-test-slugify/consecutive-specials ()
  "Collapses consecutive special characters into single hyphen."
  (should (equal (agent-log--slugify "a---b___c")
                 "a-b-c")))

(ert-deftest agent-log-test-slugify/empty-string ()
  "Returns \"untitled\" for empty string."
  (should (equal (agent-log--slugify "") "untitled")))

(ert-deftest agent-log-test-slugify/nil-input ()
  "Returns \"untitled\" for nil."
  (should (equal (agent-log--slugify nil) "untitled")))

(ert-deftest agent-log-test-slugify/all-special-chars ()
  "Returns \"untitled\" when all chars are special."
  (should (equal (agent-log--slugify "!!!@@@###") "untitled")))

(ert-deftest agent-log-test-slugify/truncation ()
  "Truncates to `agent-log-slug-max-length'."
  (let ((agent-log-slug-max-length 10))
    (should (equal (agent-log--slugify "this is a very long text that should be truncated")
                   "this-is-a-"))))

(ert-deftest agent-log-test-slugify/unicode ()
  "Converts non-ASCII characters to hyphens."
  (should (equal (agent-log--slugify "café résumé")
                 "caf-r-sum")))

(ert-deftest agent-log-test-slugify/leading-trailing-specials ()
  "Strips leading and trailing hyphens."
  (should (equal (agent-log--slugify "  --hello--  ") "hello")))

(ert-deftest agent-log-test-slugify/numbers-preserved ()
  "Preserves numbers in slugs."
  (should (equal (agent-log--slugify "version 2.0.1") "version-2-0-1")))

;;;;; String utilities

(ert-deftest agent-log-test-truncate-string/short-string ()
  "Returns short strings unchanged."
  (should (equal (agent-log--truncate-string "hello" 10) "hello")))

(ert-deftest agent-log-test-truncate-string/exact-length ()
  "Returns string unchanged when exactly at max."
  (should (equal (agent-log--truncate-string "hello" 5) "hello")))

(ert-deftest agent-log-test-truncate-string/long-string ()
  "Truncates long strings with ellipsis."
  (should (equal (agent-log--truncate-string "hello world" 5) "hello…")))

(ert-deftest agent-log-test-truncate-string/empty-string ()
  "Returns empty string unchanged."
  (should (equal (agent-log--truncate-string "" 10) "")))

(ert-deftest agent-log-test-normalize-whitespace/tabs-and-newlines ()
  "Collapses tabs, newlines, and multiple spaces."
  (should (equal (agent-log--normalize-whitespace "hello\n\tworld  foo")
                 "hello world foo")))

(ert-deftest agent-log-test-normalize-whitespace/nil-input ()
  "Handles nil input."
  (should (equal (agent-log--normalize-whitespace nil) "")))

(ert-deftest agent-log-test-normalize-whitespace/leading-trailing ()
  "Trims leading and trailing whitespace."
  (should (equal (agent-log--normalize-whitespace "  hello  ") "hello")))

;;;;; Timestamps

(ert-deftest agent-log-test-format-epoch-ms/valid ()
  "Formats epoch milliseconds to date string."
  (let ((result (agent-log--format-epoch-ms 1700000000000)))
    ;; Should be a date-like string.  Exact value depends on timezone.
    (should (stringp result))
    (should (string-match-p "2023-11-1[45]" result))))

(ert-deftest agent-log-test-format-epoch-ms/non-number ()
  "Returns \"unknown\" for non-numeric input."
  (should (equal (agent-log--format-epoch-ms "not a number") "unknown"))
  (should (equal (agent-log--format-epoch-ms nil) "unknown")))

(ert-deftest agent-log-test-iso-to-epoch-ms/valid ()
  "Converts ISO timestamp to epoch milliseconds."
  (let ((result (agent-log--iso-to-epoch-ms "2023-11-14T12:00:00Z")))
    (should (numberp result))
    ;; Should be approximately 1700000000000 (within a day)
    (should (< (abs (- result 1699963200000)) (* 24 60 60 1000)))))

(ert-deftest agent-log-test-iso-to-epoch-ms/invalid ()
  "Returns nil for non-string inputs."
  (should (null (agent-log--iso-to-epoch-ms 12345))))

(ert-deftest agent-log-test-format-iso-timestamp/valid ()
  "Formats a valid ISO timestamp."
  (let ((result (agent-log--format-iso-timestamp "2023-11-14T12:00:00Z")))
    (should (stringp result))
    (should (string-match-p "2023-11-14" result))))

(ert-deftest agent-log-test-format-iso-timestamp/nil ()
  "Returns \"unknown\" for nil."
  (should (equal (agent-log--format-iso-timestamp nil) "unknown")))

(ert-deftest agent-log-test-format-iso-timestamp/empty ()
  "Returns \"unknown\" for empty string."
  (should (equal (agent-log--format-iso-timestamp "") "unknown")))

(ert-deftest agent-log-test-parse-and-format-iso/valid ()
  "Parses and formats a valid ISO timestamp."
  (let ((result (agent-log--parse-and-format-iso "2023-11-14T12:00:00Z")))
    (should (string-match-p "2023" result))))

(ert-deftest agent-log-test-parse-and-format-iso/invalid-returns-formatted ()
  "Returns a formatted date even for invalid strings (date-to-time is lenient)."
  ;; date-to-time does not error on arbitrary strings in modern Emacs,
  ;; so the result is a formatted date string, not the original input.
  (let ((result (agent-log--parse-and-format-iso "garbage")))
    (should (stringp result))))

;;;;; Short project

(ert-deftest agent-log-test-short-project/full-path ()
  "Extracts basename from full path."
  (should (equal (agent-log--short-project "/home/user/projects/my-app")
                 "my-app")))

(ert-deftest agent-log-test-short-project/trailing-slash ()
  "Handles path with trailing slash."
  (should (equal (agent-log--short-project "/home/user/projects/my-app/")
                 "my-app")))

(ert-deftest agent-log-test-short-project/nil ()
  "Returns \"unknown\" for nil."
  (should (equal (agent-log--short-project nil) "unknown")))

(ert-deftest agent-log-test-short-project/empty ()
  "Returns \"unknown\" for empty string."
  (should (equal (agent-log--short-project "") "unknown")))

(ert-deftest agent-log-test-short-project/simple-name ()
  "Returns simple name as-is."
  (should (equal (agent-log--short-project "my-project") "my-project")))

(ert-deftest agent-log-test-unique-project-names/all-unique ()
  "Uses bare leaf names when every leaf is unique."
  (should (equal (agent-log--unique-project-names
                  '("/home/user/foo" "/home/user/bar"))
                 '(("/home/user/foo" . "foo")
                   ("/home/user/bar" . "bar")))))

(ert-deftest agent-log-test-unique-project-names/one-collision ()
  "Adds one ancestor when leaf names collide."
  (should (equal (agent-log--unique-project-names
                  '("/a/sources/codex" "/a/dotfiles/codex"))
                 '(("/a/sources/codex" . "sources/codex")
                   ("/a/dotfiles/codex" . "dotfiles/codex")))))

(ert-deftest agent-log-test-unique-project-names/deep-collision ()
  "Grows past a shared ancestor until each suffix is unique."
  (should (equal (agent-log--unique-project-names
                  '("/p/8.1.0-dev/elpaca/sources/codex"
                    "/p/8.3.0-dev/elpaca/sources/codex"))
                 '(("/p/8.1.0-dev/elpaca/sources/codex"
                    . "8.1.0-dev/elpaca/sources/codex")
                   ("/p/8.3.0-dev/elpaca/sources/codex"
                    . "8.3.0-dev/elpaca/sources/codex")))))

(ert-deftest agent-log-test-unique-project-names/no-duplicate-labels ()
  "Never emits the same display name for two distinct paths."
  (let* ((paths '("/private/tmp/codex-app-server-e2e"
                  "/private/tmp/codex-app-server-e2e-2"
                  "/p/8.1.0-dev/elpaca/sources/codex"
                  "/u/My Drive/dotfiles/codex"
                  "/p/8.3.0-dev/elpaca/sources/codex"))
         (names (mapcar #'cdr (agent-log--unique-project-names paths))))
    (should (= (length names) (length (delete-dups (copy-sequence names)))))))

(ert-deftest agent-log-test-unique-project-names/preserves-spaces ()
  "Keeps directory components that contain spaces intact."
  (should (equal (agent-log--unique-project-names '("/u/My Drive/dotfiles/codex"))
                 '(("/u/My Drive/dotfiles/codex" . "codex")))))

;;;;; Encode project path

(ert-deftest agent-log-test-encode-project-path/slashes-and-dots ()
  "Replaces slashes and dots with hyphens."
  (let ((result (agent-log-claude--encode-project-path "/home/user/my.project")))
    (should (not (string-match-p "[/.]" result)))
    (should (string-match-p "-home-user-my-project" result))))

(ert-deftest agent-log-test-claude-find-encoded-project/spaces ()
  "Finds an existing project from Claude's encoded directory name."
  (agent-log-test--with-temp-dir
    (let* ((project-dir (expand-file-name "My Drive/repos/ta65"
                                          agent-log-test--dir))
           (encoded (agent-log-claude--encode-project-path project-dir)))
      (make-directory project-dir t)
      (should (equal (agent-log-claude--find-encoded-project-below
                      agent-log-test--dir encoded 6)
                     (file-name-as-directory project-dir))))))

(ert-deftest agent-log-test-claude-session-project-directory/source-fallback ()
  "Uses the source JSONL projects directory when history has a stale path."
  (agent-log-test--with-temp-dir
    (let* ((project-dir (expand-file-name "My Drive/repos/ta65"
                                          agent-log-test--dir))
           (encoded (agent-log-claude--encode-project-path project-dir))
           (jsonl-path (agent-log-test--write-file
                        (format ".claude/projects/%s/s1.jsonl" encoded)
                        ""))
           (history-path (agent-log-test--write-file
                          ".claude/history.jsonl"
                          "{\"sessionId\":\"s1\",\"project\":\"/missing\"}\n"))
           (agent-log-directory (file-name-directory history-path))
           (agent-log--source-file jsonl-path)
           (agent-log--session-project nil))
      (make-directory project-dir t)
      (cl-letf (((symbol-function 'agent-log-claude--find-existing-encoded-project)
                 (lambda (actual-encoded)
                   (and (equal actual-encoded encoded)
                        project-dir))))
        (should (equal (agent-log-claude--session-project-directory "s1")
                       (file-name-as-directory project-dir)))))))

(ert-deftest agent-log-test-metadata-from-file/claude-history-project-fallback ()
  "Uses Claude history when the JSONL lacks progress CWD metadata."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-directory agent-log-test--dir)
           (projects-dir (expand-file-name
                          "projects/-Users-me-project" agent-log-test--dir))
           (jsonl-path (expand-file-name "s1.jsonl" projects-dir))
           (history-path (expand-file-name "history.jsonl" agent-log-test--dir)))
      (make-directory projects-dir t)
      (with-temp-file jsonl-path
        (insert "{\"type\":\"user\",\"timestamp\":\"2026-06-04T10:21:52Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello project\"}}\n"))
      (with-temp-file history-path
        (insert "{\"sessionId\":\"s1\",\"project\":\"/Users/me/project\",\"timestamp\":1780568512124,\"display\":\"Hello from history\"}\n"))
      (let ((metadata (agent-log--metadata-from-file
                       jsonl-path agent-log-test--claude-backend)))
        (should (equal (plist-get metadata :project)
                       "/Users/me/project"))
        (should (equal (plist-get metadata :display)
                       "Hello project"))
        (should (numberp (plist-get metadata :timestamp)))))))

;;;;; Index management

(ert-deftest agent-log-test-read-index/missing-file ()
  "Returns empty hash table when index file doesn't exist."
  (agent-log-test--with-temp-dir
    (let ((agent-log-rendered-directory agent-log-test--dir))
      (let ((result (agent-log--read-index)))
        (should (hash-table-p result))
        (should (= (hash-table-count result) 0))))))

(ert-deftest agent-log-test-read-index/corrupt-file ()
  "Returns empty hash table on corrupt file."
  (agent-log-test--with-temp-dir
    (let ((agent-log-rendered-directory agent-log-test--dir))
      (agent-log-test--write-file "_index.el" "not a hash table")
      (let ((result (agent-log--read-index)))
        (should (hash-table-p result))
        (should (= (hash-table-count result) 0))))))

(ert-deftest agent-log-test-write-and-read-index/roundtrip ()
  "Write then read produces the same data."
  (agent-log-test--with-temp-dir
    (let ((agent-log-rendered-directory agent-log-test--dir)
          (index (make-hash-table :test #'equal)))
      (puthash "session-1" (list :file "/tmp/a.md" :jsonl-size 100) index)
      (puthash "session-2" (list :file "/tmp/b.md" :jsonl-size 200) index)
      (agent-log--write-index index)
      (let ((loaded (agent-log--read-index)))
        (should (hash-table-p loaded))
        (should (= (hash-table-count loaded) 2))
        (should (equal (plist-get (gethash "session-1" loaded) :file) "/tmp/a.md"))
        (should (equal (plist-get (gethash "session-2" loaded) :jsonl-size) 200))))))

(ert-deftest agent-log-test-index-merge/new-entry ()
  "Merges properties into a new index entry."
  (let ((index (make-hash-table :test #'equal)))
    (agent-log--index-merge index "s1" (list :file "/a.md" :jsonl-size 100))
    (let ((entry (gethash "s1" index)))
      (should (equal (plist-get entry :file) "/a.md"))
      (should (equal (plist-get entry :jsonl-size) 100)))))

(ert-deftest agent-log-test-index-merge/update-preserves-existing ()
  "Merging preserves properties not in the new props."
  (let ((index (make-hash-table :test #'equal)))
    (puthash "s1" (list :file "/a.md" :jsonl-size 100 :summary "test") index)
    (agent-log--index-merge index "s1" (list :jsonl-size 200))
    (let ((entry (gethash "s1" index)))
      (should (equal (plist-get entry :file) "/a.md"))
      (should (equal (plist-get entry :jsonl-size) 200))
      (should (equal (plist-get entry :summary) "test")))))

(ert-deftest agent-log-test-index-merge/overwrite-value ()
  "Merging overwrites existing values for matching keys."
  (let ((index (make-hash-table :test #'equal)))
    (puthash "s1" (list :file "/old.md") index)
    (agent-log--index-merge index "s1" (list :file "/new.md"))
    (should (equal (plist-get (gethash "s1" index) :file) "/new.md"))))

(ert-deftest agent-log-test-repair-rendered-index/migrates-unknown-entry ()
  "Re-renders unknown-folder index entries to their real project path."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (concat
                         "{\"type\":\"progress\",\"cwd\":\"/Users/me/project\",\"timestamp\":\"2026-06-04T10:21:52Z\"}\n"
                         "{\"type\":\"user\",\"timestamp\":\"2026-06-04T10:21:52Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello project\"}}\n")))
           (old-rendered (agent-log-test--write-file
                          "rendered/unknown/unknown_untitled.md"
                          "<!-- session: s1 -->\n"))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (list :file old-rendered
                          :jsonl-size 1
                          :summary "Existing abstract"
                          :summary-oneline "Existing abstract")
               index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'agent-log--find-session-file-any)
                 (lambda (sid)
                   (and (equal sid "s1") jsonl-path)))
                ((symbol-function 'agent-log--backend-for-file)
                 (lambda (&rest _) agent-log-test--claude-backend)))
        (should (= (agent-log-repair-rendered-index) 1)))
      (let* ((entry (gethash "s1" (agent-log--read-index)))
             (new-file (plist-get entry :file)))
        (should (string-match-p "/project/" new-file))
        (should-not (string-match-p "/unknown/" new-file))
        (should (file-exists-p old-rendered))
        (should (file-exists-p new-file))
        (should (equal (plist-get entry :summary) "Existing abstract"))))))

(ert-deftest agent-log-test-backfill-rendered-summaries ()
  "Writes stored summaries into existing rendered Markdown files."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (rendered (agent-log-test--write-file
                      "rendered/project/session.md"
                      "<!-- session: s1 -->\n\n# Session: project — 2026-06-04\n\n---\n\n## User — now\n\nHello\n"))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (list :file rendered
                          :summary "Existing abstract"
                          :summary-oneline "Existing abstract")
               index)
      (agent-log--write-index index)
      (should (= (agent-log-backfill-rendered-summaries) 1))
      (let ((content (with-temp-buffer
                       (insert-file-contents rendered)
                       (buffer-string))))
        (should (string-match-p
                 "^> \\*\\*Summary\\*\\*: Existing abstract" content)))
      (should (= (agent-log-backfill-rendered-summaries) 0)))))

(ert-deftest agent-log-test-rendered-index-audit/classifies-summary-state ()
  "Classifies rendered index entries by actionable summary state."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (source (agent-log-test--write-file
                    "source/session.jsonl"
                    "{\"type\":\"user\",\"message\":{\"content\":\"Hello\"}}\n"))
           (present-rendered
            (agent-log-test--write-file
             "rendered/project/present.md"
             (format "<!-- source: %s -->\n\n# Session: project\n" source)))
           (missing-rendered
            (agent-log-test--write-file
             "rendered/project/missing.md"
             "<!-- source: /tmp/not-present.jsonl -->\n\n# Session: project\n"))
           (index (make-hash-table :test #'equal)))
      (puthash "real" (list :file present-rendered
                            :summary "Summary"
                            :summary-oneline "Summary"
                            :summary-conversation-hash "v2:abc")
               index)
      (puthash "none" (list :file present-rendered
                            :summary agent-log--no-conversation-sentinel
                            :summary-oneline agent-log--no-conversation-sentinel
                            :summary-conversation-hash "v2:def")
               index)
      (puthash "source-present" (list :file present-rendered) index)
      (puthash "rendered-only" (list :file missing-rendered) index)
      (puthash "stale" nil index)
      (agent-log--write-index index)
      (let ((audit (agent-log-rendered-index-audit)))
        (should (= (plist-get audit :total) 5))
        (should (= (plist-get audit :real-summary) 1))
        (should (= (plist-get audit :no-conversation) 1))
        (should (= (plist-get audit :source-present-missing-summary) 1))
        (should (= (plist-get audit :rendered-only-missing-summary) 1))
        (should (= (plist-get audit :stale-index-entry) 1))))))

(ert-deftest agent-log-test-clean-test-index-entries/removes-fixtures ()
  "Removes stale test fixture entries from the rendered index."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (rendered (agent-log-test--write-file
                      "rendered/project/session.md"
                      "<!-- session: real -->\n"))
           (index (make-hash-table :test #'equal)))
      (puthash "test-sid" nil index)
      (puthash "test-session-id" (list :jsonl-size 10) index)
      (puthash "real" (list :file rendered) index)
      (agent-log--write-index index)
      (should (= (agent-log-clean-test-index-entries) 2))
      (let ((loaded (agent-log--read-index)))
        (should-not (gethash "test-sid" loaded))
        (should-not (gethash "test-session-id" loaded))
        (should (gethash "real" loaded))))))

(ert-deftest agent-log-test-rendered-only-summary-candidates ()
  "Finds only missing-summary entries whose rendered files are source-only."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (source (agent-log-test--write-file
                    "source/session.jsonl"
                    "{\"type\":\"user\",\"message\":{\"content\":\"Hello\"}}\n"))
           (source-rendered
            (agent-log-test--write-file
             "rendered/project/source.md"
             (format "<!-- source: %s -->\n\n# Session: project\n" source)))
           (rendered-only
            (agent-log-test--write-file
             "rendered/project/rendered-only.md"
             "<!-- source: /tmp/not-present.jsonl -->\n\n# Session: project\n"))
           (index (make-hash-table :test #'equal)))
      (puthash "source-present" (list :file source-rendered) index)
      (puthash "rendered-only" (list :file rendered-only) index)
      (puthash "summarized" (list :file rendered-only
                                  :summary "Summary"
                                  :summary-oneline "Summary"
                                  :summary-conversation-hash "v2:abc")
               index)
      (agent-log--write-index index)
      (let ((candidates (agent-log--rendered-only-summary-candidates index)))
        (should (= (length candidates) 1))
        (should (equal (caar candidates) "rendered-only"))))))

(ert-deftest agent-log-test-summarize-rendered-handle-success/marks-recovered ()
  "Stores rendered-only summaries with explicit recovery metadata."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (rendered (agent-log-test--write-file
                      "rendered/project/session.md"
                      (concat "<!-- session: s1 -->\n\n"
                              "# Session: project\n\n"
                              "---\n\n"
                              "## User — now\n\nHello\n")))
           (index (make-hash-table :test #'equal))
           (text "User: Hello"))
      (puthash "s1" (list :file rendered) index)
      (agent-log--write-index index)
      (agent-log--summarize-rendered-handle-success
       "{\"oneline\":\"Greeting\",\"summary\":\"The user greeted the assistant.\"}"
       "s1" rendered text nil 0 1 1)
      (let* ((entry (gethash "s1" (agent-log--read-index)))
             (content (with-temp-buffer
                        (insert-file-contents rendered)
                        (buffer-string))))
        (should (equal (plist-get entry :summary-oneline) "Greeting"))
        (should (equal (plist-get entry :summary-source) :rendered-markdown))
        (should (equal (plist-get entry :summary-rendered-file) rendered))
        (should (plist-get entry :summary-recovered-from-rendered))
        (should (string-match-p
                 "^> \\*\\*Summary\\*\\*: The user greeted the assistant\\."
                 content))))))

(ert-deftest agent-log-test-summarize-rendered-handle-failure/finishes ()
  "A rendered-only summary failure advances the recovery loop."
  (let ((agent-log--rendered-summary-active t)
        (agent-log--rendered-summary-generation 1)
        (agent-log--rendered-summary-stop nil))
    (cl-letf (((symbol-function 'run-with-timer)
               (lambda (_secs _repeat fn &rest args)
                 (apply fn args))))
      (agent-log--summarize-rendered-handle-failure
       "s1" nil 0 1 1)
      (should-not agent-log--rendered-summary-active))))

;;;;; Tool result extraction

(ert-deftest agent-log-test-extract-tool-result-text/string ()
  "Extracts text from string content."
  (should (equal (agent-log--extract-tool-result-text "hello") "hello")))

(ert-deftest agent-log-test-extract-tool-result-text/list ()
  "Extracts text from list content."
  (let ((content (list (list :type "text" :text "part 1")
                       (list :type "text" :text "part 2"))))
    (should (equal (agent-log--extract-tool-result-text content)
                   "part 1\npart 2"))))

(ert-deftest agent-log-test-extract-tool-result-text/non-text-items ()
  "Handles non-text items in list content."
  (let ((content (list (list :type "image" :data "...")
                       (list :type "text" :text "hello"))))
    (should (equal (agent-log--extract-tool-result-text content) "\nhello"))))

(ert-deftest agent-log-test-extract-tool-result-text/nil ()
  "Returns empty string for nil content."
  (should (equal (agent-log--extract-tool-result-text nil) "")))

(ert-deftest agent-log-test-extract-tool-result-text/unexpected-type ()
  "Returns empty string for unexpected types."
  (should (equal (agent-log--extract-tool-result-text 42) "")))

;;;;; Tool input summarization

(ert-deftest agent-log-test-summarize-read ()
  "Summarizes Read tool input."
  (let ((result (agent-log--summarize-tool-input
                 "Read" (list :file_path "/tmp/test.el"))))
    (should (string-match-p "/tmp/test.el" result))))

(ert-deftest agent-log-test-summarize-write ()
  "Summarizes Write tool input."
  (let ((result (agent-log--summarize-tool-input
                 "Write" (list :file_path "/tmp/out.md"))))
    (should (string-match-p "/tmp/out.md" result))))

(ert-deftest agent-log-test-summarize-edit ()
  "Summarizes Edit tool input with file and old_string."
  (let ((result (agent-log--summarize-tool-input
                 "Edit" (list :file_path "/tmp/test.el"
                              :old_string "defun old-func"))))
    (should (string-match-p "/tmp/test.el" result))
    (should (string-match-p "defun old-func" result))))

(ert-deftest agent-log-test-summarize-edit/missing-fields ()
  "Handles Edit tool with missing fields."
  (let ((agent-log--backend agent-log-test--claude-backend))
    (let ((result (agent-log--summarize-tool-input "Edit" (list))))
      (should (string-match-p "\\?" result)))))

(ert-deftest agent-log-test-summarize-bash ()
  "Summarizes Bash tool input."
  (let ((result (agent-log--summarize-tool-input
                 "Bash" (list :command "git status"))))
    (should (string-match-p "git status" result))))

(ert-deftest agent-log-test-summarize-grep/with-path ()
  "Summarizes Grep with pattern and path."
  (let ((result (agent-log--summarize-tool-input
                 "Grep" (list :pattern "defun" :path "/src"))))
    (should (string-match-p "defun" result))
    (should (string-match-p "/src" result))))

(ert-deftest agent-log-test-summarize-grep/without-path ()
  "Summarizes Grep with pattern only."
  (let ((result (agent-log--summarize-tool-input
                 "Grep" (list :pattern "TODO"))))
    (should (string-match-p "TODO" result))
    (should-not (string-match-p " in " result))))

(ert-deftest agent-log-test-summarize-glob ()
  "Summarizes Glob tool input."
  (let ((result (agent-log--summarize-tool-input
                 "Glob" (list :pattern "**/*.el"))))
    (should (string-match-p "\\*\\*/\\*\\.el" result))))

(ert-deftest agent-log-test-summarize-web-fetch ()
  "Summarizes WebFetch tool input."
  (let ((result (agent-log--summarize-tool-input
                 "WebFetch" (list :url "https://example.com"))))
    (should (string-match-p "example.com" result))))

(ert-deftest agent-log-test-summarize-web-search ()
  "Summarizes WebSearch tool input."
  (let ((result (agent-log--summarize-tool-input
                 "WebSearch" (list :query "emacs lisp testing"))))
    (should (string-match-p "emacs lisp testing" result))))

(ert-deftest agent-log-test-summarize-task/with-type ()
  "Summarizes Task tool with subagent_type."
  (let ((result (agent-log--summarize-tool-input
                 "Task" (list :subagent_type "Explore"
                              :description "Find all tests"))))
    (should (string-match-p "Explore" result))
    (should (string-match-p "Find all tests" result))))

(ert-deftest agent-log-test-summarize-task/without-type ()
  "Summarizes Task tool without subagent_type."
  (let ((result (agent-log--summarize-tool-input
                 "Task" (list :description "Find all tests"))))
    (should (string-match-p "Find all tests" result))))

(ert-deftest agent-log-test-summarize-unknown-tool/falls-back-to-generic ()
  "Falls back to generic summary for unknown tools."
  (let ((result (agent-log--summarize-tool-input
                 "CustomTool" (list :foo "bar" :baz "qux"))))
    (should (string-match-p "foo" result))
    (should (string-match-p "bar" result))))

(ert-deftest agent-log-test-summarize-generic/valid-plist ()
  "Generic summary formats plist keys and values."
  (let ((result (agent-log--summarize-tool-input-generic
                 (list :name "test" :value "42"))))
    (should (string-match-p "name" result))
    (should (string-match-p "test" result))
    (should (string-match-p "value" result))
    (should (string-match-p "42" result))))

(ert-deftest agent-log-test-summarize-generic/invalid-plist ()
  "Returns empty string for non-plist input."
  (should (equal (agent-log--summarize-tool-input-generic '(a b c)) ""))
  (should (equal (agent-log--summarize-tool-input-generic "string") ""))
  (should (equal (agent-log--summarize-tool-input-generic nil) "")))

;;;;; Rendering

(ert-deftest agent-log-test-render-entry/user-string-content ()
  "Renders user entry with string content."
  (let ((entry (list :type "user"
                     :timestamp "2023-11-14T12:00:00Z"
                     :message (list :role "user" :content "Hello"))))
    (let ((result (agent-log--render-entry entry)))
      (should (string-match-p "## User" result))
      (should (string-match-p "Hello" result)))))

(ert-deftest agent-log-test-render-entry/assistant ()
  "Renders assistant entry."
  (let ((entry (list :type "assistant"
                     :timestamp "2023-11-14T12:00:00Z"
                     :message (list :role "assistant"
                                    :content (list (list :type "text"
                                                         :text "Response"))))))
    (let ((result (agent-log--render-entry entry)))
      (should (string-match-p "## Assistant" result))
      (should (string-match-p "Response" result)))))

(ert-deftest agent-log-test-render-entry/no-message ()
  "Returns empty string for entry without message."
  (let ((entry (list :type "user")))
    (should (equal (agent-log--render-entry entry) ""))))

(ert-deftest agent-log-test-render-entry/unknown-role ()
  "Returns empty string for unknown role."
  (let ((entry (list :type "system"
                     :message (list :role "system" :content "foo"))))
    (should (equal (agent-log--render-entry entry) ""))))

(ert-deftest agent-log-test-render-user-turn/string ()
  "Renders string user content."
  (let ((result (agent-log--render-user-turn "Hello" "2023-11-14")))
    (should (string-match-p "## User — 2023-11-14" result))
    (should (string-match-p "Hello" result))
    (should (string-match-p "^---" result))))

(ert-deftest agent-log-test-render-user-turn/list-with-text ()
  "Renders list content with text."
  (let ((content (list (list :type "text" :text "My question"))))
    (let ((result (agent-log--render-user-turn content "ts")))
      (should (string-match-p "## User" result))
      (should (string-match-p "My question" result)))))

(ert-deftest agent-log-test-render-user-turn/only-tool-results ()
  "Renders tool results without User heading."
  (let ((content (list (list :type "tool_result"
                             :content "result text"))))
    (let ((result (agent-log--render-user-turn content "ts")))
      (should-not (string-match-p "## User" result))
      (should (string-match-p "Tool result" result)))))

(ert-deftest agent-log-test-render-user-turn/empty-content ()
  "Returns empty string for empty list content."
  (should (equal (agent-log--render-user-turn (list) "ts") "")))

(ert-deftest agent-log-test-render-user-turn/whitespace-only-text ()
  "Returns empty for whitespace-only text items."
  (let ((content (list (list :type "text" :text "   "))))
    (should (equal (agent-log--render-user-turn content "ts") ""))))

(ert-deftest agent-log-test-render-assistant-turn/text ()
  "Renders assistant text content."
  (let ((content (list (list :type "text" :text "Here's the fix."))))
    (let ((result (agent-log--render-assistant-turn content "ts")))
      (should (string-match-p "## Assistant — ts" result))
      (should (string-match-p "Here's the fix." result)))))

(ert-deftest agent-log-test-render-assistant-turn/empty-body ()
  "Returns empty string for assistant turn with no visible content."
  (let ((content (list)))
    (should (equal (agent-log--render-assistant-turn content "ts") ""))))

(ert-deftest agent-log-test-render-assistant-body/mixed-content ()
  "Renders mixed thinking, text, and tool_use items."
  (let ((content (list (list :type "thinking" :thinking "Let me think...")
                       (list :type "text" :text "Here's my answer.")
                       (list :type "tool_use" :name "Bash"
                             :input (list :command "ls")))))
    (let ((result (agent-log--render-assistant-body content)))
      (should (string-match-p "#### Thinking" result))
      (should (string-match-p "Here's my answer." result))
      (should (string-match-p "#### Tool: Bash" result)))))

(ert-deftest agent-log-test-render-assistant-body/skips-empty-text ()
  "Skips empty text items."
  (let ((content (list (list :type "text" :text "")
                       (list :type "text" :text "  ")
                       (list :type "text" :text "Actual content"))))
    (let ((result (agent-log--render-assistant-body content)))
      (should (string-match-p "Actual content" result))
      ;; Should only have one text block, not three
      (should (= (length (split-string result "Actual content")) 2)))))

(ert-deftest agent-log-test-render-thinking ()
  "Renders thinking block with heading."
  (let ((item (list :type "thinking" :thinking "Analyzing the code...")))
    (let ((result (agent-log--render-thinking item)))
      (should (string-match-p "^#### Thinking" result))
      (should (string-match-p "Analyzing the code..." result)))))

(ert-deftest agent-log-test-render-thinking/truncation ()
  "Truncates long thinking blocks."
  (let* ((agent-log-max-tool-result-length 20)
         (item (list :type "thinking"
                     :thinking "This is a very long thinking block that should be truncated"))
         (result (agent-log--render-thinking item)))
    (should (string-match-p "…" result))))

(ert-deftest agent-log-test-render-thinking/collapses-newlines ()
  "Collapses multiple consecutive newlines."
  (let ((item (list :type "thinking" :thinking "line1\n\n\n\nline2")))
    (let ((result (agent-log--render-thinking item)))
      (should-not (string-match-p "\n\n\n" result)))))

(ert-deftest agent-log-test-render-thinking/empty-text ()
  "Returns empty string when thinking text is empty or missing."
  (should (string-empty-p (agent-log--render-thinking (list :type "thinking" :thinking ""))))
  (should (string-empty-p (agent-log--render-thinking (list :type "thinking"))))
  (should (string-empty-p (agent-log--render-thinking (list :type "thinking" :thinking "  ")))))

(ert-deftest agent-log-test-render-tool-use ()
  "Renders tool_use item with summary."
  (let ((item (list :type "tool_use" :name "Read"
                    :input (list :file_path "/tmp/test.el"))))
    (let ((result (agent-log--render-tool-use item)))
      (should (string-match-p "^#### Tool: Read" result))
      (should (string-match-p "/tmp/test.el" result)))))

(ert-deftest agent-log-test-render-tool-result ()
  "Renders tool_result as blockquote."
  (let ((item (list :type "tool_result" :content "File contents here")))
    (let ((result (agent-log--render-tool-result item)))
      (should (string-match-p "^#### Tool result" result))
      (should (string-match-p "> File contents here" result)))))

(ert-deftest agent-log-test-render-tool-result/multiline ()
  "Renders multiline tool result with blockquote continuation."
  (let ((item (list :type "tool_result" :content "line1\nline2\nline3")))
    (let ((result (agent-log--render-tool-result item)))
      (should (string-match-p "> line1" result))
      (should (string-match-p "> line2" result))
      (should (string-match-p "> line3" result)))))

(ert-deftest agent-log-test-collect-user-text/filters-text ()
  "Collects only text items from content."
  (let ((content (list (list :type "text" :text "question")
                       (list :type "tool_result" :content "result")
                       (list :type "text" :text "followup"))))
    (let ((result (agent-log--collect-user-text content)))
      (should (= (length result) 2))
      (should (string-match-p "question" (car result)))
      (should (string-match-p "followup" (cadr result))))))

(ert-deftest agent-log-test-collect-user-text/empty-text-excluded ()
  "Excludes empty and whitespace-only text items."
  (let ((content (list (list :type "text" :text "")
                       (list :type "text" :text "  \n  ")
                       (list :type "text" :text "real text"))))
    (let ((result (agent-log--collect-user-text content)))
      (should (= (length result) 1))
      (should (string-match-p "real text" (car result))))))

(ert-deftest agent-log-test-collect-tool-results ()
  "Collects only tool_result items."
  (let ((content (list (list :type "text" :text "text")
                       (list :type "tool_result" :content "result 1")
                       (list :type "tool_result" :content "result 2"))))
    (should (= (length (agent-log--collect-tool-results content)) 2))))

;;;;; UTF-8 boundary detection

(ert-deftest agent-log-test-incomplete-utf8/complete-ascii ()
  "ASCII string has no incomplete tail."
  (should (= (agent-log--incomplete-utf8-tail-length
              (encode-coding-string "hello" 'raw-text))
             0)))

(ert-deftest agent-log-test-incomplete-utf8/complete-multibyte ()
  "Complete multibyte string has no incomplete tail."
  (should (= (agent-log--incomplete-utf8-tail-length
              (encode-coding-string "café" 'utf-8))
             0)))

(ert-deftest agent-log-test-incomplete-utf8/truncated-2byte ()
  "Detects incomplete 2-byte sequence (lead byte only)."
  (let* ((full (encode-coding-string "é" 'utf-8))
         (partial (substring full 0 1)))
    (should (= (agent-log--incomplete-utf8-tail-length partial) 1))))

(ert-deftest agent-log-test-incomplete-utf8/truncated-3byte ()
  "Detects incomplete 3-byte sequence."
  (let* ((full (encode-coding-string "€" 'utf-8))  ; 3 bytes
         (partial (substring full 0 2)))
    (should (= (agent-log--incomplete-utf8-tail-length partial) 2))))

(ert-deftest agent-log-test-incomplete-utf8/truncated-4byte ()
  "Detects incomplete 4-byte sequence."
  (let* ((full (encode-coding-string "𐍈" 'utf-8))  ; 4-byte Gothic letter
         (partial (substring full 0 2)))
    (should (= (agent-log--incomplete-utf8-tail-length partial) 2))))

(ert-deftest agent-log-test-incomplete-utf8/empty-string ()
  "Empty string has no incomplete tail."
  (should (= (agent-log--incomplete-utf8-tail-length "") 0)))

(ert-deftest agent-log-test-incomplete-utf8/ascii-then-truncated ()
  "ASCII followed by truncated multibyte."
  (let* ((ascii (encode-coding-string "hello" 'raw-text))
         (full-utf8 (encode-coding-string "é" 'utf-8))
         (combined (concat ascii (substring full-utf8 0 1))))
    (should (= (agent-log--incomplete-utf8-tail-length combined) 1))))

;;;;; Front matter

(ert-deftest agent-log-test-render-front-matter ()
  "Renders front matter with session metadata."
  (let ((result (agent-log--render-front-matter "abc-123" "/tmp/test.jsonl" 5000)))
    (should (string-match-p "<!-- session: abc-123 -->" result))
    (should (string-match-p "<!-- source: /tmp/test.jsonl -->" result))
    (should (string-match-p "<!-- jsonl-size: 5000 -->" result))
    (should (string-match-p "<!-- rendered: " result))))

(ert-deftest agent-log-test-render-front-matter/nil-size ()
  "Handles nil size with fallback to 0."
  (let ((result (agent-log--render-front-matter "id" "/tmp/x.jsonl" nil)))
    (should (string-match-p "<!-- jsonl-size: 0 -->" result))))

;;;;; Session metadata extraction

(ert-deftest agent-log-test-extract-session-metadata-from-entries ()
  "Extracts project and date from entries."
  (let ((entries (list (list :type "progress" :cwd "/home/user/project")
                       (list :type "user"
                             :timestamp "2023-11-14T12:00:00Z"
                             :message (list :role "user" :content "hello")))))
    (let ((result (agent-log--extract-session-metadata-from-entries entries)))
      (should (equal (plist-get result :project) "project"))
      (should (string-match-p "2023-11-14" (plist-get result :date))))))

(ert-deftest agent-log-test-extract-session-metadata-from-entries/no-progress ()
  "Returns \"unknown\" project when no progress entry."
  (let ((entries (list (list :type "user"
                             :timestamp "2023-11-14T12:00:00Z"
                             :message (list :role "user" :content "hi")))))
    (let ((result (agent-log--extract-session-metadata-from-entries entries)))
      (should (equal (plist-get result :project) "unknown")))))

(ert-deftest agent-log-test-extract-session-metadata-from-entries/progress-date ()
  "Uses progress timestamp when no conversation timestamp exists."
  (let ((entries (list (list :type "progress"
                             :cwd "/home/user/project"
                             :timestamp "2023-11-14T12:00:00Z"))))
    (let ((result (agent-log--extract-session-metadata-from-entries entries)))
      (should (equal (plist-get result :project) "project"))
      (should (string-match-p "2023-11-14" (plist-get result :date))))))

;;;;; Rendered filepath

(ert-deftest agent-log-test-rendered-filepath/generates-path ()
  "Generates a valid rendered filepath."
  (let* ((agent-log-rendered-directory "/tmp/rendered")
         (metadata (list :timestamp 1700000000000
                         :project "/home/user/my-app"
                         :display "Fix the bug"))
         (result (agent-log--rendered-filepath "session-1" metadata)))
    (should (string-match-p "/tmp/rendered/my-app/" result))
    (should (string-match-p "fix-the-bug\\.md$" result))
    (should (string-match-p "2023-11-1[45]_" result))))

(ert-deftest agent-log-test-rendered-filepath/missing-timestamp ()
  "Handles missing (non-numeric) timestamp."
  (let* ((agent-log-rendered-directory "/tmp/rendered")
         (metadata (list :timestamp nil
                         :project "/project"
                         :display "test")))
    (let ((result (agent-log--rendered-filepath "s1" metadata)))
      (should (string-match-p "unknown_test\\.md" result)))))

(ert-deftest agent-log-test-rendered-filepath/empty-display ()
  "Handles empty display text."
  (let* ((agent-log-rendered-directory "/tmp/rendered")
         (metadata (list :timestamp 1700000000000
                         :project "/project"
                         :display "")))
    (let ((result (agent-log--rendered-filepath "s1" metadata)))
      (should (string-match-p "untitled\\.md" result)))))

;;;;; Render to file (integration)

(ert-deftest agent-log-test-render-to-file/basic ()
  "Renders a JSONL file to Markdown."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content
            (concat
             "{\"type\":\"progress\",\"cwd\":\"/home/user/project\"}\n"
             "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\","
             "\"message\":{\"role\":\"user\",\"content\":\"Fix the bug\"}}\n"
             "{\"type\":\"assistant\",\"timestamp\":\"2023-11-14T12:00:01Z\","
             "\"message\":{\"role\":\"assistant\",\"content\":"
             "[{\"type\":\"text\",\"text\":\"I'll fix it.\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (output-path (expand-file-name "output.md" agent-log-test--dir))
           (metadata (list :file jsonl-path
                           :timestamp 1700000000000
                           :project "/home/user/project"
                           :display "Fix the bug"))
           (result (agent-log--render-to-file "s1" metadata output-path)))
      ;; Returns (rendered-path . jsonl-size)
      (should (equal (car result) output-path))
      (should (numberp (cdr result)))
      ;; File should exist and contain expected content
      (should (file-exists-p output-path))
      (let ((content (with-temp-buffer
                       (insert-file-contents output-path)
                       (buffer-string))))
        (should (string-match-p "<!-- session: s1 -->" content))
        (should (string-match-p "# Session:" content))
        (should (string-match-p "## User" content))
        (should (string-match-p "Fix the bug" content))
        (should (string-match-p "## Assistant" content))
        (should (string-match-p "I'll fix it." content))))))

(ert-deftest agent-log-test-render-to-file/malformed-lines-handled ()
  "Renders correctly even with some malformed JSONL lines."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content
            (concat
             "CORRUPTED LINE\n"
             "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\","
             "\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n"
             "ANOTHER BAD LINE\n"))
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (output-path (expand-file-name "output.md" agent-log-test--dir))
           (metadata (list :file jsonl-path :timestamp nil :project "" :display ""))
           (result (agent-log--render-to-file "s1" metadata output-path)))
      (should (file-exists-p output-path))
      (let ((content (with-temp-buffer
                       (insert-file-contents output-path)
                       (buffer-string))))
        (should (string-match-p "## User" content))
        (should (string-match-p "hello" content))))))

(ert-deftest agent-log-test-render-to-file/uses-parsed-metadata-for-path ()
  "Uses metadata parsed from the JSONL when caller metadata is minimal."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (concat
                         "{\"type\":\"progress\",\"cwd\":\"/Users/me/project\",\"timestamp\":\"2026-06-04T10:21:52Z\"}\n"
                         "{\"type\":\"user\",\"timestamp\":\"2026-06-04T10:21:52Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello project\"}}\n")))
           (metadata (list :file jsonl-path
                           :timestamp nil
                           :project ""
                           :display ""
                           :backend agent-log-test--claude-backend))
           (result (agent-log--render-to-file "s1" metadata))
           (rendered-path (car result))
           (expected-timestamp
            (format-time-string "%Y-%m-%d_%H-%M"
                                (date-to-time "2026-06-04T10:21:52Z"))))
      (should (string-match-p "/project/" rendered-path))
      (should-not (string-match-p "/unknown/" rendered-path))
      (should (string-match-p (concat (regexp-quote expected-timestamp)
                                      "_hello-project\\.md\\'")
                              rendered-path)))))

(ert-deftest agent-log-test-render-to-file/persists-summary ()
  "Writes an existing index summary into the rendered Markdown file."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (concat
                         "{\"type\":\"progress\",\"cwd\":\"/Users/me/project\",\"timestamp\":\"2026-06-04T07:21:52Z\"}\n"
                         "{\"type\":\"user\",\"timestamp\":\"2026-06-04T07:21:52Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello\"}}\n")))
           (metadata (list :file jsonl-path
                           :timestamp 1780557712000
                           :project "/Users/me/project"
                           :display "Hello"
                           :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (list :summary "Existing abstract"
                          :summary-oneline "Existing abstract")
               index)
      (agent-log--write-index index)
      (let* ((result (agent-log--render-to-file "s1" metadata))
             (content (with-temp-buffer
                        (insert-file-contents (car result))
                        (buffer-string))))
        (should (string-match-p "> \\*\\*Summary\\*\\*: Existing abstract"
                                content))))))

;;;;; Summary parsing

(ert-deftest agent-log-test-parse-summary-response/valid-json ()
  "Parses valid JSON summary response."
  (let ((result (agent-log--parse-summary-response
                 "{\"summary\":\"A detailed summary.\",\"oneline\":\"Short\"}")))
    (should result)
    (should (equal (car result) "A detailed summary."))
    (should (equal (cdr result) "Short"))))

(ert-deftest agent-log-test-parse-summary-response/with-code-fences ()
  "Parses JSON with markdown code fences."
  (let ((result (agent-log--parse-summary-response
                 "```json\n{\"summary\":\"test\",\"oneline\":\"short\"}\n```")))
    (should result)
    (should (equal (car result) "test"))))

(ert-deftest agent-log-test-parse-summary-response/invalid-json ()
  "Returns nil for invalid JSON."
  (should (null (agent-log--parse-summary-response "not json"))))

(ert-deftest agent-log-test-parse-summary-response/missing-fields ()
  "Returns nil when required fields are missing."
  (should (null (agent-log--parse-summary-response "{\"summary\":\"test\"}")))
  (should (null (agent-log--parse-summary-response "{\"oneline\":\"test\"}"))))

(ert-deftest agent-log-test-parse-summary-response/non-string-fields ()
  "Returns nil when fields are not strings."
  (should (null (agent-log--parse-summary-response
                 "{\"summary\":123,\"oneline\":\"test\"}"))))

(ert-deftest agent-log-test-parse-summary-response/whitespace-trimmed ()
  "Trims whitespace from response."
  (let ((result (agent-log--parse-summary-response
                 "  \n{\"summary\":\"test\",\"oneline\":\"short\"}\n  ")))
    (should result)
    (should (equal (car result) "test"))))

;;;;; Message text extraction

(ert-deftest agent-log-test-extract-message-text/string ()
  "Extracts text from string content."
  (should (equal (agent-log--extract-message-text agent-log-test--claude-backend "hello") "hello")))

(ert-deftest agent-log-test-extract-message-text/list ()
  "Extracts text from list content, ignoring non-text items."
  (let ((content (list (list :type "thinking" :thinking "...")
                       (list :type "text" :text "answer")
                       (list :type "tool_use" :name "Bash"))))
    (should (equal (agent-log--extract-message-text agent-log-test--claude-backend content) "answer"))))

(ert-deftest agent-log-test-extract-message-text/multiple-texts ()
  "Joins multiple text items."
  (let ((content (list (list :type "text" :text "part 1")
                       (list :type "text" :text "part 2"))))
    (should (equal (agent-log--extract-message-text agent-log-test--claude-backend content) "part 1\npart 2"))))

(ert-deftest agent-log-test-extract-message-text/empty ()
  "Returns empty string for nil or non-list/string."
  (should (equal (agent-log--extract-message-text agent-log-test--claude-backend nil) ""))
  (should (equal (agent-log--extract-message-text agent-log-test--claude-backend 42) "")))

(ert-deftest agent-log-test-extract-message-text/skips-empty-text ()
  "Skips empty and whitespace-only text items."
  (let ((content (list (list :type "text" :text "")
                       (list :type "text" :text "   ")
                       (list :type "text" :text "real"))))
    (should (equal (agent-log--extract-message-text agent-log-test--claude-backend content) "real"))))

;;;;; Conversation text extraction

(ert-deftest agent-log-test-extract-conversation-text/basic ()
  "Extracts conversation text from entries."
  (let ((entries (list (list :type "user"
                             :message (list :role "user" :content "question"))
                       (list :type "assistant"
                             :message (list :role "assistant"
                                            :content (list (list :type "text"
                                                                  :text "answer")))))))
    (let ((result (agent-log--extract-conversation-text
                   entries agent-log-test--claude-backend)))
      (should (string-match-p "User: question" result))
      (should (string-match-p "Assistant: answer" result)))))

(ert-deftest agent-log-test-extract-conversation-text/truncation ()
  "Truncates to max content length."
  (let ((agent-log-summary-max-content-length 30)
        (entries (list (list :type "user"
                             :message (list :role "user"
                                            :content "This is a long message that should be truncated"))
                       (list :type "assistant"
                             :message (list :role "assistant"
                                            :content (list (list :type "text"
                                                                  :text "Another long message")))))))
    (let ((result (agent-log--extract-conversation-text
                   entries agent-log-test--claude-backend)))
      (should (<= (length result) 30)))))

(ert-deftest agent-log-test-extract-conversation-text/preserves-tail ()
  "Keeps the end of long sessions for summaries."
  (let ((agent-log-summary-max-content-length 120)
        (entries (list (list :type "user"
                             :message (list :role "user"
                                            :content (make-string 80 ?a)))
                       (list :type "assistant"
                             :message (list :role "assistant"
                                            :content (list (list :type "text"
                                                                  :text "tail marker")))))))
    (let ((result (agent-log--extract-conversation-text
                   entries agent-log-test--claude-backend)))
      (should (<= (length result) 120))
      (should (string-match-p "User: a" result))
      (should (string-match-p "tail marker" result)))))

(ert-deftest agent-log-test-extract-conversation-text/filters-non-conversation ()
  "Excludes non-conversation entries."
  (let ((entries (list (list :type "progress" :cwd "/tmp")
                       (list :type "user"
                             :message (list :role "user" :content "hello")))))
    (let ((result (agent-log--extract-conversation-text
                   entries agent-log-test--claude-backend)))
      (should (string-match-p "User: hello" result))
      (should-not (string-match-p "progress" result)))))

(ert-deftest agent-log-test-conversation-text-from-file/skips-claude-noise ()
  "Skips non-conversation Claude lines before JSON parsing."
  (agent-log-test--with-temp-dir
    (let* ((content (concat "{not-json " (make-string 1000 ?x) "}\n"
                            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n"))
           (path (agent-log-test--write-file "s1.jsonl" content)))
      (cl-letf (((symbol-function 'agent-log--parse-json-line)
                 (lambda (line)
                   (when (string-prefix-p "{not-json" line)
                     (error "noise line should not be parsed"))
                   (json-parse-string line :object-type 'plist
                                      :array-type 'list))))
        (should (equal (agent-log--conversation-text-from-file
                        path agent-log-test--claude-backend)
                       "User: hello\n\n"))))))

(ert-deftest agent-log-test-conversation-text-from-file/claude-spaced-json ()
  "Extracts Claude conversation text from JSON with spaces."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\": \"user\", \"message\": {\"role\": \"user\", \"content\": \"hello\"}}\n")
           (path (agent-log-test--write-file "s1.jsonl" content)))
      (should (equal (agent-log--conversation-text-from-file
                      path agent-log-test--claude-backend)
                     "User: hello\n\n")))))

(ert-deftest agent-log-test-conversation-text-from-file/skips-claude-local-commands ()
  "Skips Claude local command XML entries in summary text."
  (agent-log-test--with-temp-dir
    (let* ((content
            (concat
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"<local-command-caveat>ignore</local-command-caveat>\"}}\n"
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"<command-name>/model</command-name>\"}}\n"
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"<local-command-stdout>Opus 4.8</local-command-stdout>\"}}\n"
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"Real question\"}}\n"))
           (path (agent-log-test--write-file "s1.jsonl" content)))
      (should (equal (agent-log--conversation-text-from-file
                      path agent-log-test--claude-backend)
                     "User: Real question\n\n")))))

;;;;; Build summary prompt

(ert-deftest agent-log-test-build-summary-prompt ()
  "Builds a summary prompt wrapping conversation text."
  (let ((result (agent-log--build-summary-prompt "User: hi\nAssistant: hello")))
    (should (string-match-p "Summarize" result))
    (should (string-match-p "User: hi" result))))

;;;;; Group by project

(ert-deftest agent-log-test-group-by-project/basic ()
  "Groups sessions by project."
  (let ((sessions (list (list "s1" :project "/home/user/project-a" :timestamp 3000)
                        (list "s2" :project "/home/user/project-b" :timestamp 2000)
                        (list "s3" :project "/home/user/project-a" :timestamp 1000))))
    (let ((result (agent-log--group-by-project sessions)))
      ;; Should have two groups
      (should (= (length result) 2))
      ;; project-a should be first (most recent timestamp = 3000)
      (should (equal (car (car result)) "project-a"))
      ;; project-a should have 2 sessions
      (should (= (length (cdr (car result))) 2)))))

(ert-deftest agent-log-test-sort-sessions/creation-time ()
  "Sorts sessions by creation timestamp by default."
  (let ((agent-log-session-sort-key 'creation-time)
        (sessions (list (list "older" :timestamp 1000)
                        (list "newer" :timestamp 3000))))
    (should (equal (mapcar #'car (agent-log--sort-sessions sessions))
                   '("newer" "older")))))

(ert-deftest agent-log-test-sort-sessions/modification-time ()
  "Sorts sessions by source file modification time when configured."
  (agent-log-test--with-temp-dir
    (let* ((old-file (agent-log-test--write-file "old.jsonl" "{}\n"))
           (new-file (agent-log-test--write-file "new.jsonl" "{}\n"))
           (agent-log-session-sort-key 'modification-time)
           (sessions (list (list "created-newer" :timestamp 3000
                                 :file old-file)
                           (list "modified-newer" :timestamp 1000
                                 :file new-file))))
      (set-file-times old-file (seconds-to-time 100))
      (set-file-times new-file (seconds-to-time 200))
      (should (equal (mapcar #'car (agent-log--sort-sessions sessions))
                     '("modified-newer" "created-newer"))))))

(ert-deftest agent-log-test-sort-sessions/modification-time-caches-file-state ()
  "Reads source file metadata once per session when sorting by mtime."
  (agent-log-test--with-temp-dir
    (let* ((old-file (agent-log-test--write-file "old.jsonl" "{}\n"))
           (mid-file (agent-log-test--write-file "mid.jsonl" "{}\n"))
           (new-file (agent-log-test--write-file "new.jsonl" "{}\n"))
           (agent-log-session-sort-key 'modification-time)
           (sessions (list (list "old" :timestamp 3000 :file old-file)
                           (list "new" :timestamp 2000 :file new-file)
                           (list "mid" :timestamp 1000 :file mid-file)))
           (orig-file-attributes (symbol-function 'file-attributes))
           (calls 0))
      (set-file-times old-file (seconds-to-time 100))
      (set-file-times mid-file (seconds-to-time 200))
      (set-file-times new-file (seconds-to-time 300))
      (cl-letf (((symbol-function 'file-attributes)
                 (lambda (&rest args)
                   (cl-incf calls)
                   (apply orig-file-attributes args))))
        (agent-log--sort-sessions sessions)
        (should (= calls (length sessions)))))))

(ert-deftest agent-log-test-group-by-project/modification-time ()
  "Orders project groups by the newest session modification time."
  (agent-log-test--with-temp-dir
    (let* ((a-old (agent-log-test--write-file "a-old.jsonl" "{}\n"))
           (a-new (agent-log-test--write-file "a-new.jsonl" "{}\n"))
           (b-new (agent-log-test--write-file "b-new.jsonl" "{}\n"))
           (agent-log-session-sort-key 'modification-time)
           (sessions (list (list "a-old" :project "/home/user/project-a"
                                 :timestamp 3000 :file a-old)
                           (list "b-new" :project "/home/user/project-b"
                                 :timestamp 2000 :file b-new)
                           (list "a-new" :project "/home/user/project-a"
                                 :timestamp 1000 :file a-new))))
      (set-file-times a-old (seconds-to-time 100))
      (set-file-times a-new (seconds-to-time 200))
      (set-file-times b-new (seconds-to-time 300))
      (let ((result (agent-log--group-by-project sessions)))
        (should (equal (car (car result)) "project-b"))
        (should (equal (mapcar #'car (cdr (cadr result)))
                       '("a-new" "a-old")))))))

(ert-deftest agent-log-test-group-by-project/empty ()
  "Returns empty list for no sessions."
  (should (null (agent-log--group-by-project nil))))

(ert-deftest agent-log-test-session-ignored-p/tmp ()
  "Ignores sessions whose project is under the temporary directory."
  (should (agent-log--session-ignored-p (list "s" :project "/tmp/codex-gt")))
  (should (agent-log--session-ignored-p
           (list "s" :project "/private/tmp/codex-gt")))
  (should (agent-log--session-ignored-p (list "s" :project "/tmp"))))

(ert-deftest agent-log-test-session-ignored-p/keeps-real-paths ()
  "Keeps real directories, including names that merely begin with tmp."
  (should-not (agent-log--session-ignored-p (list "s" :project "/Users/me/proj")))
  (should-not (agent-log--session-ignored-p (list "s" :project "/tmpfoo")))
  (should-not (agent-log--session-ignored-p (list "s" :project "/tmp-backups")))
  (should-not (agent-log--session-ignored-p (list "s" :project ""))))

;;;;; Sessions needing summary

(ert-deftest agent-log-test-sessions-needing-summary/all-need ()
  "Returns all sessions when none have summaries."
  (let ((sessions (list (list "s1" :file "/a.jsonl")
                        (list "s2" :file "/b.jsonl")))
        (index (make-hash-table :test #'equal)))
    (should (= (length (agent-log--sessions-needing-summary sessions index)) 2))))

(ert-deftest agent-log-test-sessions-needing-summary/some-summarized ()
  "Excludes sessions with current summaries."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (s1 (list "s1" :file jsonl-path :backend agent-log-test--claude-backend))
           (sessions (list s1 (list "s2" :file "/b.jsonl")))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (agent-log-test--summary-entry (cdr s1) "A test") index)
      (should (= (length (agent-log--sessions-needing-summary sessions index)) 1))
      (should (equal (caar (agent-log--sessions-needing-summary sessions index)) "s2")))))

(ert-deftest agent-log-test-sessions-needing-summary/all-summarized ()
  "Returns empty when all sessions have current summaries."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (s1-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (s2-path (agent-log-test--write-file "s2.jsonl" jsonl-content))
           (s1 (list "s1" :file s1-path :backend agent-log-test--claude-backend))
           (s2 (list "s2" :file s2-path :backend agent-log-test--claude-backend))
           (sessions (list s1 s2))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (agent-log-test--summary-entry (cdr s1) "A") index)
      (puthash "s2" (agent-log-test--summary-entry (cdr s2) "B") index)
      (should (null (agent-log--sessions-needing-summary sessions index))))))

(ert-deftest agent-log-test-sessions-needing-summary/current-check-is-cheap ()
  "Does not parse session JSONL while checking current summaries."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (agent-log-test--summary-entry (cdr session) "A") index)
      (cl-letf (((symbol-function 'agent-log--conversation-text-from-file)
                 (lambda (&rest _)
                   (error "currentness check should not parse JSONL"))))
        (should (null (agent-log--sessions-needing-summary
                       (list session) index)))))))

(ert-deftest agent-log-test-sessions-needing-summary/missing-hash-stale ()
  "Treats legacy summaries without a conversation hash as stale."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (sessions (list (list "s1" :file jsonl-path
                                 :backend agent-log-test--claude-backend)))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (list :summary-oneline "A") index)
      (should (= (length (agent-log--sessions-needing-summary sessions index)) 1)))))

(ert-deftest agent-log-test-sessions-needing-summary/no-hash-preserved-stale ()
  "Treats no-hash legacy summaries as stale even if preservation was stamped."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal)))
      (pcase-let ((`(,size . ,mtime)
                   (agent-log--session-jsonl-state (cdr session))))
        (puthash "s1" (list :summary-oneline "A"
                            :summary-legacy-preserved t
                            :summary-jsonl-size size
                            :summary-jsonl-mtime mtime)
                 index))
      (should (= (length (agent-log--sessions-needing-summary
                          (list session) index))
                 1)))))

(ert-deftest agent-log-test-sessions-needing-summary/stale-file-state-usable ()
  "Keeps hash-versioned summaries out of archive-wide pending work.
The archive queue is intentionally cheap: a size/mtime mismatch may be
a metadata-only rewrite, such as `move-session-log', and should not
inflate the pending summary count."
  (agent-log-test--with-temp-dir
    (let* ((old-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (new-content (concat old-content
                                "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"new work\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "s1.jsonl" old-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (old-entry (agent-log-test--summary-entry (cdr session) "A"))
           (index (make-hash-table :test #'equal)))
      (agent-log-test--write-file "s1.jsonl" new-content)
      (puthash "s1" old-entry index)
      (should (null (agent-log--sessions-needing-summary
                     (list session) index))))))

(ert-deftest agent-log-test-upgrade-summary-index/v1-current ()
  "Upgrades a matching v1 summary instead of re-summarizing it."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir))
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (should (= (agent-log--upgrade-summary-index (list session) index) 1))
      (let ((entry (gethash "s1" index)))
        (should (agent-log--session-summary-current-p session entry))
        (should-not (plist-get entry :summary-legacy-preserved))
        (should (agent-log--summary-hash-current-version-p
                 (plist-get entry :summary-conversation-hash)))
        (should (plist-member entry :summary-jsonl-size))
        (should (plist-member entry :summary-jsonl-mtime)))
      (should (null (agent-log--sessions-needing-summary
                     (list session) index))))))

(ert-deftest agent-log-test-upgrade-summary-index/v1-full-parser-fallback ()
  "Upgrades v1 summaries when fast extraction cannot prove currentness."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir))
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (cl-letf (((symbol-function 'agent-log--conversation-text-from-file)
                 (lambda (&rest _) "")))
        (should (= (agent-log--upgrade-summary-index (list session) index)
                   1)))
      (let ((entry (gethash "s1" index)))
        (should (agent-log--session-summary-current-p session entry))
        (should (agent-log--summary-hash-current-version-p
                 (plist-get entry :summary-conversation-hash)))))))

(ert-deftest agent-log-test-upgrade-summary-index/v2-stale-file-state-current ()
  "Refreshes matching v2 summaries when only file-state metadata is stale."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir)
           (entry (agent-log-test--summary-entry (cdr session) "A")))
      (plist-put entry :summary-jsonl-size -1)
      (puthash "s1" entry index)
      (should (= (agent-log--upgrade-summary-index (list session) index) 1))
      (let ((updated (gethash "s1" index)))
        (should (equal (plist-get updated :summary-oneline) "A"))
        (should (agent-log--session-summary-current-p session updated))))))

(ert-deftest agent-log-test-upgrade-summary-index/v2-changed-conversation-stale ()
  "Does not refresh v2 summaries when the conversation hash changed.
The strict per-session predicate still sees the entry as stale, but the
archive-wide queue keeps hash-versioned summaries usable without
rereading every transcript."
  (agent-log-test--with-temp-dir
    (let* ((old-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (new-content (concat old-content
                                "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"new work\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "s1.jsonl" old-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir)
           (entry (agent-log-test--summary-entry (cdr session) "A")))
      (agent-log-test--write-file "s1.jsonl" new-content)
      (puthash "s1" entry index)
      (should (= (agent-log--upgrade-summary-index (list session) index) 0))
      (should-not (agent-log--session-summary-current-p
                   session (gethash "s1" index)))
      (should (agent-log--session-summary-usable-p (gethash "s1" index)))
      (should (null (agent-log--sessions-needing-summary
                     (list session) index))))))

(ert-deftest agent-log-test-session-needs-summary/resumed-tail-beyond-limit ()
  "Detects resumed work appended beyond the summary prompt limit."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-summary-max-content-length 80)
           (old-content
            (concat
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\""
             (make-string 200 ?a)
             "\"}}\n"))
           (new-content
            (concat
             old-content
             "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\","
             "\"content\":[{\"type\":\"text\",\"text\":\"resumed tail work\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "s1.jsonl" old-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir)
           (entry (agent-log-test--summary-entry (cdr session) "A")))
      (agent-log-test--write-file "s1.jsonl" new-content)
      (puthash "s1" entry index)
      (agent-log--write-index index)
      (should (agent-log--session-needs-summary-p session)))))

(ert-deftest agent-log-test-upgrade-summary-index/v2-empty-sentinel-current ()
  "Refreshes matching empty-session sentinels when file-state metadata is stale."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-path (agent-log-test--write-file "s1.jsonl" ""))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir)
           (entry (agent-log-test--summary-entry
                   (cdr session) agent-log--no-conversation-sentinel)))
      (plist-put entry :summary-jsonl-size -1)
      (puthash "s1" entry index)
      (should (= (agent-log--upgrade-summary-index (list session) index) 1))
      (let ((updated (gethash "s1" index)))
        (should (equal (plist-get updated :summary-oneline)
                       agent-log--no-conversation-sentinel))
        (should (agent-log--session-summary-current-p session updated))))))

(ert-deftest agent-log-test-upgrade-summary-index/no-hash-stale ()
  "Leaves no-hash legacy summaries stale so they are refreshed once."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir))
      (puthash "s1" (list :summary "A" :summary-oneline "A") index)
      (cl-letf (((symbol-function 'agent-log--conversation-text-from-file)
                 (lambda (&rest _)
                   (error "legacy preservation should not parse JSONL")))
                ((symbol-function 'agent-log--parse-and-normalize)
                 (lambda (&rest _)
                   (error "legacy preservation should not use full parser"))))
        (should (= (agent-log--upgrade-summary-index (list session) index)
                   0)))
      (let ((entry (gethash "s1" index)))
        (should (equal (plist-get entry :summary-oneline) "A"))
        (should-not (plist-get entry :summary-legacy-preserved))
        (should-not (agent-log--session-summary-current-p session entry))
        (should (= (length (agent-log--sessions-needing-summary
                            (list session) index))
                   1))))))

(ert-deftest agent-log-test-upgrade-summary-index/upgraded-change-stale ()
  "Does not re-stamp upgraded summaries after the file changes.
The strict per-session predicate still sees the entry as stale, but the
archive-wide queue keeps hash-versioned summaries usable without
rereading every transcript."
  (agent-log-test--with-temp-dir
    (let* ((old-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (new-content (concat old-content
                                "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"new work\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "s1.jsonl" old-content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (index (make-hash-table :test #'equal))
           (agent-log-rendered-directory agent-log-test--dir))
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (should (= (agent-log--upgrade-summary-index (list session) index) 1))
      (agent-log-test--write-file "s1.jsonl" new-content)
      (should (= (agent-log--upgrade-summary-index (list session) index) 0))
      (should-not (agent-log--session-summary-current-p
                   session (gethash "s1" index)))
      (should (agent-log--session-summary-usable-p (gethash "s1" index)))
      (should (null (agent-log--sessions-needing-summary
                     (list session) index))))))

(ert-deftest agent-log-test-summarize-next/preserves-v1-summary ()
  "Upgrades matching v1 summaries inside the timer-driven worker."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (agent-log--write-index index)
      (unwind-protect
          (let ((agent-log--summarize-active t)
                (agent-log--summarize-generation 7))
            (cl-letf (((symbol-function 'agent-log--summarize-one)
                       (lambda (&rest _)
                         (error "legacy summary should be preserved"))))
              (agent-log--summarize-next (list session) 0 1 7))
            (let ((entry (gethash "s1" (agent-log--read-index))))
              (should (equal (plist-get entry :summary-oneline) "A"))
              (should (agent-log--session-summary-current-p session entry))))
        (setq agent-log--summarize-active nil)))))

(ert-deftest agent-log-test-summarize-next/preserves-v2-summary ()
  "Preserves matching v2 summaries when only file-state metadata is stale."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (entry (agent-log-test--summary-entry (cdr session) "A"))
           (index (make-hash-table :test #'equal)))
      (plist-put entry :summary-jsonl-size 0)
      (puthash "s1" entry index)
      (agent-log--write-index index)
      (unwind-protect
          (let ((agent-log--summarize-active t)
                (agent-log--summarize-generation 7))
            (cl-letf (((symbol-function 'agent-log--summarize-one)
                       (lambda (&rest _)
                         (error "matching summary should be preserved"))))
              (agent-log--summarize-next (list session) 0 1 7))
            (let ((updated (gethash "s1" (agent-log--read-index))))
              (should (equal (plist-get updated :summary-oneline) "A"))
              (should (agent-log--session-summary-current-p session updated))))
        (setq agent-log--summarize-active nil)))))

(ert-deftest agent-log-test-summarize-sessions/startup-does-not-upgrade-v1 ()
  "Does not refresh stale summaries synchronously before scheduling work."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal))
           (orig-require (symbol-function 'require))
           (agent-log--summarize-active nil)
           scheduled)
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'require)
                 (lambda (feature &optional filename noerror)
                   (if (eq feature 'gptel)
                       t
                     (funcall orig-require feature filename noerror))))
                ((symbol-function 'agent-log--read-all-sessions)
                 (lambda () (list session)))
                ((symbol-function 'agent-log--upgrade-summary-index)
                 (lambda (&rest _)
                   (error "startup should not parse session transcripts")))
                ((symbol-function 'run-with-timer)
                 (lambda (&rest args)
                   (setq scheduled args))))
        (agent-log-summarize-sessions)
        (should scheduled)
        (should (= (nth 5 scheduled) 1))))))

(ert-deftest agent-log-test-summarize-sessions/startup-does-not-refresh-v2 ()
  "Does not rehash or schedule usable stale-file-state v2 summaries."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal))
           (orig-require (symbol-function 'require))
           (agent-log--summarize-active nil)
           (entry (agent-log-test--summary-entry (cdr session) "A"))
           scheduled)
      (plist-put entry :summary-jsonl-size -1)
      (puthash "s1" entry index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'require)
                 (lambda (feature &optional filename noerror)
                   (if (eq feature 'gptel)
                       t
                     (funcall orig-require feature filename noerror))))
                ((symbol-function 'agent-log--read-all-sessions)
                 (lambda () (list session)))
                ((symbol-function 'agent-log--upgrade-summary-index)
                 (lambda (&rest _)
                   (error "startup should not parse session transcripts")))
                ((symbol-function 'run-with-timer)
                 (lambda (&rest args)
                   (setq scheduled args))))
        (agent-log-summarize-sessions)
        (should-not scheduled)
        (should (agent-log--session-summary-usable-p
                 (gethash "s1" (agent-log--read-index))))
        (should-not (agent-log--session-summary-current-p
                     session (gethash "s1" (agent-log--read-index))))))))

(ert-deftest agent-log-test-summarize-sessions/no-hash-startup-stays-pending ()
  "Does not drop no-hash legacy summaries from the pending queue."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal))
           (orig-require (symbol-function 'require))
           scheduled)
      (puthash "s1" (list :summary "A" :summary-oneline "A") index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'require)
                 (lambda (feature &optional filename noerror)
                   (if (eq feature 'gptel)
                       t
                     (funcall orig-require feature filename noerror))))
                ((symbol-function 'agent-log--read-all-sessions)
                 (lambda () (list session)))
                ((symbol-function 'run-with-timer)
                 (lambda (&rest args)
                   (setq scheduled args))))
        (agent-log-summarize-sessions)
        (should scheduled)
        (should (= (nth 5 scheduled) 1))
        (should-not (agent-log--session-summary-current-p
                     session (gethash "s1" (agent-log--read-index))))))))

(ert-deftest agent-log-test-summarize-sessions/start-message-shows-archive-total ()
  "Reports pending updates separately from the archive size."
  (let ((sessions (list (list "s1") (list "s2") (list "s3")))
        (index (make-hash-table :test #'equal))
        (messages nil)
        (scheduled nil)
        (orig-require (symbol-function 'require))
        (agent-log--summarize-active nil)
        (agent-log--summarize-archive-total nil))
    (cl-letf (((symbol-function 'require)
               (lambda (feature &optional filename noerror)
                 (if (eq feature 'gptel)
                     t
                   (funcall orig-require feature filename noerror))))
              ((symbol-function 'agent-log--read-all-sessions)
               (lambda () sessions))
              ((symbol-function 'agent-log--read-index)
               (lambda () index))
              ((symbol-function 'agent-log--upgrade-summary-index)
               (lambda (&rest _) 0))
              ((symbol-function 'agent-log--sessions-needing-summary)
               (lambda (&rest _) (list (car sessions))))
              ((symbol-function 'run-with-timer)
               (lambda (&rest args) (setq scheduled args)))
              ((symbol-function 'message)
               (lambda (format-string &rest args)
                 (push (apply #'format-message format-string args)
                       messages))))
      (agent-log-summarize-sessions)
      (should scheduled)
      (should (= agent-log--summarize-archive-total 3))
      (should (string-match-p
               "1 pending summary update.*3 discovered session"
               (car messages))))))

(ert-deftest agent-log-test-auto-session-end-actions/targets-single-session ()
  "Auto session-end actions spawn a worker only for the identified session."
  (agent-log-test--with-temp-dir
    (let* ((agent-log--summary-workers (make-hash-table :test #'equal))
           (jsonl-path (agent-log-test--write-file
                        "s1.jsonl"
                        "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n"))
           command
           (agent-log-auto-sync-sessions nil)
           (agent-log-auto-summarize-sessions t)
           (agent-log-auto-rename-sessions t)
           (agent-log--summarize-active nil)
           (agent-log--summarize-blocked-reason nil))
      (cl-letf (((symbol-function 'agent-log--read-all-sessions)
                 (lambda ()
                   (ert-fail "automatic session-end action scanned archive")))
                ((symbol-function 'agent-log--find-session-file-any)
                 (lambda (sid)
                   (and (equal sid "s1") jsonl-path)))
                ((symbol-function 'agent-log--backend-for-file)
                 (lambda (&rest _) nil))
                ((symbol-function 'make-process)
                 (lambda (&rest args)
                   (setq command (plist-get args :command))
                   (make-symbol "process"))))
        (unwind-protect
            (progn
              (agent-log--auto-session-end-actions "s1")
              (should command)
              (should (member "--quick" command))
              (should (member "--batch" command))
              (let* ((state-file (cadr (member "--load" command)))
                     (state (and state-file
                                 (file-exists-p state-file)
                                 (with-temp-buffer
                                   (insert-file-contents state-file)
                                   (buffer-string)))))
                (should state)
                (should (string-match-p
                         "agent-log--batch-summarize-session \"s1\""
                         state))
                (should (string-match-p
                         "agent-log-auto-rename-sessions t"
                         state))
                (should-not (string-match-p "\"s2\"" state))))
          (when-let* ((state-file (cadr (member "--load" command))))
            (when (file-exists-p state-file)
              (delete-file state-file))))))))

(ert-deftest agent-log-test-auto-session-end-actions/unresolved-skips-archive ()
  "Unresolved automatic events skip quietly without archive-wide work."
  (let ((agent-log-auto-sync-sessions t)
        (agent-log-auto-summarize-sessions t)
        called
        messages)
    (cl-letf (((symbol-function 'agent-log-sync-sessions)
               (lambda (&rest _) (setq called 'sync)))
              ((symbol-function 'agent-log-summarize-sessions)
               (lambda (&rest _) (setq called 'summary)))
              ((symbol-function 'message)
               (lambda (&rest args) (push args messages))))
      (agent-log--auto-session-end-actions nil)
      (should-not called)
      (should-not messages))))

(ert-deftest agent-log-test-session-from-id-fast/derives-render-metadata ()
  "Fast session lookup returns metadata rich enough for rendering."
  (agent-log-test--with-temp-dir
    (let ((jsonl-path
           (agent-log-test--write-file
            "session.jsonl"
            (concat
             "{\"type\":\"progress\",\"cwd\":\"/Users/me/project\",\"timestamp\":\"2026-06-04T07:21:52Z\"}\n"
             "{\"type\":\"user\",\"timestamp\":\"2026-06-04T07:21:52Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello project\"}}\n"))))
      (cl-letf (((symbol-function 'agent-log--find-session-file-any)
                 (lambda (sid)
                   (and (equal sid "s1") jsonl-path)))
                ((symbol-function 'agent-log--backend-for-file)
                 (lambda (&rest _) agent-log-test--claude-backend)))
        (let ((session (agent-log--session-from-id-fast "s1")))
          (should (equal (car session) "s1"))
          (should (equal (plist-get (cdr session) :project)
                         "/Users/me/project"))
          (should (equal (plist-get (cdr session) :display)
                         "Hello project"))
          (should (numberp (plist-get (cdr session) :timestamp))))))))

(ert-deftest agent-log-test-auto-summary-sweep/spawns-background-worker ()
  "Automatic backlog sweeps start a batch worker, not a live archive scan."
  (let* ((agent-log--summary-workers (make-hash-table :test #'equal))
         (agent-log-auto-summarize-sessions t)
         (agent-log-auto-summarize-sweep-limit 7)
         (agent-log--summarize-active nil)
         (agent-log--summarize-blocked-reason nil)
         (orig-require (symbol-function 'require))
         command)
    (cl-letf (((symbol-function 'require)
               (lambda (feature &optional filename noerror)
                 (if (eq feature 'gptel)
                     t
                   (funcall orig-require feature filename noerror))))
              ((symbol-function 'agent-log--read-all-sessions)
               (lambda ()
                 (ert-fail "automatic sweep scanned archive in live Emacs")))
              ((symbol-function 'make-process)
               (lambda (&rest args)
                 (setq command (plist-get args :command))
                 (make-symbol "process"))))
      (unwind-protect
          (progn
            (agent-log--auto-summary-sweep)
            (should command)
            (should (member "--quick" command))
            (should (member "--batch" command))
            (let* ((state-file (cadr (member "--load" command)))
                   (state (and state-file
                               (file-exists-p state-file)
                               (with-temp-buffer
                                 (insert-file-contents state-file)
                                 (buffer-string)))))
              (should state)
              (should (string-match-p
                       "agent-log--batch-summarize-pending 7"
                       state))))
        (when-let* ((state-file (cadr (member "--load" command))))
          (when (file-exists-p state-file)
            (delete-file state-file)))))))

(ert-deftest agent-log-test-auto-summary-sweep/skips-duplicate-worker ()
  "Automatic backlog sweeps do not start overlapping sweep workers."
  (let ((agent-log--summary-workers (make-hash-table :test #'equal)))
    (puthash :sweep (cons 'process "/tmp/state.el")
             agent-log--summary-workers)
    (cl-letf (((symbol-function 'make-process)
               (lambda (&rest _)
                 (ert-fail "duplicate sweep worker started"))))
      (agent-log--spawn-summary-sweep-worker 5))))

(ert-deftest agent-log-test-batch-summarize-pending/limits-work ()
  "Batch backlog workers summarize only a bounded pending batch."
  (let* ((sessions (list (list "s1") (list "s2") (list "s3")))
         (index (make-hash-table :test #'equal))
         (orig-require (symbol-function 'require))
         captured)
    (cl-letf (((symbol-function 'require)
               (lambda (feature &optional filename noerror)
                 (if (eq feature 'gptel)
                     t
                   (funcall orig-require feature filename noerror))))
              ((symbol-function 'agent-log--read-all-sessions)
               (lambda () sessions))
              ((symbol-function 'agent-log--read-index)
               (lambda () index))
              ((symbol-function 'agent-log--sessions-needing-summary)
               (lambda (&rest _) sessions))
              ((symbol-function 'run-with-timer)
               (lambda (_secs _repeat fn &rest args)
                 (setq captured (cons fn args))
                 (setq agent-log--summarize-active nil))))
      (agent-log--batch-summarize-pending 2)
      (should (eq (car captured) #'agent-log--summarize-next))
      (should (= (length (cadr captured)) 2))
      (should (= (nth 3 captured) 2)))))

(ert-deftest agent-log-test-update-session-end-hook/adds-codex-hook ()
  "Installs the Codex event handler when automatic actions are enabled."
  (let ((codex-event-hook nil)
        (claude-code-event-hook nil)
        (agent-log-auto-sync-sessions nil)
        (agent-log-auto-summarize-sessions t))
    (agent-log--update-session-end-hook)
    (should (memq #'agent-log-codex--session-end-handler codex-event-hook))))

(ert-deftest agent-log-test-update-session-end-hook/adds-codex-identity-hook ()
  "Auto session-end setup must also record Codex session IDs.
If another package has reset `codex-event-hook', installing only the
Stop handler leaves automatic summaries unable to resolve the stopped
session."
  (let ((codex-event-hook '(agent-codex--handle-notification))
        (codex-start-hook nil)
        (claude-code-event-hook nil)
        (agent-log-auto-sync-sessions nil)
        (agent-log-auto-summarize-sessions t))
    (agent-log--update-session-end-hook)
    (should (memq #'agent-log-codex--session-event-handler
                  codex-event-hook))
    (should (memq #'agent-log-codex--session-end-handler
                  codex-event-hook))
    (should (memq #'agent-log-codex--clear-buffer-session
                  codex-start-hook))))

(ert-deftest agent-log-test-codex-session-id-from-event ()
  "Resolves a Codex Stop event buffer to its session ID."
  (let ((file "/tmp/rollout-2026-05-10-12345678-1234-1234-1234-123456789abc.jsonl"))
    (with-temp-buffer
      (rename-buffer " *agent-log-codex-test*" t)
      (cl-letf (((symbol-function 'agent-log-codex--buffer-session-file)
                 (lambda (&rest _) file))
                ((symbol-function 'agent-log--read-sessions)
                 (lambda (&rest _) nil)))
        (should (equal
                 (agent-log-codex--session-id-from-event
                  (list :type "Stop" :buffer-name (buffer-name)))
                 "12345678-1234-1234-1234-123456789abc"))))))

(ert-deftest agent-log-test-summarize-one/progress-message-shows-archive-total ()
  "Reports pending progress without implying it is the archive size."
  (let ((messages nil)
        (requested nil)
        (agent-log--summarize-archive-total 2571))
    (cl-letf (((symbol-function 'agent-log--resolve-summary-backend-and-model)
               (lambda () (cons nil "test-model")))
              ((symbol-function 'gptel-request)
               (lambda (&rest _) (setq requested t)))
              ((symbol-function 'message)
               (lambda (format-string &rest args)
                 (push (apply #'format-message format-string args)
                       messages))))
      (agent-log--summarize-one
       "s1" '(:display "Example session") "User: hello" "hash"
       '(1 . 2) nil 0 20 7)
      (should requested)
      (should (string-match-p
               "pending update 1/20 (archive: 2571 sessions)"
               (car messages))))))

(ert-deftest agent-log-test-search/startup-does-not-upgrade-v1 ()
  "Does not refresh legacy summaries synchronously before search."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :timestamp 1
                          :project "/tmp/project"
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal))
           (orig-require (symbol-function 'require)))
      (puthash "s1" (agent-log-test--legacy-summary-entry
                     (cdr session) "A")
               index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'require)
                 (lambda (feature &optional filename noerror)
                   (if (eq feature 'gptel)
                       t
                     (funcall orig-require feature filename noerror))))
                ((symbol-function 'agent-log--read-all-sessions)
                 (lambda () (list session)))
                ((symbol-function 'agent-log--resolve-search-scope-backend-and-model)
                 (lambda () (cons nil "test-model")))
                ((symbol-function 'gptel-request)
                 (lambda (&rest _)
                   (error "search should not request when no current summaries exist"))))
        (should-error (agent-log-search "anything")
                      :type 'user-error)
        (should-not (agent-log--session-summary-current-p
                     session (gethash "s1" (agent-log--read-index))))))))

(ert-deftest agent-log-test-search/startup-does-not-refresh-v2 ()
  "Search uses stale-file-state v2 summaries without synchronous rehashing."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content))
           (session (list "s1" :file jsonl-path
                          :timestamp 1
                          :project "/tmp/project"
                          :backend agent-log-test--claude-backend))
           (agent-log-rendered-directory agent-log-test--dir)
           (index (make-hash-table :test #'equal))
           (orig-require (symbol-function 'require))
           (requested nil)
           (entry (agent-log-test--summary-entry (cdr session) "A")))
      (plist-put entry :summary-jsonl-size -1)
      (puthash "s1" entry index)
      (agent-log--write-index index)
      (cl-letf (((symbol-function 'require)
                 (lambda (feature &optional filename noerror)
                   (if (eq feature 'gptel)
                       t
                     (funcall orig-require feature filename noerror))))
                ((symbol-function 'agent-log--read-all-sessions)
                 (lambda () (list session)))
                ((symbol-function 'agent-log--resolve-search-scope-backend-and-model)
                 (lambda () (cons nil "test-model")))
                ((symbol-function 'gptel-request)
                 (lambda (&rest _)
                   (setq requested t))))
        (agent-log-search "anything")
        (should requested)
        (should-not (agent-log--session-summary-current-p
                     session (gethash "s1" (agent-log--read-index))))
        (should (agent-log--session-summary-usable-p
                 (gethash "s1" (agent-log--read-index))))))))

;;;;; Search metadata

(ert-deftest agent-log-test-search-gather-metadata/legacy-summary ()
  "Counts legacy summaries separately from searchable current summaries."
  (agent-log-test--with-temp-dir
    (cl-letf (((symbol-function 'agent-log--active-backend-instances)
               (lambda () nil)))
      (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
             (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
             (session (list "s1" :file jsonl-path
                            :backend agent-log-test--claude-backend
                            :timestamp 1700000000000
                            :project "/tmp/project"))
             (index (make-hash-table :test #'equal)))
        (puthash "s1" (list :summary "Old summary"
                            :summary-oneline "Old summary")
                 index)
        (let ((metadata (agent-log--search-gather-metadata
                         (list session) index)))
          (should (= (plist-get metadata :summarized) 0))
          (should (= (plist-get metadata :unsummarized) 1))
          (should (= (plist-get metadata :legacy-summaries) 1))
          (should (= (plist-get metadata :empty-summaries) 0)))))))

(ert-deftest agent-log-test-search-gather-metadata/current-empty-summary ()
  "Counts current empty-session markers without treating them as unsummarized."
  (agent-log-test--with-temp-dir
    (cl-letf (((symbol-function 'agent-log--active-backend-instances)
               (lambda () nil)))
      (let* ((jsonl-path (agent-log-test--write-file "s1.jsonl" ""))
             (session (list "s1" :file jsonl-path
                            :backend agent-log-test--claude-backend
                            :timestamp 1700000000000
                            :project "/tmp/project"))
             (index (make-hash-table :test #'equal)))
        (puthash "s1" (agent-log-test--summary-entry
                       (cdr session) agent-log--no-conversation-sentinel)
                 index)
        (let ((metadata (agent-log--search-gather-metadata
                         (list session) index)))
          (should (= (plist-get metadata :summarized) 0))
          (should (= (plist-get metadata :unsummarized) 0))
          (should (= (plist-get metadata :legacy-summaries) 0))
          (should (= (plist-get metadata :empty-summaries) 1)))))))

(ert-deftest agent-log-test-search-gather-metadata/stale-file-state-usable ()
  "Counts hash-versioned summaries as usable despite stale file metadata."
  (agent-log-test--with-temp-dir
    (cl-letf (((symbol-function 'agent-log--active-backend-instances)
               (lambda () nil)))
      (let* ((jsonl-content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
             (jsonl-path (agent-log-test--write-file "s1.jsonl" jsonl-content))
             (session (list "s1" :file jsonl-path
                            :backend agent-log-test--claude-backend
                            :timestamp 1700000000000
                            :project "/tmp/project"))
             (index (make-hash-table :test #'equal))
             (entry (agent-log-test--summary-entry (cdr session) "A")))
        (plist-put entry :summary-jsonl-size -1)
        (puthash "s1" entry index)
        (let ((metadata (agent-log--search-gather-metadata
                         (list session) index)))
          (should (= (plist-get metadata :summarized) 1))
          (should (= (plist-get metadata :unsummarized) 0))
          (should (= (plist-get metadata :legacy-summaries) 0))
          (should (= (plist-get metadata :empty-summaries) 0)))))))

(ert-deftest agent-log-test-search-apply-scope/excludes-active-sessions ()
  "Uses the same active-session exclusion as search metadata."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
           (s1-path (agent-log-test--write-file "s1.jsonl" content))
           (s2-path (agent-log-test--write-file "s2.jsonl" content))
           (s1 (list "s1" :file s1-path
                     :backend agent-log-test--claude-backend
                     :timestamp 1700000000000
                     :project "/tmp/project"))
           (s2 (list "s2" :file s2-path
                     :backend agent-log-test--claude-backend
                     :timestamp 1700000001000
                     :project "/tmp/project"))
           (sessions (list s1 s2))
           (index (make-hash-table :test #'equal))
           (scope (list :projects "all" :date-after nil :date-before nil)))
      (puthash "s1" (agent-log-test--summary-entry (cdr s1) "Active") index)
      (puthash "s2" (agent-log-test--summary-entry (cdr s2) "Inactive") index)
      (cl-letf (((symbol-function 'agent-log--active-backend-instances)
                 (lambda () (list agent-log-test--claude-backend)))
                ((symbol-function 'agent-log--active-session-ids)
                 (lambda (_backend) '("s1"))))
        (let ((metadata (agent-log--search-gather-metadata sessions index))
              (filtered (agent-log--search-apply-scope sessions index scope)))
          (should (= (plist-get metadata :summarized) 1))
          (should (equal (mapcar #'car filtered) '("s2"))))))))

(ert-deftest agent-log-test-search-no-summaries-message/legacy ()
  "Explains that legacy summaries need refreshing."
  (let ((message (agent-log--search-no-summaries-message
                  (list :legacy-summaries 2 :empty-summaries 0))))
    (should (string-match-p "predate freshness tracking" message))
    (should (string-match-p "agent-log-summarize-sessions" message))))

(ert-deftest agent-log-test-search/does-not-upgrade-before-metadata ()
  "AI search does not refresh summary fingerprints on the UI path."
  (let ((sessions nil)
        (index (make-hash-table :test #'equal))
        (orig-require (symbol-function 'require)))
    (cl-letf (((symbol-function 'require)
               (lambda (feature &optional filename noerror)
                 (if (eq feature 'gptel)
                     t
                   (funcall orig-require feature filename noerror))))
              ((symbol-function 'agent-log--read-all-sessions)
               (lambda () sessions))
              ((symbol-function 'agent-log--read-index)
               (lambda () index))
              ((symbol-function 'agent-log--upgrade-summary-index)
               (lambda (&rest _)
                 (error "search should not parse session transcripts"))))
      (should-error (agent-log-search "hello")
                    :type 'user-error))))

;;;;; Claude session titles

(ert-deftest agent-log-test-claude-latest-custom-title ()
  "Finds the latest custom-title entry in a Claude JSONL file."
  (agent-log-test--with-temp-dir
    (let* ((content (concat "{\"type\":\"custom-title\",\"customTitle\":\"Old\",\"sessionId\":\"s1\"}\n"
                            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"continued\"}}\n"
                            "{\"type\":\"custom-title\",\"customTitle\":\"New\",\"sessionId\":\"s1\"}\n"))
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content)))
      (should (equal (agent-log-claude--latest-custom-title jsonl-path)
                     "New")))))

(ert-deftest agent-log-test-claude-should-write-summary-title ()
  "Updates a title only when it matches the previous summary."
  (agent-log-test--with-temp-dir
    (let* ((content "{\"type\":\"custom-title\",\"customTitle\":\"Old summary\",\"sessionId\":\"s1\"}\n")
           (jsonl-path (agent-log-test--write-file "s1.jsonl" content)))
      (should (agent-log-claude--should-write-summary-title-p
               jsonl-path "Old summary"))
      (should-not (agent-log-claude--should-write-summary-title-p
                   jsonl-path "Different summary")))))

;;;;; Outline level

(ert-deftest agent-log-test-outline-level ()
  "Returns correct outline level based on # count."
  (with-temp-buffer
    (insert "## Heading\n")
    (goto-char (point-min))
    (looking-at "##+ ")
    (should (= (agent-log--outline-level) 2)))
  (with-temp-buffer
    (insert "#### Sub-heading\n")
    (goto-char (point-min))
    (looking-at "##+ ")
    (should (= (agent-log--outline-level) 4))))

;;;;; Extract session ID from buffer

(ert-deftest agent-log-test-extract-session-id-from-buffer ()
  "Extracts session ID from front matter."
  (with-temp-buffer
    (insert "<!-- session: abc-def-123 -->\n<!-- source: /tmp/test.jsonl -->\n")
    (should (equal (agent-log--extract-session-id-from-buffer) "abc-def-123"))))

(ert-deftest agent-log-test-extract-session-id-from-buffer/not-found ()
  "Returns nil when no session ID in buffer."
  (with-temp-buffer
    (insert "No front matter here\n")
    (should (null (agent-log--extract-session-id-from-buffer)))))

(ert-deftest agent-log-test-extract-source-file-from-buffer ()
  "Extracts source JSONL path from front matter."
  (with-temp-buffer
    (insert "<!-- session: abc-def-123 -->\n")
    (insert "<!-- source: /tmp/test.jsonl -->\n")
    (should (equal (agent-log--extract-source-file-from-buffer)
                   "/tmp/test.jsonl"))))

(ert-deftest agent-log-test-resume-session/hydrates-direct-rendered-buffer ()
  "Resumes direct-opened rendered logs using front matter."
  (agent-log-test--with-temp-dir
    (let* ((project-dir (expand-file-name "project" agent-log-test--dir))
           (jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (format "{\"type\":\"progress\",\"cwd\":%S}\n"
                                project-dir)))
           (backend (agent-log--make-claude
                     :name "Claude Code"
                     :key 'claude-code
                     :directory agent-log-test--dir))
           called)
      (make-directory project-dir t)
      (with-temp-buffer
        (insert "<!-- session: abc-def-123 -->\n")
        (insert (format "<!-- source: %s -->\n" jsonl-path))
        (cl-letf (((symbol-function 'agent-log--active-backend-instances)
                   (lambda () (list backend)))
                  ((symbol-function 'agent-log--resume-session)
                   (lambda (actual-backend session-id)
                     (setq called (list actual-backend session-id
                                        agent-log--session-project)))))
          (agent-log-resume-session))
        (should (equal called (list backend "abc-def-123" project-dir)))
        (should (eq agent-log--backend backend))
        (should (equal agent-log--source-file jsonl-path))))))

(ert-deftest agent-log-test-resume-session/claude-source-fallback-directory ()
  "Starts Claude in the source-derived project when history is stale."
  (agent-log-test--with-temp-dir
    (let* ((project-dir (expand-file-name "My Drive/repos/ta65"
                                          agent-log-test--dir))
           (encoded (agent-log-claude--encode-project-path project-dir))
           (claude-dir (expand-file-name ".claude" agent-log-test--dir))
           (jsonl-path (agent-log-test--write-file
                        (format ".claude/projects/%s/s1.jsonl" encoded)
                        ""))
           (history-path (agent-log-test--write-file
                          ".claude/history.jsonl"
                          "{\"sessionId\":\"s1\",\"project\":\"/missing\"}\n"))
           (backend (agent-log--make-claude
                     :name "Claude Code"
                     :key 'claude-code
                     :directory claude-dir))
           (agent-log-directory (file-name-directory history-path))
           (orig-require (symbol-function 'require))
           called)
      (make-directory project-dir t)
      (with-temp-buffer
        (insert "<!-- session: s1 -->\n")
        (insert (format "<!-- source: %s -->\n" jsonl-path))
        (cl-letf (((symbol-function 'agent-log--active-backend-instances)
                   (lambda () (list backend)))
                  ((symbol-function 'agent-log-claude--find-existing-encoded-project)
                   (lambda (actual-encoded)
                     (and (equal actual-encoded encoded) project-dir)))
                  ((symbol-function 'require)
                   (lambda (feature &optional filename noerror)
                     (if (eq feature 'claude-code)
                         t
                       (funcall orig-require feature filename noerror))))
                  ((symbol-function 'claude-code--start)
                   (lambda (&rest args)
                     (setq called (list args (claude-code--directory)))))
                  ((symbol-function 'claude-code--directory)
                   (lambda () default-directory)))
          (agent-log-resume-session))
        (should (equal called
                       (list (list nil (list "--resume" "s1"))
                             (file-name-as-directory project-dir))))))))

;;;;; Ensure rendered (integration)

(ert-deftest agent-log-test-ensure-rendered/first-time ()
  "Creates rendered file on first call."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-content
            (concat
             "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\","
             "\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n"))
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (metadata (list :file jsonl-path :timestamp 1700000000000
                           :project "/project" :display "hi"))
           (result (agent-log--ensure-rendered "s1" metadata)))
      (should (file-exists-p result))
      (let ((content (with-temp-buffer
                       (insert-file-contents result)
                       (buffer-string))))
        (should (string-match-p "## User" content))))))

(ert-deftest agent-log-test-ensure-rendered/cached ()
  "Returns cached path when file is up-to-date."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-content "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n")
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (metadata (list :file jsonl-path :timestamp 1700000000000
                           :project "/project" :display "hi")))
      ;; First call — renders
      (let ((path1 (agent-log--ensure-rendered "s1" metadata)))
        ;; Modify the rendered file content so we can detect if it gets re-rendered
        (with-temp-file path1
          (insert "MARKER: original render"))
        ;; Second call — should use cache (same jsonl size)
        (let ((path2 (agent-log--ensure-rendered "s1" metadata)))
          (should (equal path1 path2))
          ;; Content should still be our marker (not re-rendered)
          (let ((content (with-temp-buffer
                           (insert-file-contents path2)
                           (buffer-string))))
            (should (string-match-p "MARKER: original render" content))))))))

(ert-deftest agent-log-test-ensure-rendered/path-change-rerenders ()
  "Re-renders when metadata implies a better rendered path."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-rendered-directory
            (expand-file-name "rendered" agent-log-test--dir))
           (jsonl-content "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n")
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (old-metadata (list :file jsonl-path :timestamp 1700000000000
                               :project "/project" :display "old"))
           (new-metadata (list :file jsonl-path :timestamp 1700000000000
                               :project "/project" :display "hi"))
           (path1 (agent-log--ensure-rendered "s1" old-metadata))
           (path2 (agent-log--ensure-rendered "s1" new-metadata)))
      (should-not (equal path1 path2))
      (should (string-match-p "hi\\.md\\'" path2))
      (should (file-exists-p path2)))))

;;;;; Incremental text processing

(ert-deftest agent-log-test-process-incremental-text/complete-lines ()
  "Processes complete JSONL lines."
  (with-temp-buffer
    (agent-log-mode)
    (let ((agent-log--partial-line "")
          (agent-log--backend agent-log-test--claude-backend)
          (agent-log--source-file nil)
          (agent-log--rendered-file nil)
          (inhibit-read-only t))
      (insert "# Session: test — unknown\n\n")
      ;; Process a complete user entry line
      (agent-log--process-incremental-text
       (concat "{\"type\":\"user\",\"timestamp\":\"2023-11-14T12:00:00Z\","
               "\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
       nil)
      (should (string-match-p "## User" (buffer-string)))
      (should (string-match-p "hello" (buffer-string))))))

(ert-deftest agent-log-test-process-incremental-text/partial-line-saved ()
  "Saves incomplete line for next call."
  (with-temp-buffer
    (agent-log-mode)
    (let ((agent-log--partial-line "")
          (agent-log--source-file nil)
          (agent-log--rendered-file nil))
      (agent-log--process-incremental-text
       "{\"type\":\"user\",\"partial" nil)
      ;; Partial line should be saved
      (should (equal agent-log--partial-line "{\"type\":\"user\",\"partial")))))

(ert-deftest agent-log-test-process-incremental-text/partial-line-completed ()
  "Completes a previously partial line."
  (with-temp-buffer
    (agent-log-mode)
    (let ((agent-log--partial-line "{\"type\":\"us")
          (agent-log--backend agent-log-test--claude-backend)
          (agent-log--source-file nil)
          (agent-log--rendered-file nil)
          (inhibit-read-only t))
      (insert "# Session: test — unknown\n\n")
      ;; Complete the partial line
      (agent-log--process-incremental-text
       (concat "er\",\"timestamp\":\"2023-11-14T12:00:00Z\","
               "\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n")
       nil)
      (should (string-match-p "hello" (buffer-string))))))

;;;;; Pending sessions

(ert-deftest agent-log-test-pending-sessions/unrendered ()
  "Detects sessions not in the index."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\"}\n")
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (sessions (list (list "s1" :file jsonl-path)))
           (index (make-hash-table :test #'equal))
           (pending (agent-log--pending-sessions sessions index)))
      (should (= (length pending) 1)))))

(ert-deftest agent-log-test-pending-sessions/up-to-date ()
  "Detects up-to-date sessions."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\"}\n")
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (jsonl-size (file-attribute-size (file-attributes jsonl-path)))
           (rendered-path (agent-log-test--write-file "rendered.md" "rendered"))
           (sessions (list (list "s1" :file jsonl-path)))
           (index (make-hash-table :test #'equal)))
      (puthash "s1" (list :file rendered-path :jsonl-size jsonl-size) index)
      (let ((pending (agent-log--pending-sessions sessions index)))
        (should (= (length pending) 0))))))

(ert-deftest agent-log-test-pending-sessions/stale ()
  "Detects sessions where JSONL has grown since rendering."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content "{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n")
           (jsonl-path (agent-log-test--write-file "test.jsonl" jsonl-content))
           (rendered-path (agent-log-test--write-file "rendered.md" "rendered"))
           (sessions (list (list "s1" :file jsonl-path)))
           (index (make-hash-table :test #'equal)))
      ;; Index claims smaller size than actual
      (puthash "s1" (list :file rendered-path :jsonl-size 10) index)
      (let ((pending (agent-log--pending-sessions sessions index)))
        (should (= (length pending) 1))))))

;;;;; Append to file

(ert-deftest agent-log-test-append-to-file ()
  "Appends text to a file."
  (agent-log-test--with-temp-dir
    (let ((path (expand-file-name "test.md" agent-log-test--dir)))
      (with-temp-file path (insert "first\n"))
      (agent-log--append-to-file path "second\n")
      (let ((content (with-temp-buffer
                       (insert-file-contents path)
                       (buffer-string))))
        (should (equal content "first\nsecond\n"))))))

;;;;; Preserve order table

(ert-deftest agent-log-test-preserve-order-table/metadata ()
  "Returns metadata with identity sort functions."
  (let ((table (agent-log--preserve-order-table '("a" "b" "c"))))
    (let ((meta (funcall table "" nil 'metadata)))
      (should (equal (car meta) 'metadata))
      (should (assq 'display-sort-function (cdr meta)))
      (should (assq 'cycle-sort-function (cdr meta))))))

;;;;; Completion candidates

(ert-deftest agent-log-test-build-candidates/includes-session-size ()
  "Includes a human-readable session file size column."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (make-string 2048 ?x)))
           (sessions (list (list "s1"
                                  :file jsonl-path
                                  :timestamp nil
                                  :project "/tmp/project"
                                  :display "Hello"))))
      (cl-letf (((symbol-function 'agent-log--read-index)
                 (lambda () (make-hash-table :test #'equal)))
                ((symbol-function 'image-type-available-p)
                 (lambda (_type) nil))
                ((symbol-function 'frame-width)
                 (lambda (&optional _frame) 100)))
        (should (string-match-p
                 (rx "unknown" (+ space) "project" (+ space) "2k"
                     (+ space) "\"Hello\"")
                 (caar (agent-log--build-candidates sessions))))))))

(ert-deftest agent-log-test-build-candidates/caches-session-size ()
  "Reads source file metadata once per session while building candidates."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-path (agent-log-test--write-file
                        "session.jsonl"
                        (make-string 2048 ?x)))
           (sessions (list (list "s1"
                                  :file jsonl-path
                                  :timestamp nil
                                  :project "/tmp/project"
                                  :display "Hello")))
           (orig-file-attributes (symbol-function 'file-attributes))
           (calls 0))
      (cl-letf (((symbol-function 'agent-log--read-index)
                 (lambda () (make-hash-table :test #'equal)))
                ((symbol-function 'image-type-available-p)
                 (lambda (_type) nil))
                ((symbol-function 'frame-width)
                 (lambda (&optional _frame) 100))
                ((symbol-function 'file-attributes)
                 (lambda (&rest args)
                   (cl-incf calls)
                   (apply orig-file-attributes args))))
        (agent-log--build-candidates sessions)
        (should (= calls 1))))))

;;;;; Claude current-buffer session detection

(ert-deftest agent-log-test-claude-current-buffer-session-file/visible-text ()
  "Matches visible Claude terminal text before the project mtime fallback."
  (agent-log-test--with-temp-dir
    (let* ((dir "/tmp/project")
           (line "Now let me read the remaining affected files")
           (current-file (agent-log-test--write-file
                          "claude-project/current.jsonl"
                          (format
                           "{\"message\":{\"content\":\"%s\"}}\n"
                           line)))
           (latest-file (agent-log-test--write-file
                         "claude-project/latest.jsonl"
                         "{\"message\":{\"content\":\"unrelated newer session\"}}\n"))
           (session-dir (file-name-directory current-file)))
      (set-file-times current-file (seconds-to-time 100))
      (set-file-times latest-file (seconds-to-time 200))
      (with-temp-buffer
        (insert "⏺ " line "\n")
        (cl-letf (((symbol-function 'agent-log-claude--read-status-file)
                   (lambda () nil))
                  ((symbol-function 'claude-code--extract-directory-from-buffer-name)
                   (lambda (_buffer-name) dir))
                  ((symbol-function 'agent-log-claude--find-project-session-dir)
                   (lambda (_directory) session-dir)))
          (should (equal (agent-log--current-buffer-session-file
                          agent-log-test--claude-backend)
                         current-file)))))))

(ert-deftest agent-log-test-claude-current-buffer-session-file/visible-text-score ()
  "Uses combined visible Claude snippets when no single line is unique."
  (agent-log-test--with-temp-dir
    (let* ((dir "/tmp/project")
           (line-a "shared patch hunk about writing moves.json with UTF-8 encoding")
           (line-b "shared patch hunk about writing moves-summary with UTF-8 encoding")
           (current-file (agent-log-test--write-file
                          "claude-project/current.jsonl"
                          (format "%s\n%s\n" line-a line-b)))
           (other-a-file (agent-log-test--write-file
                          "claude-project/other-a.jsonl"
                          (concat line-a "\n")))
           (other-b-file (agent-log-test--write-file
                          "claude-project/other-b.jsonl"
                          (concat line-b "\n")))
           (latest-file (agent-log-test--write-file
                         "claude-project/latest.jsonl"
                         "unrelated newer session\n"))
           (session-dir (file-name-directory current-file)))
      (set-file-times current-file (seconds-to-time 100))
      (set-file-times other-a-file (seconds-to-time 150))
      (set-file-times other-b-file (seconds-to-time 175))
      (set-file-times latest-file (seconds-to-time 200))
      (with-temp-buffer
        (insert line-a "\n" line-b "\n")
        (cl-letf (((symbol-function 'agent-log-claude--read-status-file)
                   (lambda () nil))
                  ((symbol-function 'claude-code--extract-directory-from-buffer-name)
                   (lambda (_buffer-name) dir))
                  ((symbol-function 'agent-log-claude--find-project-session-dir)
                   (lambda (_directory) session-dir)))
          (should (equal (agent-log--current-buffer-session-file
                          agent-log-test--claude-backend)
                         current-file)))))))

(ert-deftest agent-log-test-claude-current-buffer-session-file/short-assistant-line ()
  "Uses short Claude assistant prompt lines as visible session evidence."
  (agent-log-test--with-temp-dir
    (let* ((dir "/tmp/project")
           (line "Now gather.py encoding fixes:")
           (current-file (agent-log-test--write-file
                          "claude-project/current.jsonl"
                          (concat line "\n")))
           (latest-file (agent-log-test--write-file
                         "claude-project/latest.jsonl"
                         "unrelated newer session\n"))
           (session-dir (file-name-directory current-file)))
      (set-file-times current-file (seconds-to-time 100))
      (set-file-times latest-file (seconds-to-time 200))
      (with-temp-buffer
        (insert "⏵⏵ auto mode on (shift+tab to cycle) · ← for agents\n")
        (insert "⏺ " line "\n")
        (cl-letf (((symbol-function 'agent-log-claude--read-status-file)
                   (lambda () nil))
                  ((symbol-function 'claude-code--extract-directory-from-buffer-name)
                   (lambda (_buffer-name) dir))
                  ((symbol-function 'agent-log-claude--find-project-session-dir)
                   (lambda (_directory) session-dir)))
          (should (equal (agent-log--current-buffer-session-file
                          agent-log-test--claude-backend)
                         current-file)))))))

;;;;; Codex backend

(require 'agent-log-codex)

(defvar codex-terminal-backend)

(defvar agent-log-test--codex-backend agent-log-codex--instance
  "Codex backend instance for use in tests.")

;;;;;; Session discovery

(ert-deftest agent-log-test-codex-read-sessions/reuses-metadata-cache ()
  "Does not reread unchanged Codex transcripts after metadata is cached."
  (agent-log-test--with-temp-dir
    (let* ((sid "019df82b-8607-7231-a491-e57316e4fa02")
           (jsonl-path
            (agent-log-test--write-file
             (concat "sessions/2026/05/06/rollout-2026-05-06T00-00-00-"
                     sid ".jsonl")
             (concat
              "{\"type\":\"session_meta\","
              "\"timestamp\":\"2026-05-06T00:00:00Z\","
              "\"payload\":{\"id\":\"" sid "\","
              "\"cwd\":\"/tmp/project\","
              "\"timestamp\":\"2026-05-06T00:00:00Z\","
              "\"source\":\"cli\"}}\n"
              "{\"type\":\"response_item\"}\n")))
           (backend
            (agent-log--make-codex
             :name "Codex"
             :key 'codex
             :directory agent-log-test--dir
             :rendered-directory (expand-file-name "rendered"
                                                   agent-log-test--dir)))
           (orig-insert-file-contents
            (symbol-function 'insert-file-contents))
           (transcript-reads 0))
      (agent-log-test--write-file
       "history.jsonl"
       (concat "{\"session_id\":\"" sid
               "\",\"ts\":1778025600,\"text\":\"Hello\"}\n"))
      (agent-log--read-sessions backend)
      (cl-letf (((symbol-function 'insert-file-contents)
                 (lambda (filename &rest args)
                   (when (equal (expand-file-name filename) jsonl-path)
                     (cl-incf transcript-reads))
                   (apply orig-insert-file-contents filename args))))
        (let ((sessions (agent-log--read-sessions backend)))
          (should (= (length sessions) 1))
          (should (equal (plist-get (cdar sessions) :project)
                         "/tmp/project"))
          (should (= transcript-reads 0)))))))

(ert-deftest agent-log-test-codex-resume-session/app-server ()
  "Resumes Codex logs through app-server when app-server is the active backend."
  (let ((codex-terminal-backend 'app-server)
        (agent-log--session-project "/tmp/project/")
        called)
    (cl-letf (((symbol-function 'require)
               (lambda (feature &optional _filename _noerror)
                 (eq feature 'codex)))
              ((symbol-function 'codex--app-server-launch-resume-session)
               (lambda (session-id)
                 (setq called session-id)))
              ((symbol-function 'codex--start-subcommand)
               (lambda (&rest _)
                 (ert-fail "app-server resume should not use terminal subcommand"))))
      (agent-log--resume-session agent-log-test--codex-backend "sid-123"))
    (should (equal called "sid-123"))))

(ert-deftest agent-log-test-codex-find-session-for-project/allows-subagent ()
  "Finds the newest matching Codex session by default."
  (let* ((dir "/tmp/project")
         (sessions
          `(("child" :project ,dir :timestamp 2000
             :source (:subagent (:thread_spawn (:parent_thread_id "parent"))))
            ("parent" :project ,dir :timestamp 1000 :source "cli"))))
    (should (equal (car (agent-log-codex--find-session-for-project
                         dir sessions))
                   "child"))))

(ert-deftest agent-log-test-codex-find-session-for-project/top-level-only ()
  "Ignores subagents when resolving the session for a live terminal buffer."
  (let* ((dir "/tmp/project")
         (sessions
          `(("child" :project ,dir :timestamp 2000
             :source (:subagent (:thread_spawn (:parent_thread_id "parent"))))
            ("parent" :project ,dir :timestamp 1000 :source "cli"))))
    (should (equal (car (agent-log-codex--find-session-for-project
                         dir sessions t))
                   "parent"))))

(ert-deftest agent-log-test-codex-find-session-for-project/process-start ()
  "Uses process start time to distinguish top-level sessions in one project."
  (let* ((dir "/tmp/project")
         (sessions
          `(("newer" :project ,dir :timestamp 200000 :source "cli")
            ("older" :project ,dir :timestamp 100000 :source "cli"))))
    (should (equal (car (agent-log-codex--find-session-for-project
                         dir sessions t 101000))
                   "older"))))

(ert-deftest agent-log-test-codex-find-session-for-project/process-start-miss ()
  "Returns nil instead of an unrelated stale session when launch times miss."
  (let* ((dir "/tmp/project")
         (sessions `(("old" :project ,dir :timestamp 100000 :source "cli"))))
    (should-not (agent-log-codex--find-session-for-project
                 dir sessions t (+ 100000
                                   agent-log-codex--session-start-match-window-ms
                                   1)))))

(ert-deftest agent-log-test-codex-resumed-session-id-from-command ()
  "Extracts an explicit session ID from a Codex resume command."
  (let ((sid "019df82b-8607-7231-a491-e57316e4fa02"))
    (should (equal (agent-log-codex--resumed-session-id-from-command
                    (list "/usr/bin/env" "sh" "-c" "exec \"$@\""
                          ".." "codex" "--no-alt-screen" "resume" sid))
                   sid))))

(ert-deftest agent-log-test-codex-resumed-session-id-from-command/last ()
  "Returns nil for resume commands that do not name a session ID."
  (should-not (agent-log-codex--resumed-session-id-from-command
               '("codex" "--no-alt-screen" "resume" "--last"))))

(ert-deftest agent-log-test-codex-current-buffer-session-file/resume-id ()
  "Uses an explicit resumed session ID before heuristic matching."
  (let ((sid "019df82b-8607-7231-a491-e57316e4fa02")
        (file "/tmp/resumed.jsonl"))
    (with-temp-buffer
      (cl-letf (((symbol-function 'agent-log-codex--buffer-resumed-session-id)
                 (lambda () sid))
                ((symbol-function 'agent-log--find-session-file)
                 (lambda (_backend session-id)
                   (and (equal session-id sid) file)))
                ((symbol-function 'codex--buffer-directory-for)
                 (lambda (_buffer)
                   (error "heuristic lookup should not run"))))
        (should (equal (agent-log--current-buffer-session-file
                        agent-log-test--codex-backend)
                       file))))))

(ert-deftest agent-log-test-codex-current-buffer-session-file/recorded-id ()
  "Uses the buffer-local Codex session ID before heuristic matching."
  (let ((sid "019df82b-8607-7231-a491-e57316e4fa02")
        (file "/tmp/recorded.jsonl"))
    (with-temp-buffer
      (setq-local agent-log-codex--buffer-session-id sid)
      (cl-letf (((symbol-function 'agent-log--find-session-file)
                 (lambda (_backend session-id)
                   (and (equal session-id sid) file)))
                ((symbol-function 'agent-log-codex--buffer-resumed-session-id)
                 (lambda ()
                   (ert-fail "resume lookup should not run"))))
        (should (equal (agent-log-codex--buffer-session-file
                        agent-log-test--codex-backend nil)
                       file))))))

(ert-deftest agent-log-test-codex-current-buffer-session-file/visible-text ()
  "Matches the visible terminal transcript to the owning JSONL file."
  (let ((dir "/tmp/project")
        (line "Main project-note scan is clean for legacy Open action items from meetings")
        (file-a (make-temp-file "agent-log-codex-a" nil ".jsonl"))
        (file-b (make-temp-file "agent-log-codex-b" nil ".jsonl")))
    (unwind-protect
        (let ((sessions `(("b" :project ,dir :timestamp 200 :source "cli"
                           :file ,file-b)
                          ("a" :project ,dir :timestamp 100 :source "cli"
                           :file ,file-a))))
          (with-temp-file file-a
            (insert "{\"type\":\"response_item\",\"payload\":{\"content\":\"other\"}}\n"))
          (with-temp-file file-b
            (insert "{\"type\":\"response_item\",\"payload\":{\"content\":\""
                    line "\"}}\n"))
          (with-temp-buffer
            (insert "  - " line "\n\n› Explain this codebase\n")
            (cl-letf (((symbol-function 'agent-log-codex--buffer-resumed-session-id)
                       (lambda () nil))
                      ((symbol-function 'agent-log-codex--buffer-process-start-ms)
                       (lambda () nil))
                      ((symbol-function 'codex--buffer-directory-for)
                       (lambda (_buffer) dir)))
              (should (equal (agent-log-codex--buffer-session-file
                              agent-log-test--codex-backend sessions)
                             file-b)))))
      (delete-file file-a)
      (delete-file file-b))))

(ert-deftest agent-log-test-codex-visible-text/normalizes-display-markup ()
  "Matches terminal snippets despite list markers and Markdown markup."
  (let ((file (make-temp-file "agent-log-codex-markup" nil ".jsonl")))
    (unwind-protect
        (progn
          (with-temp-file file
            (insert "{\"type\":\"response_item\",\"payload\":{\"content\":\""
                    "- Main project-note scan is clean for legacy "
                    "`Open action items from meetings`, routine `Meeting references`, "
                    "inline `DONE`, and checkbox task lists.\"}}\n"))
          (should
           (agent-log-codex--file-contains-p
            file
            (agent-log-codex--normalize-visible-snippet
             "  - Main project-note scan is clean for legacy Open action items from meetings,"))))
      (delete-file file))))

(ert-deftest agent-log-test-codex-session-event-handler ()
  "Records Codex session IDs reported by hook messages."
  (let ((sid "019df82b-8607-7231-a491-e57316e4fa02")
        (file "/tmp/session.jsonl"))
    (with-temp-buffer
      (rename-buffer " *agent-log-codex-event-test*" t)
      (cl-letf (((symbol-function 'agent-log--find-session-file)
                 (lambda (_backend session-id)
                   (and (equal session-id sid) file))))
        (should-not
         (agent-log-codex--session-event-handler
          (list :type "SessionStart"
                :buffer-name (buffer-name)
                :json-data (format "{\"session_id\":\"%s\"}" sid))))
        (should (equal agent-log-codex--buffer-session-id sid))
        (should (equal agent-log-codex--buffer-session-file file))))))

(ert-deftest agent-log-test-codex-active-session-ids ()
  "Returns session IDs for live Codex terminal buffers."
  (let ((buf1 (generate-new-buffer "codex-1"))
        (buf2 (generate-new-buffer "codex-2")))
    (unwind-protect
        (cl-letf (((symbol-function 'require)
                   (lambda (feature &rest _)
                     (eq feature 'codex)))
                  ((symbol-function 'buffer-list)
                   (lambda () (list buf1 buf2)))
                  ((symbol-function 'codex--buffer-p)
                   (lambda (buffer) (memq buffer (list buf1 buf2))))
                  ((symbol-function 'get-buffer-process)
                   (lambda (buffer) (and (eq buffer buf1) 'process)))
                  ((symbol-function 'process-live-p)
                   (lambda (_process) t))
                  ((symbol-function 'agent-log--read-sessions)
                   (lambda (_backend) 'sessions))
                  ((symbol-function 'agent-log-codex--buffer-session-file)
                   (lambda (_backend sessions)
                     (and (eq sessions 'sessions)
                          (eq (current-buffer) buf1)
                          "/tmp/rollout-2026-05-06T00-00-00-019df82b-8607-7231-a491-e57316e4fa02.jsonl"))))
          (should (equal (agent-log--active-session-ids
                          agent-log-test--codex-backend)
                         '("019df82b-8607-7231-a491-e57316e4fa02"))))
      (kill-buffer buf1)
      (kill-buffer buf2))))

(ert-deftest agent-log-test-claude-active-session-ids/unbound-status ()
  "Skips live Claude buffers without bound extras status data."
  (let ((buf1 (generate-new-buffer "claude-1"))
        (buf2 (generate-new-buffer "claude-2"))
        (status-bound (boundp 'claude-code-extras--status-data))
        (status-value (when (boundp 'claude-code-extras--status-data)
                        claude-code-extras--status-data)))
    (unwind-protect
        (progn
          (makunbound 'claude-code-extras--status-data)
          (with-current-buffer buf1
            (setq-local claude-code-extras--status-data
                        '(:session_id "claude-session")))
          (cl-letf (((symbol-function 'require)
                     (lambda (feature &rest _)
                       (eq feature 'claude-code)))
                    ((symbol-function 'buffer-list)
                     (lambda () (list buf1 buf2)))
                    ((symbol-function 'claude-code--buffer-p)
                     (lambda (buffer) (memq buffer (list buf1 buf2))))
                    ((symbol-function 'get-buffer-process)
                     (lambda (_buffer) 'process))
                    ((symbol-function 'process-live-p)
                     (lambda (_process) t)))
            (should (equal (agent-log--active-session-ids
                            agent-log-test--claude-backend)
                           '("claude-session")))))
      (if status-bound
          (setq claude-code-extras--status-data status-value)
        (makunbound 'claude-code-extras--status-data))
      (kill-buffer buf1)
      (kill-buffer buf2))))

;;;;;; Entry normalization

(ert-deftest agent-log-test-codex-normalize/session-meta ()
  "Normalizes session_meta to a progress entry."
  (let* ((raw (list :type "session_meta"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :id "abc" :cwd "/tmp/project"
                                   :timestamp "2026-04-01T18:00:00Z")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (should (equal (plist-get (car result) :type) "progress"))
    (should (equal (plist-get (car result) :cwd) "/tmp/project"))))

(ert-deftest agent-log-test-codex-render/session-meta-only-has-date ()
  "Renders a session_meta-only Codex file with a real session date."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content
            (concat
             "{\"type\":\"session_meta\","
             "\"timestamp\":\"2026-04-01T18:00:00Z\","
             "\"payload\":{\"id\":\"abc\","
             "\"cwd\":\"/tmp/project\","
             "\"timestamp\":\"2026-04-01T18:00:00Z\"}}\n"))
           (jsonl-path (agent-log-test--write-file "codex.jsonl" jsonl-content))
           (output-path (expand-file-name "output.md" agent-log-test--dir))
           (metadata (list :file jsonl-path
                           :timestamp 1775066400000
                           :project "/tmp/project"
                           :display ""
                           :backend agent-log-test--codex-backend)))
      (agent-log--render-to-file "abc" metadata output-path)
      (let ((content (with-temp-buffer
                       (insert-file-contents output-path)
                       (buffer-string))))
        (should (string-match-p "# Session: project" content))
        (should (string-match-p "2026-04-01" content))
        (should-not (string-match-p "unknown" content))))))

(ert-deftest agent-log-test-codex-normalize/user-message ()
  "Normalizes a user message response_item."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "message" :role "user"
                                   :content (list (list :type "input_text"
                                                        :text "Fix the bug")))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let ((entry (car result)))
      (should (equal (plist-get entry :type) "user"))
      (should (equal (plist-get (plist-get entry :message) :role) "user"))
      (let ((content (plist-get (plist-get entry :message) :content)))
        (should (equal (plist-get (car content) :type) "text"))
        (should (equal (plist-get (car content) :text) "Fix the bug"))))))

(ert-deftest agent-log-test-codex-normalize/assistant-message ()
  "Normalizes an assistant message response_item."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "message" :role "assistant"
                                   :content (list (list :type "output_text"
                                                        :text "I'll fix it"))
                                   :phase "commentary")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let ((entry (car result)))
      (should (equal (plist-get entry :type) "assistant"))
      (let ((content (plist-get (plist-get entry :message) :content)))
        (should (equal (plist-get (car content) :text) "I'll fix it"))))))

(ert-deftest agent-log-test-codex-conversation-text-from-file/spaced-json ()
  "Extracts Codex conversation text from JSON with spaces."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content
            (concat
             "{\"type\": \"response_item\", "
             "\"timestamp\": \"2026-04-01T18:00:00Z\", "
             "\"payload\": {\"type\": \"message\", \"role\": \"user\", "
             "\"content\": [{\"type\": \"input_text\", "
             "\"text\": \"Fix the bug\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "codex.jsonl" jsonl-content)))
      (should (equal (agent-log--conversation-text-from-file
                      jsonl-path agent-log-test--codex-backend)
                     "User: Fix the bug\n\n")))))

(ert-deftest agent-log-test-codex-conversation-text-from-file/skips-agents ()
  "Skips injected AGENTS instructions in Codex summary text."
  (agent-log-test--with-temp-dir
    (let* ((jsonl-content
            (concat
             "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\","
             "\"role\":\"user\",\"content\":[{\"type\":\"input_text\","
             "\"text\":\"# AGENTS.md instructions for /tmp\\nignore\"}]}}\n"
             "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\","
             "\"role\":\"user\",\"content\":[{\"type\":\"input_text\","
             "\"text\":\"Fix the bug\"}]}}\n"))
           (jsonl-path (agent-log-test--write-file "codex.jsonl" jsonl-content)))
      (should (equal (agent-log--conversation-text-from-file
                      jsonl-path agent-log-test--codex-backend)
                     "User: Fix the bug\n\n")))))

(ert-deftest agent-log-test-conversation-text-from-file/stops-at-limit ()
  "Stops parsing summary lines once enough text has been collected."
  (agent-log-test--with-temp-dir
    (let* ((agent-log-summary-max-content-length 30)
           (jsonl-content
            (concat
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"This message is already long enough\"}}\n"
             "{\"type\":\"user\",\"message\":{\"role\":\"user\","
             "\"content\":\"This line should not be parsed\"}}\n"))
           (path (agent-log-test--write-file "s1.jsonl" jsonl-content))
           (calls 0))
      (cl-letf (((symbol-function 'agent-log--parse-json-line)
                 (lambda (line)
                   (cl-incf calls)
                   (json-parse-string line :object-type 'plist
                                      :array-type 'list))))
        (agent-log--conversation-text-from-file
         path agent-log-test--claude-backend)
        (should (= calls 1))))))

(ert-deftest agent-log-test-codex-normalize/developer-message-skipped ()
  "Skips developer messages during normalization."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "message" :role "developer"
                                   :content (list (list :type "input_text"
                                                        :text "system instructions")))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (null result))))

(ert-deftest agent-log-test-codex-normalize/function-call ()
  "Normalizes a function_call to a tool_use entry."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "function_call"
                                   :name "exec_command"
                                   :arguments "{\"cmd\":\"ls\",\"workdir\":\"/tmp\"}"
                                   :call_id "call_123")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let* ((entry (car result))
           (content (plist-get (plist-get entry :message) :content))
           (tool-use (car content)))
      (should (equal (plist-get entry :type) "assistant"))
      (should (equal (plist-get tool-use :type) "tool_use"))
      (should (equal (plist-get tool-use :name) "exec_command"))
      (should (equal (plist-get (plist-get tool-use :input) :cmd) "ls")))))

(ert-deftest agent-log-test-codex-normalize/function-call-output ()
  "Normalizes a function_call_output to a tool_result entry."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "function_call_output"
                                   :call_id "call_123"
                                   :output "file.txt")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let* ((entry (car result))
           (content (plist-get (plist-get entry :message) :content))
           (tool-result (car content)))
      (should (equal (plist-get entry :type) "user"))
      (should (equal (plist-get tool-result :type) "tool_result"))
      (should (equal (plist-get tool-result :content) "file.txt")))))

(ert-deftest agent-log-test-codex-normalize/event-msg-skipped ()
  "Skips event_msg entries during normalization."
  (let* ((raw (list :type "event_msg"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "task_started")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (null result))))

(ert-deftest agent-log-test-codex-normalize/turn-context-skipped ()
  "Skips turn_context entries during normalization."
  (let* ((raw (list :type "turn_context"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :turn_id "t1" :cwd "/tmp")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (null result))))

(ert-deftest agent-log-test-codex-normalize/system-xml-filtered ()
  "Filters out system XML text items during normalization."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "message" :role "user"
                                   :content (list (list :type "input_text"
                                                        :text "<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>")))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    ;; The entry should be skipped entirely since all text was system XML.
    (should (null result))))

(ert-deftest agent-log-test-codex-normalize/mixed-system-and-user-text ()
  "Keeps user text when mixed with system XML in the same message."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "message" :role "user"
                                   :content (list (list :type "input_text"
                                                        :text "<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>")
                                                  (list :type "input_text"
                                                        :text "Fix the bug")))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let* ((content (plist-get (plist-get (car result) :message) :content)))
      ;; Only the non-system text should remain.
      (should (= (length content) 1))
      (should (equal (plist-get (car content) :text) "Fix the bug")))))

;;;;;; Turn merging

(ert-deftest agent-log-test-codex-normalize/consecutive-assistant-merged ()
  "Merges consecutive assistant entries into a single turn."
  (let* ((entries (list (list :type "response_item"
                              :timestamp "2026-04-01T18:00:00Z"
                              :payload (list :type "message" :role "assistant"
                                             :content (list (list :type "output_text"
                                                                  :text "Checking..."))))
                        (list :type "response_item"
                              :timestamp "2026-04-01T18:00:01Z"
                              :payload (list :type "function_call"
                                             :name "exec_command"
                                             :arguments "{\"cmd\":\"ls\"}"
                                             :call_id "call_1"))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend entries)))
    ;; Should merge into a single assistant turn.
    (should (= (length result) 1))
    (let* ((entry (car result))
           (content (plist-get (plist-get entry :message) :content)))
      (should (equal (plist-get entry :type) "assistant"))
      ;; Should have both the text and the tool_use.
      (should (= (length content) 2))
      (should (equal (plist-get (car content) :type) "text"))
      (should (equal (plist-get (cadr content) :type) "tool_use")))))

(ert-deftest agent-log-test-codex-normalize/user-assistant-not-merged ()
  "Does not merge user and assistant entries."
  (let* ((entries (list (list :type "response_item"
                              :timestamp "2026-04-01T18:00:00Z"
                              :payload (list :type "message" :role "user"
                                             :content (list (list :type "input_text"
                                                                  :text "Hello"))))
                        (list :type "response_item"
                              :timestamp "2026-04-01T18:00:01Z"
                              :payload (list :type "message" :role "assistant"
                                             :content (list (list :type "output_text"
                                                                  :text "Hi"))))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend entries)))
    (should (= (length result) 2))
    (should (equal (plist-get (car result) :type) "user"))
    (should (equal (plist-get (cadr result) :type) "assistant"))))

;;;;;; Conversation filtering

(ert-deftest agent-log-test-codex-conversation-entry-p/user ()
  "Recognizes user entries."
  (let ((entry (list :type "user" :message (list :content "hello"))))
    (should (agent-log--conversation-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-conversation-entry-p/assistant ()
  "Recognizes assistant entries."
  (let ((entry (list :type "assistant" :message (list :content "hi"))))
    (should (agent-log--conversation-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-conversation-entry-p/progress-excluded ()
  "Excludes progress entries."
  (let ((entry (list :type "progress")))
    (should-not (agent-log--conversation-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-system-entry-p/environment-context ()
  "Detects <environment_context> system tag."
  (let ((entry (list :message (list :content "<environment_context><cwd>/tmp</cwd></environment_context>"))))
    (should (agent-log--system-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-system-entry-p/turn-aborted ()
  "Detects <turn_aborted> system tag."
  (let ((entry (list :message (list :content "<turn_aborted>interrupted</turn_aborted>"))))
    (should (agent-log--system-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-system-entry-p/normal-message ()
  "Does not flag normal user messages as system."
  (let ((entry (list :message (list :content "Fix the bug"))))
    (should-not (agent-log--system-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-system-entry-p/list-content-all-system ()
  "Detects system entries with list content where all items are system XML."
  (let ((entry (list :message
                     (list :content
                           (list (list :type "text"
                                       :text "<environment_context><cwd>/tmp</cwd></environment_context>")
                                 (list :type "text"
                                       :text "<permissions instructions>...</permissions>"))))))
    (should (agent-log--system-entry-p agent-log-test--codex-backend entry))))

(ert-deftest agent-log-test-codex-system-entry-p/list-content-mixed ()
  "Non-system entry when list content has a non-system text item."
  (let ((entry (list :message
                     (list :content
                           (list (list :type "text"
                                       :text "<environment_context><cwd>/tmp</cwd></environment_context>")
                                 (list :type "text"
                                       :text "Fix the bug"))))))
    (should-not (agent-log--system-entry-p agent-log-test--codex-backend entry))))

;;;;;; First user text

(ert-deftest agent-log-test-codex-first-user-text/basic ()
  "Extracts first genuine user text after normalization."
  (let* ((entries (list (list :type "user"
                              :message (list :content
                                             (list (list :type "text"
                                                         :text "Fix the bug")))))))
    (should (equal (agent-log--first-user-text agent-log-test--codex-backend entries)
                   "Fix the bug"))))

(ert-deftest agent-log-test-codex-first-user-text/skips-system ()
  "Skips system user entries to find first genuine text."
  (let* ((entries (list (list :type "user"
                              :message (list :content "<environment_context>...</environment_context>"))
                        (list :type "user"
                              :message (list :content
                                             (list (list :type "text"
                                                         :text "Real question")))))))
    (should (equal (agent-log--first-user-text agent-log-test--codex-backend entries)
                   "Real question"))))

(ert-deftest agent-log-test-codex-first-user-text/skips-agents ()
  "Skips injected AGENTS instructions to find first genuine text."
  (let* ((entries (list (list :type "user"
                              :message (list :content "# AGENTS.md instructions for /tmp"))
                        (list :type "user"
                              :message (list :content
                                             (list (list :type "text"
                                                         :text "Real question")))))))
    (should (equal (agent-log--first-user-text agent-log-test--codex-backend entries)
                   "Real question"))))

;;;;;; Tool input summaries

(ert-deftest agent-log-test-codex-summarize-tool/exec-command ()
  "Summarizes exec_command tool input."
  (let ((result (agent-log--summarize-tool-input-by-name
                 agent-log-test--codex-backend
                 "exec_command"
                 (list :cmd "ls -la" :workdir "/tmp"))))
    (should (string-match-p "ls -la" result))
    (should (string-match-p "/tmp" result))))

(ert-deftest agent-log-test-codex-summarize-tool/exec-command-no-workdir ()
  "Summarizes exec_command without workdir."
  (let ((result (agent-log--summarize-tool-input-by-name
                 agent-log-test--codex-backend
                 "exec_command"
                 (list :cmd "pwd"))))
    (should (string-match-p "pwd" result))
    (should-not (string-match-p "workdir" result))))

(ert-deftest agent-log-test-codex-summarize-tool/unknown-tool-empty ()
  "Returns empty string for unknown tools."
  (let ((result (agent-log--summarize-tool-input-by-name
                 agent-log-test--codex-backend
                 "unknown_tool"
                 (list :foo "bar"))))
    (should (string-empty-p result))))

;;;;;; Message text extraction

(ert-deftest agent-log-test-codex-extract-message-text/string ()
  "Extracts text from string content."
  (should (equal (agent-log--extract-message-text
                  agent-log-test--codex-backend "hello")
                 "hello")))

(ert-deftest agent-log-test-codex-extract-message-text/list ()
  "Extracts text from list content, ignoring tool_use items."
  (let ((content (list (list :type "text" :text "Fix it")
                       (list :type "tool_use" :name "exec_command"))))
    (should (equal (agent-log--extract-message-text
                    agent-log-test--codex-backend content)
                   "Fix it"))))

;;;;;; Session file index

(ert-deftest agent-log-test-codex-session-id-regexp ()
  "Extracts session UUID from Codex rollout filename."
  (let ((filename "rollout-2026-03-29T08-34-07-019d395f-687b-73c2-a8f5-384bdafbc3e0.jsonl"))
    (should (string-match agent-log-codex--session-id-regexp filename))
    (should (equal (match-string 1 filename)
                   "019d395f-687b-73c2-a8f5-384bdafbc3e0"))))

;;;;;; Content helpers

(ert-deftest agent-log-test-codex-content-non-empty-p/string ()
  "Non-empty string is truthy."
  (should (agent-log-codex--content-non-empty-p "hello")))

(ert-deftest agent-log-test-codex-content-non-empty-p/empty-string ()
  "Empty or blank string is falsy."
  (should-not (agent-log-codex--content-non-empty-p ""))
  (should-not (agent-log-codex--content-non-empty-p "  ")))

(ert-deftest agent-log-test-codex-content-non-empty-p/list ()
  "Non-empty list is truthy, empty list is falsy."
  (should (agent-log-codex--content-non-empty-p '((:type "text" :text "hi"))))
  (should-not (agent-log-codex--content-non-empty-p nil)))

(ert-deftest agent-log-test-codex-parse-arguments/valid ()
  "Parses valid JSON arguments string."
  (let ((result (agent-log-codex--parse-arguments "{\"cmd\":\"ls\"}")))
    (should (equal (plist-get result :cmd) "ls"))))

(ert-deftest agent-log-test-codex-parse-arguments/invalid ()
  "Returns nil for invalid JSON."
  (should (null (agent-log-codex--parse-arguments "not json"))))

(ert-deftest agent-log-test-codex-parse-arguments/nil ()
  "Returns nil for nil input."
  (should (null (agent-log-codex--parse-arguments nil))))

;;;;;; Web search and custom tool normalization

(ert-deftest agent-log-test-codex-normalize/web-search ()
  "Normalizes web_search_call to a tool_use entry."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "web_search_call"
                                   :status "completed"
                                   :action (list :type "search"
                                                 :query "emacs codex integration"))))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let* ((entry (car result))
           (content (plist-get (plist-get entry :message) :content))
           (tool-use (car content)))
      (should (equal (plist-get tool-use :name) "WebSearch"))
      (should (equal (plist-get (plist-get tool-use :input) :query)
                     "emacs codex integration")))))

(ert-deftest agent-log-test-codex-normalize/custom-tool-call ()
  "Normalizes custom_tool_call to a tool_use entry."
  (let* ((raw (list :type "response_item"
                    :timestamp "2026-04-01T18:00:00Z"
                    :payload (list :type "custom_tool_call"
                                   :name "apply_patch"
                                   :input "*** Begin Patch\n*** Add File: /tmp/test.txt"
                                   :call_id "call_456")))
         (result (agent-log--normalize-entries agent-log-test--codex-backend
                                               (list raw))))
    (should (= (length result) 1))
    (let* ((entry (car result))
           (content (plist-get (plist-get entry :message) :content))
           (tool-use (car content)))
      (should (equal (plist-get tool-use :name) "apply_patch")))))

;;;;; Redaction

(ert-deftest agent-log-test-redact-jsonl-line/preserves-opaque-values ()
  "Leaves opaque JSON values byte-identical when only they match."
  (let* ((secret (concat "sk-" (make-string 24 ?a)))
         (google-key (concat "AIza" (make-string 35 ?A)))
         (line (format (concat "{\"type\":\"response_item\",\"payload\":"
                               "{\"encrypted_content\":\"%s\","
                               "\"signature\":\"%s\","
                               "\"thinking_signature\":\"%s\","
                               "\"nonce\":\"%s\","
                               "\"mac\":\"%s\","
                               "\"tag\":\"%s\"}}")
                       secret google-key secret secret secret secret)))
    (should (equal (agent-log-redact--scrub-jsonl-line line) line))))

(ert-deftest agent-log-test-redact-jsonl-line/redacts-plaintext-siblings ()
  "Redacts plaintext while preserving sibling opaque values."
  (let* ((secret (concat "sk-" (make-string 24 ?a)))
         (line (format (concat "{\"type\":\"response_item\",\"payload\":"
                               "{\"encrypted_content\":\"%s\","
                               "\"text\":\"token %s\"}}")
                       secret secret))
         (scrubbed (agent-log-redact--scrub-jsonl-line line))
         (obj (json-parse-string scrubbed
                                 :object-type 'hash-table
                                 :array-type 'array))
         (payload (gethash "payload" obj)))
    (should-not (equal scrubbed line))
    (should (equal (gethash "encrypted_content" payload) secret))
    (should (string-match-p "\\[REDACTED:sk-api-key:"
                            (gethash "text" payload)))))

(ert-deftest agent-log-test-redact-jsonl-line/preserves-base64-image-data ()
  "Leaves a base64 image source byte-identical even when patterns match.
Matches inside randomized image bytes corrupt the base64 and break
session resume; the entire `type:base64' block must be preserved."
  (let* ((fake-key (concat "AK" "IA" (make-string 16 ?A)))
         (data (concat "PADDING" fake-key "PADDING"))
         (line (format (concat "{\"type\":\"image\",\"source\":"
                               "{\"type\":\"base64\","
                               "\"media_type\":\"image/png\","
                               "\"data\":\"%s\"}}")
                       data)))
    (should (equal (agent-log-redact--scrub-jsonl-line line) line))))

;;;; Summary display

(defun agent-log-test--count-summary-lines ()
  "Return the number of rendered summary blocks in the current buffer."
  (save-excursion
    (goto-char (point-min))
    (let ((count 0))
      (while (re-search-forward "^> \\*\\*Summary\\*\\*:" nil t)
        (cl-incf count))
      count)))

(ert-deftest agent-log-test-maybe-insert-summary/no-duplicate-with-embedded ()
  "Does not duplicate a summary already embedded in the rendered file.
Rendered files now embed the summary block, so the display-time
insertion must not add a second copy."
  (let ((index (make-hash-table :test #'equal)))
    (puthash "s1" (list :summary "Test summary text.") index)
    (cl-letf (((symbol-function 'agent-log--read-index)
               (lambda () index)))
      (with-temp-buffer
        (insert "# Session: proj — 2026-06-07\n\n")
        (insert "> **Summary**: Test summary text.\n\n")
        (insert "## User\n\nhello\n")
        (agent-log--maybe-insert-summary "s1")
        (should (= (agent-log-test--count-summary-lines) 1))))))

(ert-deftest agent-log-test-maybe-insert-summary/inserts-when-absent ()
  "Inserts the summary when the rendered file lacks one.
Older rendered files without an embedded summary must still gain one at
display time."
  (let ((index (make-hash-table :test #'equal)))
    (puthash "s1" (list :summary "Test summary text.") index)
    (cl-letf (((symbol-function 'agent-log--read-index)
               (lambda () index)))
      (with-temp-buffer
        (insert "# Session: proj — 2026-06-07\n\n")
        (insert "## User\n\nhello\n")
        (agent-log--maybe-insert-summary "s1")
        (should (= (agent-log-test--count-summary-lines) 1))
        (goto-char (point-min))
        (should (re-search-forward
                 "^> \\*\\*Summary\\*\\*: Test summary text\\." nil t))))))

(provide 'agent-log-test)
;;; agent-log-test.el ends here
