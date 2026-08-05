EMACS ?= emacs
ELPACA_REPOS := $(dir $(CURDIR))
LOAD_PATH := -L $(CURDIR) \
             -L $(ELPACA_REPOS)markdown-mode \
             -L $(ELPACA_REPOS)codex \
             -L $(ELPACA_REPOS)agent \
             -L $(ELPACA_REPOS)inheritenv \
             -L $(ELPACA_REPOS)transient/lisp \
             -L $(ELPACA_REPOS)llama \
             -L $(ELPACA_REPOS)cond-let \
             -L $(ELPACA_REPOS)compat

.PHONY: test test-load-order test-bridge compile clean

test: test-load-order test-bridge
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq load-prefer-newer t)' \
	  -l agent-log.el \
	  -l agent-log-claude.el \
	  -l agent-log-codex.el \
	  -l agent-log-test.el \
	  -f ert-run-tests-batch-and-exit

# Separate from `test' because it is the one suite that requires the
# `agent' package; agent-log-test.el stays loadable without it.
test-bridge:
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq load-prefer-newer t)' \
	  -l agent-log-agent-test.el \
	  -f ert-run-tests-batch-and-exit

test-load-order:
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq load-prefer-newer t)' \
	  --eval "(progn (require 'agent) (require 'agent-log) (unless (and (featurep 'agent) (featurep 'agent-log) (featurep 'agent-log-agent)) (error \"Agent Log bridge features are not loaded\")) (unless (eq agent-session-annotation-function #'agent-log-agent--session-annotation) (error \"Agent Log bridge did not install the switcher annotation function\")))"
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq load-prefer-newer t)' \
	  --eval "(progn (require 'agent-log) (when (or (featurep 'agent) (featurep 'agent-log-agent)) (error \"Agent Log bridge loaded eagerly\")) (require 'agent) (unless (and (featurep 'agent) (featurep 'agent-log) (featurep 'agent-log-agent)) (error \"Agent Log bridge features are not loaded\")) (unless (eq agent-session-annotation-function #'agent-log-agent--session-annotation) (error \"Agent Log bridge did not install the switcher annotation function\")))"

compile:
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq load-prefer-newer t)' \
	  --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile agent-log.el agent-log-claude.el agent-log-codex.el agent-log-redact.el agent-log-agent.el

clean:
	rm -f *.elc
