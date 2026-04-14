EMACS ?= emacs
ELPACA_REPOS := $(dir $(CURDIR))
LOAD_PATH := -L $(CURDIR) \
             -L $(ELPACA_REPOS)markdown-mode \
             -L $(ELPACA_REPOS)codex \
             -L $(ELPACA_REPOS)inheritenv \
             -L $(ELPACA_REPOS)transient/lisp \
             -L $(ELPACA_REPOS)cond-let

.PHONY: test compile clean

test:
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  -l agent-log.el \
	  -l agent-log-claude.el \
	  -l agent-log-test.el \
	  -f ert-run-tests-batch-and-exit

compile:
	$(EMACS) -Q --batch $(LOAD_PATH) \
	  --eval '(setq byte-compile-error-on-warn nil)' \
	  -f batch-byte-compile agent-log.el agent-log-claude.el agent-log-codex.el

clean:
	rm -f *.elc
