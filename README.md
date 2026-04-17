# `agent-log`: Browse AI coding agent session logs in Emacs

## Overview

AI coding agents such as [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [Codex](https://openai.com/index/introducing-codex/) store complete conversation transcripts as JSONL files. These files are machine-readable but not human-friendly. `agent-log` renders them as plain Markdown files so that standard tools -- `consult-ripgrep`, Dired, `grep` -- work natively on readable content.

The package provides a session browser that lists all your coding agent conversations, grouped by project and sorted most-recent-first. Sessions are lazily rendered on first access: you pick a session, and `agent-log` converts its JSONL transcript into a well-structured Markdown file with headings for each turn, collapsible tool calls, and thinking blocks. For active conversations, a file watcher keeps the rendered buffer updated in real time.

Key capabilities:

- **Session browser** with project grouping and per-session preview (date, project, first message).
- **Rendered Markdown mirror** with readable filenames, organized by project.
- **Full-text search** via `consult-ripgrep` or any grep tool on the rendered directory.
- **Live updates** via `file-notify` as conversations progress.
- **Outline navigation** to fold/unfold tool calls, thinking blocks, and tool results.
- **Smart tool summaries** showing the most relevant input for each tool call (file path for Read/Write, command for Bash, pattern for Grep, etc.).

## Installation

**Requirements:** Emacs 29.1 or later, and [markdown-mode](https://jblevins.org/projects/markdown-mode/) 2.6 or later.

### package-vc (built-in since Emacs 30)

```emacs-lisp
(use-package agent-log
  :vc (:url "https://github.com/benthamite/agent-log"))
```

### Elpaca

```emacs-lisp
(use-package agent-log
  :ensure (:host github :repo "benthamite/agent-log"))
```

### straight.el

```emacs-lisp
(use-package agent-log
  :straight (:host github :repo "benthamite/agent-log"))
```

## Quick start

```emacs-lisp
(use-package agent-log
  :ensure (agent-log :host github :repo "benthamite/agent-log")
  :bind (("C-c l b" . agent-log-browse-sessions)
         ("C-c l l" . agent-log-open-latest)
         ("C-c l d" . agent-log-open-rendered-directory)))
```

Run `M-x agent-log-browse-sessions` to pick a project and session. The session opens as a rendered Markdown buffer with folding support. Press `n`/`p` to jump between turns, `TAB` to toggle a section, and `C` to collapse all tool sections at once.

## Documentation

For a comprehensive description of all user options, commands, and functions, see the [manual](https://stafforini.com/notes/agent-log/).

## License

`agent-log` is licensed under the GPL-3.0-or-later. See [COPYING.txt](COPYING.txt) for details.
