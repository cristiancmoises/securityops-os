;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d6a38bda40a15a7490488bb8512fb415 owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; Basename exclusions for the live image's embedded configuration source.

(define-module (securityops source-selection)
  #:use-module (srfi srfi-13)
  #:export (securityops-source-file?))

(define (securityops-source-file? file stat)
  "Select FILE for the embedded source tree.  Guix supplies its lstat as STAT.
Rejected directory entries prune their subtree.  Names are reserved at every
depth; this does not inspect contents, authorize untracked files, or change
Guix's existing symlink handling.  Keep local-file's source anchor in config.scm."
  (let ((b (basename file)))
    (not (or (member b '("out" ".git" ".claude" "continue" "__pycache__"
                        "GET_THE_ISO.md" ".env"
                        ".dsh" ".agents" "AGENTS.md" "CODEX_TASK.md"
                        ".ai-memory" ".agent-private" ".prompts" ".second-brain"
                        "AGENTS.local.md" "CLAUDE.md" "CLAUDE.local.md"
                        "MAINTAINER_PROMPT.md" "TASK_PROMPT.md" "NEXT_PROMPT.md"
                        "build" "evidence" "qemu.log"
                        "securityops-os-phase28-handoff-v3"
                        "securityops-os-phase46-codex-guix-kit-v1"
                        "securityops-os-phase46-codex-guix-kit-v1.tar.gz"))
             (string-prefix? ".aider" b)
             (string-prefix? ".codex" b)
             (string-prefix? ".env." b)
             (string-prefix? "id_" b)
             (string-suffix? ".pyc" b)
             (string-suffix? ".pyo" b)
             (string-suffix? ".key" b)
             (string-suffix? ".pem" b)
             (string-suffix? ".token" b)
             (string-suffix? "_token" b)
             (string-suffix? ".iso" b)))))
