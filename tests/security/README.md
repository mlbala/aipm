# Security tests

The security regression suite (SECURITY.md §14). Every security-relevant change adds a test here (AGENTS.md).

- `corpus/`: hostile inputs, one YAML file per case; see its README.
- `fixtures/`: deliberately violating code, excluded from the normal lint and never imported.
- `test_banned_api.py`: ruff bans every way to start a process outside `execution/process.py`.
- `test_layers.py`: the import-linter contracts hold, and they catch violations.
- `test_no_hidden_characters.py`: no tracked text hides bidi, zero-width, tag or control characters.
- `test_corpus_format.py`: the corpus is well formed.
- `test_managed_block.py`: aipm replaces only the text between its markers in context files, byte for byte, and refuses broken markers (hypothesis fuzzing).
- `test_context_files.py`: invariant I-3 over every generated context file (fuzzed), corpus C-022 to C-027 in every model-written field and in the PRD and architecture bodies, gate argv only from `compile_gate`, and no reads or writes through links.
- `test_task_prompt.py`: protected paths only as "MUST NOT modify" rules, previous gate output only inside a well-formed untrusted block, secrets redacted in saved and printed prompts, safe `--out` and `--report` paths, and the size budget.
- `test_git_head.py`: the base-commit git call is hardened and its environment constructed.
