# Injection corpus

Hostile inputs for the security regression suite ([SECURITY.md §14.2](../../../docs/architecture/SECURITY.md#142-injection-corpus-testssecuritycorpus)). Each case is one YAML file, `C-NNN-<slug>.yaml`. The tests that feed the cases through aipm's input paths arrive with the build prompts that add those paths (02–09). `test_corpus_format.py` checks the format now.

## Format

```yaml
id: C-001                     # unique, matches the file name
vector: direct-instruction    # attack category, see below
input:
  surface: idea.md            # where the text enters aipm
  text: |                     # the hostile text
    ...
expected:
  outcome: >-                 # what must happen, in one or two sentences
    ...
  exit_code: 4                # optional: the exit code in non-interactive mode
```

- `vector` is one of: `direct-instruction`, `indirect-instruction`, `smuggling`, `boundary`, `exfiltration`, `structural`, `path`, `terminal`, `config-redirection`.
- `input.surface` names the input path, such as `idea.md`, `answers`, `repo-file`, `llm-output`, `prd-field` or `repo-config`.
- Write invisible and control characters as YAML double-quoted escapes (`"\U000E0061"`, `"\u200b"`, `"\x1b"`), never as raw characters, so the files stay readable and reviewable.
- Never put a real secret or a working exploit URL in a case. Use `evil.example`, which is reserved and never resolves.

## Adding a case

Add the next free `C-NNN`, name the invariant or rule it exercises in `expected.outcome`, and add it to the input-path tests of the build prompt that owns that path.
