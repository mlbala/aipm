"""Fake secrets for redaction tests (AGENTS.md rule 9, SECURITY.md invariant I-5).

None of these is a real credential. Each value is long and distinctive, so a test can prove it
never appears in an LLM request, a file, a log or a run artifact. The values avoid real
provider token formats, so secret scanners and GitHub push protection do not treat them as
live keys; `.gitleaks.toml` allowlists this file.
"""

FAKE_SECRETS: dict[str, str] = {
    "ANTHROPIC_API_KEY": "aipm-fake-anthropic-key-not-a-real-secret-0001",
    "OPENAI_API_KEY": "aipm-fake-openai-key-not-a-real-secret-0002",
    "GITHUB_TOKEN": "aipm-fake-github-token-not-a-real-secret-0003",
    "AIPM_TEST_DB_PASSWORD": "aipm-fake-db-password-not-a-real-secret-0004",
}
