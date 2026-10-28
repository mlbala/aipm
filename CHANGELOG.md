# Changelog

All notable changes to aipm are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository skeleton: the `aipm` package laid out by layer (ARCHITECTURE §19), with typed stubs that name the build step that implements them.
- The `aipm` command line with every command and flag from ARCHITECTURE §16, the JSON envelope and the exit codes. Commands exit 2 until their build step lands, saying which one.
- Tests: CLI smoke tests, a startup-time test (`aipm --help` under 300 ms), the ruff process ban, the import-linter layer contracts, a hidden-character check, and the first 10 cases of the injection corpus.
- CI on Linux and macOS with Python 3.12 and 3.13, a commit-authorship check, and a weekly security workflow (gitleaks, semgrep, osv-scanner, zizmor). Every action is pinned by commit SHA.
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, ADRs 0001–0013 and the `clinic-booking` example idea.

### Changed

- Design review 01 applied to the architecture and security design: config keys are user-only, tighten-only or repo-ok; the command policy checks argv prefixes and runners; approved artifacts stay wrapped as untrusted; `prompt` and `sync-context` need trust; the LLM gateway never sends sampling parameters.
