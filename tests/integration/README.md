# Integration tests

Every command, run through the CLI against temporary git repositories (the `tmp_repo` fixture). Later steps add stub agent binaries on `PATH` that apply scripted, sometimes malicious, diffs (SECURITY.md §14.3).
