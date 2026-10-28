# Security policy

aipm reads untrusted text and launches programs, so security reports are welcome and taken seriously. The security design is in [docs/architecture/SECURITY.md](docs/architecture/SECURITY.md).

## Supported versions

Only the latest minor release receives security fixes.

## How to report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue, pull request or discussion for a vulnerability.

Include:

- the aipm version (`aipm --version`) and your operating system;
- the coding agent and its version, if one is involved;
- the steps to reproduce;
- the impact, as you understand it.

## What to expect

- Acknowledgement within 3 business days.
- Triage within 7 days.
- A fix within 30 days for high and critical issues.

You will be kept informed, and credited in the release notes if you wish.

## Scope

In scope:

- aipm's code and templates;
- the install script;
- release artifacts.

Out of scope:

- third-party coding agents, scanners and models (report those to their maintainers);
- issues that need an already-compromised machine or user account.

## Safe harbor

Research done in good faith, that respects users' privacy and data and avoids disrupting services, will not lead to legal action from this project. If in doubt, ask through private vulnerability reporting first.
