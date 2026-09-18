# Open-source implementation and adoption evidence

This page records verifiable evidence for the project's open-source maintenance story. It deliberately separates **implementation evidence** from **external adoption evidence**.

Snapshot date: 2026-09-18

## Implementation evidence

- Public, non-fork repository: `Skbindas/Api_Scanner_Bot`.
- MIT license is present in the repository.
- `main` contains two merged OSS-readiness pull requests: PR #1 and PR #3.
- CI workflow covers Python 3.11, 3.12, and 3.13.
- Tagged-release workflow builds a Python distribution and runs `twine check`.
- Dependabot configuration covers pip and GitHub Actions.
- CODEOWNERS identifies the primary maintainer.
- Structured bug and feature issue forms are present.
- Pull-request template and security policy are present.
- A Good First Issue exists for deterministic API endpoint detection.
- CLI entry point and CLI argument tests are present.
- Earlier project history includes a dedicated test-suite implementation and subsequent review/fix commits.

## Adoption evidence currently verified

- GitHub stars: **1** as of the snapshot date.
- GitHub forks: **0** as of the snapshot date.
- Published GitHub releases: **0** as of the snapshot date.
- Public package/download statistics: **not yet available**.
- External contributor PRs: **none verified**.
- Public dependent repositories: **none verified**.

The current star count is an adoption signal, but this record does not attribute it to an external person because GitHub's public stargazer identity data is restricted. It should not be described as evidence of broad adoption.

## What counts as real external adoption

For the Codex for Open Source application, only evidence that actually occurred should be reported. Useful future evidence includes:

- an external person opening an issue with a reproducible report;
- an external pull request that is reviewed and merged;
- a public fork with meaningful changes;
- a published package with verifiable download statistics;
- GitHub release downloads after v2.0.0 is published;
- public dependent repositories shown by GitHub's dependency graph;
- independent technical write-ups or tutorials that use the project.

Do not manufacture stars, forks, downloads, testimonials, users, or contributor activity.

## Evidence update rule

Whenever new adoption happens, add the date, exact metric, source URL, and what the metric demonstrates. Keep historical snapshots rather than overwriting them.
