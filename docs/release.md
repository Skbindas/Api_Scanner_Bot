# Release checklist

This document describes the maintainer process for publishing API Scanner Pro releases.

## v2.0.0

The repository is prepared for v2.0.0, but the GitHub release is not considered published until the `v2.0.0` Git tag and corresponding GitHub release exist.

### Before publishing

1. Merge all release-preparation changes into `main`.
2. Confirm the package version in `pyproject.toml` is `2.0.0`.
3. Confirm the changelog identifies this as the release-candidate baseline.
4. Confirm CI is green on the release commit.
5. Create the annotated tag `v2.0.0` on the validated `main` commit.
6. Push the tag to GitHub.
7. Create/publish the GitHub release for `v2.0.0`.
8. Confirm the tagged-release workflow builds the package and passes `twine check`.
9. Record the published release URL and any download counts in the adoption/evidence record.

GitHub supports creating a release from an existing tag or creating the tag while drafting the release. Releases are based on Git tags, so the tag must point at the intended release commit.

### Local Git commands

From a clean checkout of `main`:

```bash
git pull --ff-only origin main
git tag -a v2.0.0 -m "API Scanner Pro v2.0.0"
git push origin v2.0.0
```

Then open the repository's Releases page, select `v2.0.0`, verify the target commit, and publish the release.

## Post-release verification

- Confirm the `v2.0.0` tag exists.
- Confirm the release is marked as the latest stable release when appropriate.
- Confirm the tagged-release GitHub Actions workflow completed successfully.
- Confirm package artifacts were generated.
- Confirm the README and changelog point users to the release.
- Update [docs/oss-evidence.md](oss-evidence.md) with dated, verifiable metrics.

Do not report a release, download count, user count, or adoption metric until the corresponding public evidence exists.
