# Release handbook

## Contract

- Release from `main` only through `./scripts/release.sh X.Y.Z` and the resulting release PR.
- Do not create manual tags or GitHub releases.
- The merged `chore(release): vX.Y.Z` commit is the source of truth for the tag, GitHub release notes, and `package.json` version.
- The release workflow re-verifies that merged commit before creating the tag, builds the npm tarball as a release asset, and emits GitHub build provenance attestations for the shipped files.

## Fast path

```bash
./scripts/release.sh 0.6.2
```

This script:

1. Verifies the worktree is clean and `HEAD` matches `origin/main`.
2. Creates `release/vX.Y.Z`.
3. Moves `CHANGELOG.md`'s `Unreleased` section into the new release entry.
4. Bumps `package.json` to the release version.
5. Runs install/lint/typecheck/test/build unless `--skip-verify` is used.
6. Opens a release PR and enables squash auto-merge by default.

## After merge

- `.github/workflows/release.yml` detects the merged `chore(release): vX.Y.Z` commit on `main`.
- CI validates the merged release commit, creates the tag only after verification, builds the package tarball, and publishes the GitHub release from the committed changelog entry.
- Optional npm publishing is available through trusted publishing. It stays off by default until the repo variable `TELCLAUDE_PUBLISH_NPM=true` or a manual dispatch with `publish-to-npm=true` is used and npm trusted publishing is configured for the package.

`workflow_dispatch` is only for rerunning an existing tag.
