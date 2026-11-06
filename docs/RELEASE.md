# Release handbook

## Contract

- Release from `main` through `.github/workflows/release-request.yml` (`workflow_dispatch`) or `./scripts/release.sh X.Y.Z`, then merge the resulting release PR.
- Do not create manual tags or GitHub releases.
- The merged `chore(release): vX.Y.Z` commit is the source of truth for the tag, GitHub release notes, and `package.json` version.
- The release workflow re-verifies that merged commit before creating the tag, builds the npm tarball as a release asset, and emits GitHub build provenance attestations for the shipped files.

## Fast path (GitHub Actions)

Actions → **Release request** → version `X.Y.Z`. The workflow mints a short-lived token from the org release GitHub App (`vars.RELEASE_APP_CLIENT_ID` / `secrets.RELEASE_APP_PRIVATE_KEY`), runs the same prep as `scripts/release.sh`, pushes `release/vX.Y.Z`, and opens the squash-auto-merge `chore(release): vX.Y.Z` PR.

`.github/workflows/release.yml` `workflow_dispatch` is only for rerunning an existing tag.

## Fast path (local)

```bash
./scripts/release.sh 0.6.2
```

`--ci` / `--no-push` prepares the release commit and stops (no push, no PR). Detached `HEAD` is allowed when it matches `origin/<default-branch>`.

This script:

1. Verifies the worktree is clean and `HEAD` matches `origin/main`.
2. Creates `release/vX.Y.Z`.
3. Moves `CHANGELOG.md`'s `Unreleased` section into the new release entry.
4. Bumps `package.json` to the release version.
5. Runs install/lint/typecheck/test/build unless `--skip-verify` is used.
6. Opens a release PR and enables squash auto-merge by default (unless `--ci` / `--no-push`).

## After merge

- `.github/workflows/release.yml` detects the merged `chore(release): vX.Y.Z` commit on `main`.
- CI validates the merged release commit, creates the tag only after verification, builds the package tarball, and publishes the GitHub release from the committed changelog entry. npm is not a release channel for this repo.
