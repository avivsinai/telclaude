# Governance

Status: alpha (0.1.x). Maintained by @avivsinai.

## Roles
- **Maintainer**: approves/merges PRs, cuts releases, manages security disclosures.
- **Contributors**: propose changes via PR; reviews welcome from anyone.

## Decision Process
- Default: **lazy consensus** on issues/PRs after at least one maintainer review.
- **Security fixes**: maintainer decides; embargo until fix shipped.
- **Breaking changes**: allowed in 0.x; must be called out in PR and CHANGELOG.

## Releases
- Versioning: semver-style tags; 0.x may break.
- Release cadence: ad-hoc; target monthly during alpha.
- Artifacts: GitHub release notes + CHANGELOG update; Docker images built from `main`.

## Contributions
- Code of Conduct: `CODE_OF_CONDUCT.md`.
- Contribution flow: fork → branch → tests → PR. See `CONTRIBUTING.md`.
- Disagreements: start a GitHub Discussion; maintainer resolves if no consensus.

