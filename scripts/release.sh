#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/release.sh X.Y.Z [options]

Prepares a release PR from the default branch by:
- verifying the worktree is clean
- verifying HEAD matches origin/<default-branch>
- creating release/vX.Y.Z
- moving CHANGELOG.md's Unreleased section into a versioned release entry
- bumping package.json to the release version
- validating the release metadata
- optionally running install/lint/typecheck/test/build
- creating and pushing the release commit
- opening a GitHub PR and enabling squash auto-merge

Options:
  --date YYYY-MM-DD  Override release date (default: today in UTC)
  --skip-verify      Skip local verification gates
  --allow-empty      Allow releasing with an empty Unreleased section
  --no-auto-merge    Create the PR but do not enable auto-merge
  -h, --help         Show this help text
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

normalize_version() {
  local raw="$1"
  raw="${raw#v}"
  if [[ ! "$raw" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$ ]]; then
    echo "error: version must look like 0.6.2 or v0.6.2" >&2
    exit 1
  fi
  printf '%s\n' "$raw"
}

default_branch() {
  local ref
  ref="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
  if [[ -z "$ref" ]]; then
    echo "main"
  else
    echo "${ref#origin/}"
  fi
}

version=""
release_date="$(date -u +%Y-%m-%d)"
skip_verify=0
allow_empty=0
auto_merge=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --date)
      [[ $# -ge 2 ]] || { echo "error: --date requires a value" >&2; exit 1; }
      release_date="$2"
      shift 2
      ;;
    --skip-verify)
      skip_verify=1
      shift
      ;;
    --allow-empty)
      allow_empty=1
      shift
      ;;
    --no-auto-merge)
      auto_merge=0
      shift
      ;;
    --*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "$version" ]]; then
        echo "error: version already set to $version; unexpected extra argument: $1" >&2
        usage >&2
        exit 1
      fi
      version="$1"
      shift
      ;;
  esac
done

[[ -n "$version" ]] || { usage >&2; exit 1; }

require_command git
require_command gh
require_command pnpm
require_command python3

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="$(normalize_version "$version")"
TAG="v${VERSION}"
BRANCH="release/${TAG}"
DEFAULT_BRANCH="$(default_branch)"

git diff --quiet --ignore-submodules HEAD -- || {
  echo "error: worktree is dirty; commit or stash first" >&2
  exit 1
}
git diff --cached --quiet --ignore-submodules -- || {
  echo "error: index has staged changes; commit or unstage first" >&2
  exit 1
}

CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "$DEFAULT_BRANCH" ]] || {
  echo "error: releases must start from ${DEFAULT_BRANCH}; current branch is ${CURRENT_BRANCH}" >&2
  exit 1
}

git fetch --quiet origin "$DEFAULT_BRANCH" --tags

LOCAL_HEAD="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse "origin/${DEFAULT_BRANCH}")"
[[ "$LOCAL_HEAD" == "$REMOTE_HEAD" ]] || {
  echo "error: local ${DEFAULT_BRANCH} is not at origin/${DEFAULT_BRANCH}; pull or fast-forward before releasing" >&2
  exit 1
}

if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
  echo "error: branch already exists locally: ${BRANCH}" >&2
  exit 1
fi
if git ls-remote --exit-code --heads origin "${BRANCH}" >/dev/null 2>&1; then
  echo "error: branch already exists on origin: ${BRANCH}" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "error: tag already exists locally: ${TAG}" >&2
  exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "error: tag already exists on origin: ${TAG}" >&2
  exit 1
fi

git switch -c "$BRANCH"

python3 - "$VERSION" "$release_date" "$allow_empty" <<'PY'
import json
import pathlib
import re
import sys

version, release_date, allow_empty = sys.argv[1], sys.argv[2], sys.argv[3] == "1"

changelog = pathlib.Path("CHANGELOG.md")
text = changelog.read_text(encoding="utf-8")
marker = "## [Unreleased]"
if marker not in text:
    raise SystemExit("error: CHANGELOG.md is missing the Unreleased section")

start = text.index(marker)
after_marker = start + len(marker)
rest = text[after_marker:]
match = re.search(r"(?m)^## \[", rest)
if match:
    unreleased_body = rest[:match.start()]
    suffix = rest[match.start():]
else:
    unreleased_body = rest
    suffix = ""

if not unreleased_body.strip() and not allow_empty:
    raise SystemExit("error: CHANGELOG.md Unreleased section is empty; add release notes first or pass --allow-empty")

release_header = f"\n\n## [{version}] - {release_date}\n"
new_text = text[:start] + marker + release_header + unreleased_body.lstrip("\n")
if suffix:
    new_text += suffix if suffix.startswith("\n") else "\n" + suffix
changelog.write_text(new_text, encoding="utf-8")

package_path = pathlib.Path("package.json")
data = json.loads(package_path.read_text(encoding="utf-8"))
data["version"] = version
package_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

if [[ "$skip_verify" -eq 0 ]]; then
  pnpm install --frozen-lockfile
  pnpm run lint
  pnpm run typecheck
  pnpm test
  pnpm run build
fi

./scripts/check-release-version.sh "$VERSION"

git add CHANGELOG.md package.json
git diff --cached --quiet && {
  echo "error: release prep produced no staged changes" >&2
  exit 1
}

git commit -m "chore(release): ${TAG}"
git push -u origin "$BRANCH"

PR_BODY=$(
  cat <<EOF
## Release

- updates \`CHANGELOG.md\` for \`${TAG}\`
- bumps \`package.json\` to \`${VERSION}\`
- merge triggers \`.github/workflows/release.yml\`, which verifies the merged release commit before tagging
- GitHub release assets are checksummed and attested; optional npm publishing is available through trusted publishing when enabled
EOF
)

PR_URL="$(
  gh pr create \
    --base "$DEFAULT_BRANCH" \
    --head "$BRANCH" \
    --title "chore(release): ${TAG}" \
    --body "$PR_BODY"
)"

if [[ "$auto_merge" -eq 1 ]]; then
  gh pr merge "$PR_URL" --squash --auto --delete-branch
fi

echo "Created release PR: $PR_URL"
