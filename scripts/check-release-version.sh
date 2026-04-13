#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: ./scripts/check-release-version.sh <version|tag>" >&2
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

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="$(normalize_version "$1")"

python3 - "$VERSION" <<'PY'
import json
import pathlib
import re
import sys

version = sys.argv[1]
errors = []

package = pathlib.Path("package.json")
if not package.exists():
    errors.append("package.json is missing")
else:
    package_version = json.loads(package.read_text(encoding="utf-8")).get("version")
    if package_version != version:
        errors.append(f"package.json version is {package_version!r}, expected {version!r}")

changelog = pathlib.Path("CHANGELOG.md")
if not changelog.exists():
    errors.append("CHANGELOG.md is missing")
else:
    text = changelog.read_text(encoding="utf-8")
    pattern = re.compile(rf"(?m)^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$")
    if not pattern.search(text):
        errors.append(f"CHANGELOG.md is missing a release heading for {version}")

if errors:
    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    raise SystemExit(1)

print(f"release metadata ok: v{version}")
PY
