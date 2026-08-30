#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(<"$repository_root/.release-please-version")"
error_output="$(mktemp "${TMPDIR:-/tmp}/sandy-release-version.XXXXXX")"
trap 'rm -f "$error_output"' EXIT

"$repository_root/scripts/verify-release-version.sh" "v$version"

if "$repository_root/scripts/verify-release-version.sh" "v0.0.0" >"$error_output" 2>&1; then
  echo "release verifier accepted a mismatched tag" >&2
  exit 1
fi

if ! grep -Fq 'does not match .release-please-version' "$error_output"; then
  echo "release verifier did not explain the version mismatch" >&2
  exit 1
fi
