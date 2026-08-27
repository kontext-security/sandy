#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arm64_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
amd64_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
formula_path="$(mktemp "${TMPDIR:-/tmp}/sandy-formula.XXXXXX")"
trap 'rm -f "$formula_path"' EXIT

"$repository_root/scripts/render-homebrew-formula.sh" \
  "0.1.6" "$arm64_sha256" "$amd64_sha256" > "$formula_path"
ruby -c "$formula_path" >/dev/null

assert_contains() {
  local expected="$1"
  if ! grep -Fq -- "$expected" "$formula_path"; then
    echo "generated formula is missing: $expected" >&2
    exit 1
  fi
}

assert_absent() {
  local unexpected="$1"
  if grep -Fq -- "$unexpected" "$formula_path"; then
    echo "generated formula contains private-distribution behavior: $unexpected" >&2
    exit 1
  fi
}

assert_contains 'url "https://github.com/kontext-security/sandy/releases/download/v0.1.6/sandy_0.1.6_darwin_arm64.tar.gz"'
assert_contains 'url "https://github.com/kontext-security/sandy/releases/download/v0.1.6/sandy_0.1.6_darwin_amd64.tar.gz"'
assert_contains "sha256 \"$arm64_sha256\""
assert_contains "sha256 \"$amd64_sha256\""
assert_contains "sandy doctor"
assert_absent "HOMEBREW_GITHUB_API_TOKEN"
assert_absent "PrivateRepositoryReleaseDownloadStrategy"
assert_absent "using:"
