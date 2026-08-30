#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 TAG_NAME" >&2
  exit 2
fi

tag_name="$1"
if [[ ! "$tag_name" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: $tag_name" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

version="${tag_name#v}"
release_please_version="$(<.release-please-version)"
if [[ "$release_please_version" != "$version" ]]; then
  echo "release tag $tag_name does not match .release-please-version ($release_please_version)" >&2
  exit 1
fi

metadata="$(cargo metadata --no-deps --format-version 1 --locked)"
package_count=0
while IFS=$'\t' read -r package package_version; do
  package_count=$((package_count + 1))
  if [[ "$package_version" != "$version" ]]; then
    echo "release tag $tag_name does not match $package ($package_version)" >&2
    exit 1
  fi
done < <(jq -r '.packages[] | [.name, .version] | @tsv' <<< "$metadata")

if [[ "$package_count" -eq 0 ]]; then
  echo "Cargo metadata returned no workspace packages" >&2
  exit 1
fi

echo "verified $tag_name across Release Please and $package_count workspace packages"
