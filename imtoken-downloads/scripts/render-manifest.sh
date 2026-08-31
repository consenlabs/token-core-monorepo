#!/usr/bin/env bash

set -euo pipefail

die() {
  echo "render-manifest: $*" >&2
  exit 1
}

verification=""
github_tag=""
published_at=""
release_url=""
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verification) verification="${2:-}"; shift 2 ;;
    --github-tag) github_tag="${2:-}"; shift 2 ;;
    --published-at) published_at="${2:-}"; shift 2 ;;
    --release-url) release_url="${2:-}"; shift 2 ;;
    --output) output_path="${2:-}"; shift 2 ;;
    *) die "unknown or incomplete argument: $1" ;;
  esac
done

[[ -f "$verification" ]] || die "verification JSON does not exist"
[[ -n "$github_tag" ]] || die "--github-tag is required"
[[ -n "$published_at" ]] || die "--published-at is required"
[[ -n "$release_url" ]] || die "--release-url is required"
[[ -n "$output_path" ]] || die "--output is required"

jq -e '
  (.packageName | strings | length > 0) and
  (.versionName | strings | length > 0) and
  (.versionCode | type == "number") and
  (.sha256 | test("^[0-9a-f]{64}$")) and
  (.signingCertificateSha256 | test("^[0-9a-f]{64}$")) and
  (.firebaseCreateTime | strings | length > 0)
' "$verification" >/dev/null || die "verification JSON is incomplete"

mkdir -p "$(dirname "$output_path")"
jq \
  --arg githubTag "$github_tag" \
  --arg githubReleaseUrl "$release_url" \
  --arg publishedAt "$published_at" \
  '{
    schemaVersion: 1,
    product: "imToken",
    platform: "android",
    environment: "PRODUCTION",
    channel: "direct",
    packageName,
    versionName,
    versionCode,
    sha256,
    signingCertificateSha256,
    firebaseCreateTime,
    githubTag: $githubTag,
    githubReleaseUrl: $githubReleaseUrl,
    publishedAt: $publishedAt
  }' "$verification" > "$output_path"
