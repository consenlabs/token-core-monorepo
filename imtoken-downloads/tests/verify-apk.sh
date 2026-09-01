#!/usr/bin/env bash

set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
downloads_dir="$(cd "$test_dir/.." && pwd)"
verify_script="$downloads_dir/scripts/verify-apk.sh"
manifest_script="$downloads_dir/scripts/render-manifest.sh"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT

apk_path="$fixture_dir/imToken.apk"
release_json="$fixture_dir/release.json"
verification_json="$fixture_dir/verification.json"
manifest_json="$fixture_dir/manifest.json"
fake_aapt2="$fixture_dir/aapt2"
fake_apksigner="$fixture_dir/apksigner"
cert_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

printf 'signed apk fixture\n' > "$apk_path"
if command -v sha256sum >/dev/null 2>&1; then
  apk_sha256="$(sha256sum "$apk_path" | awk '{print $1}')"
else
  apk_sha256="$(shasum -a 256 "$apk_path" | awk '{print $1}')"
fi

cat > "$fake_aapt2" <<'EOF'
#!/usr/bin/env bash
echo "package: name='im.token.app' versionCode='12345' versionName='2.16.0' platformBuildVersionName=''"
EOF

cat > "$fake_apksigner" <<EOF
#!/usr/bin/env bash
echo "Verifies"
echo "Signer #1 certificate SHA-256 digest: ${cert_sha256}"
EOF
chmod +x "$fake_aapt2" "$fake_apksigner"

write_release_json() {
  local build_version="${1:-12345}"
  local notes="${2:-ENV: PRODUCTION
CHANNEL: direct
BUILD: 12345
SHA256: ${apk_sha256}}"
  jq -n \
    --arg buildVersion "$build_version" \
    --arg notes "$notes" \
    '{
      name: "projects/123/apps/1:123:android:abc/releases/release-1",
      displayVersion: "2.16.0",
      buildVersion: $buildVersion,
      createTime: "2026-08-31T00:00:00Z",
      releaseNotes: {text: $notes}
    }' > "$release_json"
}

run_verify() {
  APKSIGNER_BIN="$fake_apksigner" AAPT2_BIN="$fake_aapt2" \
    "$verify_script" \
      --apk "$apk_path" \
      --release-json "$release_json" \
      --expected-package im.token.app \
      --expected-cert-sha256 "$cert_sha256" \
      --output "$verification_json"
}

expect_failure() {
  local expected_message="$1"
  shift
  local stderr_file="$fixture_dir/stderr"
  if "$@" > /dev/null 2> "$stderr_file"; then
    echo "expected command to fail: $expected_message" >&2
    exit 1
  fi
  grep -F "$expected_message" "$stderr_file" >/dev/null || {
    echo "missing expected error: $expected_message" >&2
    cat "$stderr_file" >&2
    exit 1
  }
}

write_release_json
run_verify
jq -e '
  .packageName == "im.token.app" and
  .versionName == "2.16.0" and
  .versionCode == 12345 and
  .sha256 == $sha and
  .signingCertificateSha256 == $cert
' --arg sha "$apk_sha256" --arg cert "$cert_sha256" "$verification_json" >/dev/null

"$manifest_script" \
  --verification "$verification_json" \
  --github-tag 'imtoken-android-v2.16.0+12345' \
  --published-at '2026-08-31T01:00:00Z' \
  --release-url 'https://github.com/consenlabs/token-core-monorepo/releases/tag/imtoken-android-v2.16.0%2B12345' \
  --output "$manifest_json"
jq -e '
  .schemaVersion == 1 and
  .environment == "PRODUCTION" and
  .channel == "direct" and
  .versionCode == 12345 and
  (.firebaseReleaseName | not)
' "$manifest_json" >/dev/null

write_release_json 99999
expect_failure 'APK versionCode does not match Firebase buildVersion' run_verify

write_release_json 12345 "ENV: PRODUCTION
CHANNEL: direct
BUILD: 54321
SHA256: ${apk_sha256}"
expect_failure 'APK versionCode does not match release-notes BUILD' run_verify

write_release_json 12345 "ENV: PRODUCTION
CHANNEL: direct
BUILD: 12345
BUILD: 12345
SHA256: ${apk_sha256}"
expect_failure 'release notes must contain exactly one BUILD: field' run_verify

write_release_json
expect_failure 'APK signing certificate does not match the production trust anchor' \
  env APKSIGNER_BIN="$fake_apksigner" AAPT2_BIN="$fake_aapt2" \
  "$verify_script" \
    --apk "$apk_path" \
    --release-json "$release_json" \
    --expected-package im.token.app \
    --expected-cert-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --output "$verification_json"

echo "All imToken APK verification tests passed."
