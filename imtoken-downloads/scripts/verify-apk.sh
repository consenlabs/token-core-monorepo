#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: verify-apk.sh \
  --apk PATH \
  --release-json PATH \
  --expected-package PACKAGE_NAME \
  --expected-cert-sha256 SHA256 \
  --output PATH

APKSIGNER_BIN and AAPT2_BIN may be set to override the Android SDK tools.
EOF
}

die() {
  echo "verify-apk: $*" >&2
  exit 1
}

require_value() {
  [[ $# -ge 2 && -n "${2:-}" ]] || die "missing value for $1"
}

normalize_sha256() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ':[:space:]'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

release_note_field() {
  local key="$1"
  local count
  local value

  count="$(printf '%s\n' "$release_notes" | awk -F: -v key="$key" '$1 == key { count += 1 } END { print count + 0 }')"
  [[ "$count" == "1" ]] || die "release notes must contain exactly one ${key}: field"

  value="$(printf '%s\n' "$release_notes" | awk -F: -v key="$key" '
    $1 == key {
      sub(/^[^:]*:[[:space:]]*/, "")
      sub(/[[:space:]]+$/, "")
      print
    }
  ')"
  [[ -n "$value" ]] || die "release notes field ${key} is empty"
  printf '%s' "$value"
}

apk_path=""
release_json=""
expected_package=""
expected_cert_sha256=""
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apk)
      require_value "$@"
      apk_path="$2"
      shift 2
      ;;
    --release-json)
      require_value "$@"
      release_json="$2"
      shift 2
      ;;
    --expected-package)
      require_value "$@"
      expected_package="$2"
      shift 2
      ;;
    --expected-cert-sha256)
      require_value "$@"
      expected_cert_sha256="$2"
      shift 2
      ;;
    --output)
      require_value "$@"
      output_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -f "$apk_path" ]] || die "APK does not exist: $apk_path"
[[ -f "$release_json" ]] || die "Firebase release JSON does not exist: $release_json"
[[ -n "$expected_package" ]] || die "--expected-package is required"
[[ -n "$expected_cert_sha256" ]] || die "--expected-cert-sha256 is required"
[[ -n "$output_path" ]] || die "--output is required"

command -v jq >/dev/null 2>&1 || die "jq is required"
apksigner_bin="${APKSIGNER_BIN:-apksigner}"
aapt2_bin="${AAPT2_BIN:-aapt2}"
command -v "$apksigner_bin" >/dev/null 2>&1 || die "apksigner is required"
command -v "$aapt2_bin" >/dev/null 2>&1 || die "aapt2 is required"
jq -e 'type == "object"' "$release_json" >/dev/null || die "invalid Firebase release JSON"

firebase_release_name="$(jq -er '.name | strings | select(length > 0)' "$release_json")" || die "Firebase release name is missing"
firebase_create_time="$(jq -er '.createTime | strings | select(length > 0)' "$release_json")" || die "Firebase createTime is missing"
firebase_display_version="$(jq -er '.displayVersion | strings | select(length > 0)' "$release_json")" || die "Firebase displayVersion is missing"
firebase_build_version="$(jq -er '.buildVersion | strings | select(test("^[0-9]+$"))' "$release_json")" || die "Firebase buildVersion is missing or invalid"
release_notes="$(jq -er '.releaseNotes.text | strings | select(length > 0)' "$release_json")" || die "Firebase releaseNotes.text is missing"

note_environment="$(release_note_field ENV)"
note_channel="$(release_note_field CHANNEL)"
note_build="$(release_note_field BUILD)"
note_sha256="$(normalize_sha256 "$(release_note_field SHA256)")"

[[ "$note_environment" == "PRODUCTION" ]] || die "ENV must be PRODUCTION"
[[ "$note_channel" == "direct" ]] || die "CHANNEL must be direct"
[[ "$note_build" =~ ^[0-9]+$ ]] || die "BUILD must be an Android versionCode"
[[ "$note_sha256" =~ ^[0-9a-f]{64}$ ]] || die "SHA256 must be a 64-character hex digest"

badging="$($aapt2_bin dump badging "$apk_path")" || die "aapt2 could not read the APK"
package_line="$(printf '%s\n' "$badging" | awk '/^package: / { print; exit }')"
[[ -n "$package_line" ]] || die "APK package metadata is missing"

apk_package="$(printf '%s\n' "$package_line" | sed -n "s/.* name='\([^']*\)'.*/\1/p")"
apk_version_code="$(printf '%s\n' "$package_line" | sed -n "s/.* versionCode='\([^']*\)'.*/\1/p")"
apk_version_name="$(printf '%s\n' "$package_line" | sed -n "s/.* versionName='\([^']*\)'.*/\1/p")"
[[ -n "$apk_package" && -n "$apk_version_code" && -n "$apk_version_name" ]] || die "APK package metadata is incomplete"
[[ "$apk_version_code" =~ ^[0-9]+$ ]] || die "APK versionCode is not numeric"

signer_output="$($apksigner_bin verify --verbose --print-certs "$apk_path")" || die "APK signature verification failed"
mapfile_command="mapfile"
if ! command -v mapfile >/dev/null 2>&1; then
  mapfile_command="readarray"
fi
if ! command -v "$mapfile_command" >/dev/null 2>&1; then
  # macOS ships Bash 3, which has neither mapfile nor readarray.
  signer_digests="$(printf '%s\n' "$signer_output" | sed -n 's/^Signer #[0-9][0-9]* certificate SHA-256 digest: //p')"
  signer_count="$(printf '%s\n' "$signer_digests" | awk 'NF { count += 1 } END { print count + 0 }')"
  [[ "$signer_count" == "1" ]] || die "APK must have exactly one signer SHA-256 digest"
  apk_cert_sha256="$(normalize_sha256 "$signer_digests")"
else
  declare -a signer_digest_array
  "$mapfile_command" -t signer_digest_array < <(printf '%s\n' "$signer_output" | sed -n 's/^Signer #[0-9][0-9]* certificate SHA-256 digest: //p')
  [[ "${#signer_digest_array[@]}" == "1" ]] || die "APK must have exactly one signer SHA-256 digest"
  apk_cert_sha256="$(normalize_sha256 "${signer_digest_array[0]}")"
fi

expected_cert_sha256="$(normalize_sha256 "$expected_cert_sha256")"
apk_sha256="$(normalize_sha256 "$(sha256_file "$apk_path")")"

[[ "$expected_cert_sha256" =~ ^[0-9a-f]{64}$ ]] || die "expected certificate SHA-256 is invalid"
[[ "$apk_package" == "$expected_package" ]] || die "APK package name does not match the expected package"
[[ "$apk_version_code" == "$firebase_build_version" ]] || die "APK versionCode does not match Firebase buildVersion"
[[ "$apk_version_code" == "$note_build" ]] || die "APK versionCode does not match release-notes BUILD"
[[ "$apk_version_name" == "$firebase_display_version" ]] || die "APK versionName does not match Firebase displayVersion"
[[ "$apk_sha256" == "$note_sha256" ]] || die "APK SHA-256 does not match release-notes SHA256"
[[ "$apk_cert_sha256" == "$expected_cert_sha256" ]] || die "APK signing certificate does not match the production trust anchor"

mkdir -p "$(dirname "$output_path")"
jq -n \
  --arg firebaseReleaseName "$firebase_release_name" \
  --arg firebaseCreateTime "$firebase_create_time" \
  --arg packageName "$apk_package" \
  --arg versionName "$apk_version_name" \
  --arg versionCode "$apk_version_code" \
  --arg sha256 "$apk_sha256" \
  --arg signingCertificateSha256 "$apk_cert_sha256" \
  '{
    firebaseReleaseName: $firebaseReleaseName,
    firebaseCreateTime: $firebaseCreateTime,
    packageName: $packageName,
    versionName: $versionName,
    versionCode: ($versionCode | tonumber),
    sha256: $sha256,
    signingCertificateSha256: $signingCertificateSha256
  }' > "$output_path"

echo "Verified ${apk_package} ${apk_version_name} (${apk_version_code})"
