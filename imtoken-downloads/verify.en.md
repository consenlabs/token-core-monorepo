# Verify an imToken Android APK

[简体中文](verify.md) · [Back to downloads](README.en.md)

Complete every check before installation. Do not install the APK if any check fails.

## 1. Confirm the source and files

Use only this repository's [GitHub Releases](https://github.com/consenlabs/token-core-monorepo/releases) and select a release tagged `imtoken-android-v{versionName}+{versionCode}`. Download all three files from that same Release:

- the APK
- `SHA256SUMS`
- the manifest JSON

The Release must not contain any other installer.

## 2. Verify SHA-256

Linux:

```bash
sha256sum -c SHA256SUMS
```

macOS:

```bash
shasum -a 256 imToken-*-release.apk
shasum -a 256 imtoken-*.manifest.json
```

Windows PowerShell:

```powershell
Get-FileHash .\imToken-*-release.apk -Algorithm SHA256
Get-FileHash .\imtoken-*.manifest.json -Algorithm SHA256
```

The results must match `SHA256SUMS` and the manifest `sha256` value exactly. Also compare the APK SHA-256 with the version table published by the [official imToken Help Center](https://support.token.im/hc/en-us/articles/4405256632601), which provides a verification source independent of the GitHub Release.

## 3. Verify the package and version

With Android SDK Build Tools installed, run:

```bash
aapt2 dump badging imToken-*-release.apk | head -1
```

The output must show:

- package name `im.token.app`
- a `versionName` equal to the manifest `versionName`
- a `versionCode` equal to the manifest `versionCode` and the number after `+` in the Release tag

## 4. Verify the APK signature

```bash
apksigner verify --verbose --print-certs imToken-*-release.apk
```

Verification must succeed, and `Signer #1 certificate SHA-256 digest` must equal the manifest `signingCertificateSha256`. Do not install the APK if the certificate or SHA-256 differs from a previously trusted installation; contact imToken support instead.
