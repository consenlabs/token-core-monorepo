# Official imToken Android APK

[简体中文](README.md)

This is the public release channel for the official imToken Android APK. Production versions are published under this repository's [GitHub Releases](https://github.com/consenlabs/token-core-monorepo/releases) with tags in the form `imtoken-android-v{versionName}+{versionCode}`.

## Download safely

- Trust only `token.im` and `github.com/consenlabs/token-core-monorepo`.
- Never install an APK received through direct messages, search ads, QR codes, or third-party file hosts.
- imToken will never ask for your mnemonic, private key, or password.

Every production release contains exactly three files:

- `imToken-{versionName}.{versionCode}-release.apk`
- `SHA256SUMS`
- `imtoken-{versionName}.{versionCode}.manifest.json`

Download all three files from the same Release and follow the [APK verification guide](verify.en.md) to check the SHA-256 digest, package name, version, and signature. Also compare the APK SHA-256 with the value published by the [official imToken Help Center](https://support.token.im/hc/en-us/articles/4405256632601). Do not rely only on verification files distributed beside the APK.

Do not install the APK if a file is missing, a verification result differs, or the Release tag is unexpected.

## iOS and support

Install the iOS app only from the Apple App Store and confirm that the developer is `IMTOKEN PTE.LTD.`.

Report suspicious downloads or verification failures through the [official imToken Help Center](https://support.token.im/hc/en-us) or `support@token.im`.
