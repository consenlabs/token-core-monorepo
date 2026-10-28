# 校验 imToken Android APK

[English](verify.en.md) · [返回下载说明](README.md)

安装前请完成以下检查。任何一步失败都不要安装。

## 1. 确认下载来源和文件

只从本仓库的 [GitHub Releases](https://github.com/consenlabs/token-core-monorepo/releases) 下载标签为 `imtoken-android-v{versionName}+{versionCode}` 的版本，并从同一个 Release 获取：

- APK
- `SHA256SUMS`
- manifest JSON

Release 不应包含除此之外的其他安装文件。

## 2. 校验 SHA-256

Linux：

```bash
sha256sum -c SHA256SUMS
```

macOS：

```bash
shasum -a 256 imToken-*-release.apk
shasum -a 256 imtoken-*.manifest.json
```

Windows PowerShell：

```powershell
Get-FileHash .\imToken-*-release.apk -Algorithm SHA256
Get-FileHash .\imtoken-*.manifest.json -Algorithm SHA256
```

结果必须与 `SHA256SUMS` 及 manifest 中的 `sha256` 完全一致。还必须将 APK SHA-256 与 [imToken 官方帮助中心公布的版本记录](https://support.token.im/hc/zh-cn/articles/4405256632601) 对比，建立独立于 GitHub Release 的校验来源。

## 3. 校验包名和版本

安装 Android SDK Build Tools 后执行：

```bash
aapt2 dump badging imToken-*-release.apk | head -1
```

输出必须满足：

- 包名为 `im.token.app`
- `versionName` 等于 manifest 中的 `versionName`
- `versionCode` 等于 manifest 中的 `versionCode`，并与 Release 标签中 `+` 后的数字一致

## 4. 校验 APK 签名

```bash
apksigner verify --verbose --print-certs imToken-*-release.apk
```

命令必须验证成功，并且 `Signer #1 certificate SHA-256 digest` 必须等于 manifest 中的 `signingCertificateSha256`。证书或 SHA-256 与已安装的可信版本不一致时，不要继续安装，并联系 imToken 支持。
