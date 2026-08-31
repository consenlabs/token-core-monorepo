# imToken Android 官方 APK

[English](README.en.md)

这里是 imToken Android 官方 APK 的公开发布入口。正式版本发布在本仓库的 [GitHub Releases](https://github.com/consenlabs/token-core-monorepo/releases)，标签格式为 `imtoken-android-v{versionName}+{versionCode}`。

## 安全下载

- 只信任 `token.im` 和 `github.com/consenlabs/token-core-monorepo`。
- 不要安装来自私信、搜索广告、二维码或第三方网盘的 APK。
- imToken 不会索要你的助记词、私钥或密码。

每个正式版本固定提供三个文件：

- `imToken-{versionName}.{versionCode}-release.apk`
- `SHA256SUMS`
- `imtoken-{versionName}.{versionCode}.manifest.json`

请从同一个 Release 下载这三个文件，并按照 [APK 校验指南](verify.md) 检查 SHA-256、包名、版本和签名。还应将 APK 的 SHA-256 与 [imToken 官方帮助中心公布的记录](https://support.token.im/hc/zh-cn/articles/4405256632601) 对比；不要只信任与 APK 放在同一 Release 中的校验文件。

任何文件缺失、校验结果不一致或 Release 标签异常时，都不要安装。

## iOS 与支持

iOS 版本只通过 Apple App Store 安装，并确认开发者为 `IMTOKEN PTE.LTD.`。

如果发现可疑下载或校验失败，请通过 [imToken 官方帮助中心](https://support.token.im/hc/zh-cn) 或 `support@token.im` 联系支持。
