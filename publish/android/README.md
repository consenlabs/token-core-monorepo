# Token Core Android 发布指南

本文档描述了如何使用JReleaser将Token Core Android库发布到Maven中央仓库。

## 先决条件

在开始发布过程前，确保你已经具备以下条件：

1. GPG密钥对 - 用于签名Maven制品
2. Sonatype OSSRH账号 - 用于发布到Maven中央仓库
3. 已正确设置的GitHub Actions密钥:
   - `OSSRH_USERNAME` - Sonatype账号用户名
   - `OSSRH_PASSWORD` - Sonatype账号密码
   - `SIGNING_SECRET` - GPG密钥密码
   - `GPG_PUBLIC_KEY` - GPG公钥（ASCII格式）
   - `GPG_PRIVATE_KEY` - GPG私钥（ASCII格式）

## 发布流程

### 本地测试发布

在推送到GitHub之前，你可以在本地测试发布流程：

1. 确保已经编译好AAR文件：
   ```bash
   ./gradlew assemble
   ```

2. 使用JReleaser执行本地验证：
   ```bash
   ./gradlew jreleaserConfig
   ```
   
3. 查看生成的配置并验证：
   ```bash
   cat build/jreleaser/config/jreleaser.yml
   ```

### GitHub Actions自动发布

当Pull Request被审核通过后，GitHub Actions工作流会自动执行以下步骤：

1. 构建Rust原生库
2. 构建Android AAR库
3. 使用JReleaser发布到Maven中央仓库
4. 发送Slack通知

整个流程无需人工干预，JReleaser会自动处理：
- 签名制品
- 上传到Sonatype OSSRH
- 关闭和发布Staging仓库
- 将库发布到Maven中央仓库

## 故障排除

如果发布过程中遇到问题，可以查看Actions运行的输出，特别是JReleaser的日志：
- `build/jreleaser/trace.log` - 详细的JReleaser执行日志
- `build/jreleaser/output.properties` - 输出属性

## 依赖引用

发布完成后，可以在其他项目中使用以下方式引用该库：

```kotlin
dependencies {
    implementation("io.github.consenlabs.android:token-core:$version")
}
```

其中 `$version` 是发布的版本号。 