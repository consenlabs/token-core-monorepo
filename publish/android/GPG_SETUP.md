# GPG密钥设置指南

本文档介绍如何生成和配置用于JReleaser Maven发布的GPG密钥。

## 生成GPG密钥

1. 安装GPG工具：
   ```bash
   # macOS
   brew install gnupg
   
   # Ubuntu/Debian
   sudo apt-get install gnupg
   ```

2. 生成新的GPG密钥对：
   ```bash
   gpg --full-generate-key
   ```
   
   按照提示选择：
   - 密钥类型：RSA and RSA (default)
   - 密钥长度：4096
   - 有效期：0 (永不过期) 或根据需要设置
   - 输入您的个人信息（姓名、邮箱等）
   - 设置一个安全的密码

3. 确认已生成的密钥：
   ```bash
   gpg --list-secret-keys --keyid-format LONG
   ```
   
   注意输出中形如 `rsa4096/ABCDEF1234567890` 的部分，其中 `ABCDEF1234567890` 是您的密钥ID。

## 导出GPG密钥用于GitHub Actions

1. 导出公钥（ASCII格式）：
   ```bash
   gpg --armor --export your_email@example.com > public-key.gpg
   ```

2. 导出私钥（ASCII格式）：
   ```bash
   gpg --armor --export-secret-keys your_email@example.com > private-key.gpg
   ```

3. 在GitHub仓库中添加以下Secrets：
   - `GPG_PUBLIC_KEY`: 公钥文件 public-key.gpg 的内容
   - `GPG_PRIVATE_KEY`: 私钥文件 private-key.gpg 的内容
   - `SIGNING_SECRET`: 您在创建GPG密钥时设置的密码

## 发布到Sonatype OSSRH

确保您已经：

1. 在Sonatype OSSRH (https://central.sonatype.com/) 注册了一个账号
2. 创建了一个项目/包的命名空间（例如：io.github.yourusername）
3. 将以下信息添加为GitHub Secrets：
   - `OSSRH_USERNAME`: 您的Sonatype用户名
   - `OSSRH_PASSWORD`: 您的Sonatype密码

## 将GPG公钥分发到公钥服务器

为了让其他人能够验证您的签名，需要将您的公钥上传到公钥服务器：

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
```

替换 `YOUR_KEY_ID` 为您之前找到的密钥ID。

## 验证公钥是否上传成功

```bash
gpg --keyserver keyserver.ubuntu.com --recv-keys YOUR_KEY_ID
```

## 本地测试签名

您可以在本地测试GPG签名：

```bash
echo "test" > test.txt
gpg --sign test.txt
```

这应该会创建一个名为`test.txt.gpg`的签名文件。

## 故障排除

- 如果在发布过程中遇到签名错误，检查密钥是否正确导出，以及密码是否正确设置。
- 确保环境变量名称与JReleaser配置中使用的变量名称相匹配。
- 在本地运行 `./gradlew jreleaserDeploy --dry-run` 可以测试配置是否正确，而不会实际发布。