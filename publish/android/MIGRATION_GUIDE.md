# 从Gradle发布迁移到JReleaser指南

本文档详细介绍了我们从Gradle传统发布方式迁移到JReleaser的过程，适用于项目维护者和贡献者参考。

## 迁移背景

由于Sonatype的旧版OSSRH将要停止运行，我们需要迁移到新的发布方式。JReleaser提供了一个现代化的发布工具，可以简化发布流程，并支持多种发布目标，包括Maven中央仓库。

## 主要变更内容

### 1. 构建系统配置变更
- 移除了 `io.github.gradle-nexus.publish-plugin` 依赖
- 添加了 `org.jreleaser` 插件
- 更新了GitHub Actions工作流配置

### 2. 发布API迁移
- **从Nexus2 API迁移到Central Portal API**
- 旧版: 使用OSSRH staging repository流程
- 新版: 直接使用Central Portal Publisher API

### 3. 环境变量名称变更
- 旧版: `ORG_GRADLE_PROJECT_sonatypeUsername`, `ORG_GRADLE_PROJECT_sonatypePassword`
- 新版: `JRELEASER_MAVENCENTRAL_USERNAME`, `JRELEASER_MAVENCENTRAL_PASSWORD`

### 4. 发布命令变更
- 旧版: `./gradlew publishToSonatype closeSonatypeStagingRepository`
- 新版: `./gradlew jreleaserDeploy`

### 5. GitHub Release处理
- **重要变更**: 禁用了Android工作流的GitHub Release功能
- 原因: iOS工作流已经处理GitHub Release，避免冲突
- 解决方案: 只进行Maven Central发布，不创建GitHub Release

## 迁移步骤详解

### 步骤1: 更新build.gradle文件

```groovy
plugins {
    id("maven-publish")
    id("signing")
    id("org.jreleaser") version "1.18.0"  // 添加JReleaser插件
}

// 移除旧的nexus-publish插件配置
// 保留现有的publishing和signing配置

jreleaser {
    gitRootSearch = true
    dryrun = false

    project {
        name = 'token-core'
        description = 'A secure and efficient Android library for Web3 wallet management, supporting multiple blockchains and token standards'
        website = 'https://github.com/consenlabs/token-core-monorepo'
        license = 'Apache-2.0'
        java {
            groupId = this.group
            version = this.version
        }
    }

    // 禁用GitHub Release，避免与iOS工作流冲突
    release {
        github {
            enabled = false
            skipTag = true
            skipRelease = true
        }
    }

    signing {
        active = 'ALWAYS'
        armored = true
    }
    
    // 使用Central Portal API而不是Nexus2
    deploy {
        maven {
            mavenCentral {
                sonatype {
                    active = 'ALWAYS'
                    url = 'https://central.sonatype.com/api/v1/publisher'
                    stagingRepository('build/staging-deploy')
                    
                    // 专门为AAR包装类型配置artifact覆盖
                    artifactOverride {
                        groupId = this.group
                        artifactId = 'token-core'
                        verifyPom = false
                        sourceJar = false
                        javadocJar = false
                    }
                }
            }
        }
    }
}
```

### 步骤2: 生成Central Portal Token

**重要**: Central Portal使用不同的认证系统，需要生成新的Token：

1. 登录 [central.sonatype.com](https://central.sonatype.com)
2. 进入 Account 页面
3. 生成 User Token
4. **注意**: Token只显示一次，需要立即保存

### 步骤3: 更新GitHub Actions配置

```yaml
env:
  JRELEASER_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  JRELEASER_GPG_PASSPHRASE: ${{ secrets.SIGNING_SECRET }}
  JRELEASER_GPG_PUBLIC_KEY: ${{ secrets.GPG_PUBLIC_KEY }}
  JRELEASER_GPG_SECRET_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
  # 使用Central Portal凭据
  JRELEASER_MAVENCENTRAL_USERNAME: ${{ secrets.OSSRH_USERNAME }}
  JRELEASER_MAVENCENTRAL_PASSWORD: ${{ secrets.OSSRH_PASSWORD }}

# 移除contents: write权限（不再需要创建GitHub Release）
permissions:
  pull-requests: read

# 使用jreleaserDeploy命令
- name: Publish with JReleaser
  run: |
    pushd ${{github.workspace}}
    VERSION=${{steps.getversion.outputs.version}} ./publish/android/gradlew -p publish/android jreleaserDeploy
    popd
```

### 步骤4: 更新GitHub Secrets

需要更新以下Secrets：
- `OSSRH_USERNAME`: Central Portal用户名
- `OSSRH_PASSWORD`: Central Portal Token（不是旧的OSSRH密码）
- `GPG_PUBLIC_KEY`: GPG公钥
- `GPG_PRIVATE_KEY`: GPG私钥
- `SIGNING_SECRET`: GPG密码

## 关键决策说明

### 为什么选择Central Portal API而不是Nexus2？

1. **避免staging profile问题**: Nexus2 API需要查找staging profile，但查找失败
2. **权限同步问题**: Central Portal和OSSRH系统存在数据同步延迟
3. **官方推荐**: Central Portal API是官方推荐的新标准发布方式
4. **简化流程**: 直接发布到Maven Central，无需手动staging操作

### 为什么禁用GitHub Release？

1. **避免冲突**: iOS工作流已经创建GitHub Release
2. **标签冲突**: 两个工作流都尝试创建相同的Git标签会失败
3. **职责分离**: iOS负责GitHub Release，Android只负责Maven发布

## 本地验证与测试

### 验证配置
```bash
cd publish/android
VERSION=1.0.0-test ./gradlew jreleaserConfig
```

### 检查生成的配置
```bash
cat build/jreleaser/config/jreleaser.yml
```

### 干运行测试（需要环境变量）
```bash
export JRELEASER_MAVENCENTRAL_USERNAME="your-username"
export JRELEASER_MAVENCENTRAL_PASSWORD="your-token"
export JRELEASER_GPG_PASSPHRASE="your-gpg-passphrase"
export JRELEASER_GPG_PUBLIC_KEY="$(cat ~/.gnupg/public.key)"
export JRELEASER_GPG_SECRET_KEY="$(cat ~/.gnupg/private.key)"

VERSION=1.0.0-test ./gradlew jreleaserDeploy --dry-run
```

## 常见问题解答

### Q: 看到"[upload] Uploading is not enabled. Skipping"日志是什么意思？
A: 这是正常的。JReleaser有多个功能模块：
- `deploy`: 用于Maven发布（我们使用的）
- `upload`: 用于上传到FTP、S3等其他服务（我们未启用）
- 这个日志只是告诉你upload功能被跳过了，不影响Maven发布

### Q: 如何查看发布日志？
A: JReleaser生成详细的日志文件：
- `build/jreleaser/trace.log` - 详细的执行日志
- `build/jreleaser/output.properties` - 输出属性
- GitHub Actions中也会显示实时日志

### Q: 发布后多久能在Maven Central看到？
A: 使用Central Portal API后，通常几分钟内就能在Maven Central看到新版本。

### Q: 如何处理发布失败？
A: 常见失败原因和解决方法：
1. **401认证错误**: 检查是否使用了正确的Central Portal Token
2. **GPG签名问题**: 确认GPG密钥配置正确
3. **网络问题**: 重新触发工作流
4. **权限问题**: 确认namespace已在Central Portal验证

### Q: 为什么不能使用旧的OSSRH凭据？
A: Central Portal使用不同的认证系统，必须生成新的Portal Token。旧的OSSRH用户名/密码不能用于Central Portal API。

## 迁移验证清单

- [ ] build.gradle已更新为使用JReleaser插件
- [ ] 已生成Central Portal Token
- [ ] GitHub Secrets已更新为新的环境变量名
- [ ] GitHub Actions工作流已更新
- [ ] 本地测试配置验证通过
- [ ] 首次发布测试成功
- [ ] 确认Maven Central中能找到新版本

## 总结

这次迁移的核心是从复杂的OSSRH staging流程迁移到简化的Central Portal直接发布流程。主要优势：

1. **简化流程**: 无需手动staging操作
2. **更快发布**: 几分钟内即可在Maven Central看到
3. **更可靠**: 避免了staging profile查找等问题
4. **现代化**: 使用官方推荐的最新发布方式

通过禁用Android工作流的GitHub Release功能，我们避免了与iOS工作流的冲突，实现了职责分离：iOS负责GitHub Release，Android专注于Maven发布。 