# 从Gradle发布迁移到JReleaser指南

本文档详细介绍了我们从Gradle传统发布方式迁移到JReleaser的过程，适用于项目维护者和贡献者参考。

## 迁移背景

由于Sonatype的旧版OSSRH将要停止运行，我们需要迁移到新的发布方式。JReleaser提供了一个现代化的发布工具，可以简化发布流程，并支持多种发布目标，包括Maven中央仓库。

## 主要变更内容

1. 构建系统配置变更：
   - 移除了 `io.github.gradle-nexus.publish-plugin` 依赖
   - 添加了 `org.jreleaser` 插件
   - 更新了GitHub Actions工作流配置

2. 环境变量名称变更：
   - 旧版: `ORG_GRADLE_PROJECT_sonatypeUsername`, `ORG_GRADLE_PROJECT_sonatypePassword`, etc.
   - 新版: `JRELEASER_NEXUS2_USERNAME`, `JRELEASER_NEXUS2_PASSWORD`, etc.

3. 发布命令变更：
   - 旧版: `./gradlew publishToSonatype closeSonatypeStagingRepository`
   - 新版: `./gradlew jreleaserDeploy`

## 迁移步骤总结

1. 更新`build.gradle`文件，替换发布插件
2. 创建JReleaser配置部分
3. 更新GitHub Actions工作流配置
4. 设置GPG签名密钥
5. 更新GitHub Actions Secrets

## 关键配置说明

### JReleaser配置

JReleaser配置位于项目根目录的`build.gradle`文件中：

```groovy
jreleaser {
    project {
        name = 'token-core'
        description = 'A android library for web3'
        website = 'https://github.com/consenlabs/token-core-monorepo'
        license = 'Apache-2.0'
        java {
            groupId = this.group
            version = this.version
        }
    }
    
    deploy {
        maven {
            nexus2 {
                maven {
                    active = 'ALWAYS'
                    url = 'https://s01.oss.sonatype.org/service/local'
                    username = '{{jreleaser.nexus2.username}}'
                    password = '{{jreleaser.nexus2.password}}'
                    closeRepository = true
                    releaseRepository = true
                    stagingRepositories = ['build/staging-deploy']
                    publication = 'Production'
                    sign = true
                    gpg {
                        publicKey = '{{jreleaser.gpg.public.key}}'
                        secretKey = '{{jreleaser.gpg.secret.key}}'
                        passphrase = '{{jreleaser.gpg.passphrase}}'
                    }
                }
            }
        }
    }
}
```

### GitHub Actions配置

在GitHub Actions工作流文件中，我们更新了环境变量和发布步骤：

```yaml
env:
  JRELEASER_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  JRELEASER_GPG_PASSPHRASE: ${{ secrets.SIGNING_SECRET }}
  JRELEASER_GPG_PUBLIC_KEY: ${{ secrets.GPG_PUBLIC_KEY }}
  JRELEASER_GPG_SECRET_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
  JRELEASER_NEXUS2_USERNAME: ${{ secrets.OSSRH_USERNAME }}
  JRELEASER_NEXUS2_PASSWORD: ${{ secrets.OSSRH_PASSWORD }}

# ...

- name: Publish with JReleaser
  run: |
    pushd ${{github.workspace}}/publish/android
    VERSION=${{steps.getversion.outputs.version}} ./gradlew jreleaserDeploy
    popd
```

## 本地验证与测试

在提交代码前，可以进行本地测试：

1. 生成JReleaser配置但不实际发布：
   ```bash
   ./gradlew jreleaserConfig
   ```

2. 执行干运行发布（不会实际上传）：
   ```bash
   ./gradlew jreleaserDeploy --dry-run
   ```

3. 检查生成的配置：
   ```bash
   cat build/jreleaser/config/jreleaser.yml
   ```

## 常见问题解答

### 如何查看发布日志？

JReleaser生成详细的日志文件，位于：
- `build/jreleaser/trace.log` - 详细的执行日志
- `build/jreleaser/output.properties` - 输出属性

### 如何监控发布进度？

JReleaser提供了详细的构建输出，可以在GitHub Actions日志中实时查看。此外，成功发布后，制品通常会在几小时内出现在Maven中央仓库中。

### 如何处理发布失败？

1. 查看日志文件确定失败原因
2. 常见原因包括:
   - GPG签名问题
   - 凭据错误
   - 网络问题

修复问题后，可以重新触发工作流程。 