# Public APK 发布维护手册

本文档面向仓库管理员、Release 操作人和 Security reviewer。普通下载用户请阅读 [README.md](README.md)。

## 发布边界

- 本仓库不构建、不修改、不重新签名 APK。
- 工作流只读取一个明确指定的 Firebase App Distribution release。
- 只有 `ENV: PRODUCTION`、`CHANNEL: direct` 且通过包名、版本、SHA-256 和生产签名证书校验的 APK 才能发布。
- 正式发布使用 immutable GitHub Release，并固定包含 APK、`SHA256SUMS` 和 manifest 三个资产。

## GitHub 配置

1. 启用 repository immutable releases。
2. 创建 `public-apk-publish` Environment，只允许 `main` 分支部署。
3. 启用 prevent self-review 和 no admin bypass。
4. 将 [`@consenlabs/security`](https://github.com/orgs/consenlabs/teams/security) 设为 required reviewer。团队的 Read 权限足以审批 Environment deployment；这不等同于 PR review 或 CODEOWNERS approval。
5. 仓库管理员确认 immutable releases 已启用后，在该 Environment 设置 `PUBLIC_APK_IMMUTABLE_RELEASES_ENABLED=true`。不要为查询仓库管理设置而向工作流提供管理员 PAT。

Environment variables：

| Variable | Purpose |
| --- | --- |
| `PUBLIC_APK_WIF_PROVIDER` | Google Cloud Workload Identity Provider |
| `PUBLIC_APK_FIREBASE_READER_SERVICE_ACCOUNT` | 只读 Firebase service account |
| `PUBLIC_APK_FIREBASE_PROJECT_NUMBER` | Firebase project number |
| `PUBLIC_APK_FIREBASE_APP_ID` | Firebase Android app ID |
| `PUBLIC_APK_CERT_SHA256` | Security 独立确认的生产签名证书 SHA-256 |
| `PUBLIC_APK_IMMUTABLE_RELEASES_ENABLED` | 管理员对 immutable releases 设置的受保护确认 |

## Google Cloud 配置

Service account 只授予 `roles/firebaseappdistro.viewer`，通过 GitHub OIDC/Workload Identity Federation 登录，不保存 JSON key。

WIF attribute condition 固定为：

```text
assertion.repository_owner_id == "19341221" &&
assertion.repository_id == "552787159" &&
assertion.ref == "refs/heads/main" &&
assertion.environment == "public-apk-publish" &&
assertion.workflow_ref == "consenlabs/token-core-monorepo/.github/workflows/promote-public-apk.yml@refs/heads/main"
```

## Firebase release 约定

Firebase release notes 必须各包含且只包含一行以下字段，其他说明行可以共存：

```text
ENV: PRODUCTION
CHANNEL: direct
BUILD: <APK AndroidManifest versionCode>
SHA256: <APK SHA-256>
```

Firebase `buildVersion` 也必须等于 APK `versionCode`。工作流不会把 Firebase 后台记录当作 APK build 号的唯一来源，而是读取 APK 后进行三方比对。

## 发布步骤

1. 在 `main` 手动运行 `Promote public imToken APK`。
2. 输入固定的 `firebase_release_id` 以及简体中文、英文公开发布说明。
3. 首次运行保持 `dry_run=true`，由 Security 审批并检查校验结果。
4. 使用同一个 Firebase release ID 再次运行，设置 `dry_run=false` 正式发布。
5. 下载已发布的三个资产并再次执行 [verify.md](verify.md) 中的校验。
6. 将新版本 SHA-256 同步到 imToken 官方网站或帮助中心，提供独立于 GitHub Release 的可信记录。

## 失败、重试与撤销

- 发布前失败时，工作流只删除带有当前 run ownership marker、目标 commit 和标签完全匹配的 draft/tag。
- 发布响应丢失后可以用相同 Firebase release ID 重试；只有远端 release 已 immutable 且三个资产与本地重新生成结果逐字节一致时才视为成功。
- 已发布 release 不覆盖、不删除。新 APK 的 `versionCode` 必须严格大于所有已有公开 APK。
- 发现问题时，在受影响 release 中加入撤销说明，并发布具有更高 `versionCode` 的修复版本。
