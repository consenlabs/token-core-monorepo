# TSM 服务地址动态配置设计

## 背景

imKey Core 原来将 TSM base URL 固定在 `ikc-common` 常量中。构建 production、staging 和 development 包时需要修改 Rust 源码并重新构建，容易出现环境地址提交错误，也使 Android 和 iOS 的环境管理无法与前端统一。

## 方案

保留原生启动阶段调用的 `init_imkey_core_x` 不变，新增独立 Protobuf action：

```protobuf
message ConfigureTsmParam {
    string baseUrl = 1;
}
```

```text
method: configure_tsm
response: api.CommonResponse
```

token-v2 前端通过现有 `HardWalletAPI.callImKeyApi` 通道调用该 action，不新增 Android 或 iOS NativeModule 方法。TSM URL 来自前端现有 development、staging、production 构建配置。

浏览器 WASM 包通过统一 npm facade 暴露同等能力：

```ts
const imkey = createImKeyCore();
await imkey.configureTsm("https://example.com/imkey");
```

低层 `ikc-wasm` 同时导出 `configure_tsm(baseUrl)`，复用本模块的 URL 校验和进程生命周期规则。正式前端应调用 `configureTsm` facade；facade 会把 Rust 返回的规范化 URL 同步给 `FetchTsmClient`，确保后续浏览器 `fetch` 使用同一地址。

## Core 配置生命周期

- TSM URL 在 `ikc-common` 中以进程级线程安全状态保存。
- 首次显式配置成功后，同一规范化 URL 可重复配置，保证前端热重载幂等。
- 如果业务在显式配置前发起 TSM 请求，则兼容 fallback 会成为该进程的固定地址；之后再配置其他地址会返回 `imkey_tsm_url_already_configured`。
- 同一进程不能切换到不同 URL，避免并发请求或活跃钱包会话被运行时重定向。
- 公开接口只接受 HTTPS、合法 authority、无 userinfo、query 和 fragment 的 URL。
- URL 末尾的 `/` 会被移除，TSM action 必须以 `/` 开头。
- HTTP 请求开始前复制 endpoint，不在网络调用期间持有配置锁。

## 兼容策略

当前生产 URL 作为过渡期 fallback 保留。未调用 `configure_tsm` 的旧客户端继续访问原生产 TSM，因此本次新增接口不破坏已有 SDK。

原公开 Rust 常量 `ikc_common::constants::URL` 保留为 fallback 的兼容别名，避免已有 Rust 调用方出现源码级编译中断；Core 内部网络请求不再读取该常量。该别名可在后续 major 版本移除。

token-v2 更新后会在所有 TSM 操作前显式配置 URL。后续 major 版本可以移除 fallback，并在未配置时返回 `imkey_tsm_url_not_configured`，实现 fail-closed。

## 前端调用约束

- URL 只能来自构建期环境配置，不能来自用户输入或未经认证的远程配置。
- 应在任何可能访问 TSM 的业务调用之前完成配置。
- 前端使用缓存 Promise 确保每个 TSM 操作等待配置完成。
- `configure_tsm` 本身不能再次等待该 Promise，避免递归调用。
- production、staging 和 development 各自提供完整 base URL，包括 `/imkey` 路径。

## 测试策略

- URL 规范化、HTTPS、authority、userinfo、query、fragment 和长度测试。
- 首次配置、同值幂等和不同值拒绝测试。
- base URL 与 action 安全拼接测试。
- `configure_tsm` Protobuf/C ABI 分发测试。
- HTTP 层使用本地 loopback mock server，不再由普通单元测试访问外部 TSM。
- 真实 TSM 和 imKey 设备验证仍归入 `make test-hardware`。测试辅助入口读取可选的 `IMKEY_TSM_TEST_URL`，不会影响生产业务路径：

```bash
IMKEY_TSM_TEST_URL=https://staging.example.com/imkey make test-hardware
```

未设置该变量时，硬件测试继续使用兼容 fallback；设置后，进程内全部 TSM 硬件测试使用同一地址。
