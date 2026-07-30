## 为什么要做

imKey Pro 的 onboarding、激活、绑定、应用管理、地址获取和硬件签名能力当前主要通过 native/mobile SDK 集成到 imToken、imKey Manager 等宿主应用中。Web 端希望通过浏览器 WebUSB 与 imKey Pro 建立连接，并在页面内完成完整 onboarding 和后续硬件钱包操作。

现有 `token-core/tcx-wasm` 已经证明软件钱包能力可以通过 wasm + npm 交付给前端使用。imKey 侧需要建立等价的 Web 集成形态，使 imKey 核心业务能力能够随同 token-core wasm 以统一 npm 包发布，同时保持现有移动端静态库和桌面端 native 集成稳定。

本提案的核心判断：

1. **imKey Core wasm 转换技术可行**：现有 `ikc`/`ikc-device`/`coin-*` 中的大量业务逻辑、APDU 编排、响应解析和错误映射可以复用。
2. **WebUSB 连接与发送必须由浏览器 JS 持有和执行**：WebUSB 是浏览器提供的异步 JavaScript API，Rust wasm 不应按 native `hidapi` 模式直接持有设备句柄。
3. **需要抽象 transport、TSM 网络和绑定 key 存储边界**：native/mobile/web 的差异集中在设备通讯、网络请求、本地存储和 API 包装层，不应扩散到每个业务接口。
4. **统一 npm 包是推荐交付形态**：前端只依赖一个 web package，内部同时导出 token-core 软件钱包能力和 imKey 硬件钱包能力。

---

## 变更内容

- 新增 imKey WebAssembly 集成形态，用于在浏览器环境中调用 imKey Core 业务能力。
- 新增 WebUSB transport adapter：浏览器 JS 负责 `requestDevice/open/selectConfiguration/claimInterface/transferOut/transferIn`，wasm 通过异步接口请求发送 APDU。
- 抽象 imKey APDU transport 边界，使现有 native `hidapi`、mobile callback 和 web WebUSB 可以共享上层业务逻辑。
- 抽象 TSM client 边界，使 web 端使用 `fetch` 或由前端注入的 TSM client，而不是复用 native `hyper/tokio` 网络实现。
- 抽象绑定 key storage 边界，使 web 端使用 IndexedDB/localStorage 或由前端注入的 storage adapter，而不是复用文件系统路径。
- 新增 npm package facade，将现有 `tcx-wasm` 能力和新增 imKey wasm 能力统一导出。
- 增加浏览器示例或测试页面，用于验证 WebUSB 连接、基础设备信息读取、绑定流程和代表性签名流程。

---

## 能力清单

### 新增能力

- `imkey-core-wasm-webusb`：浏览器通过 WebUSB 连接 imKey Pro，并通过 wasm 复用 imKey Core 业务逻辑。
- `imkey-web-transport`：Web 端保存 WebUSB 设备连接，并为 wasm 提供异步 APDU 发送接口。
- `imkey-web-platform-adapters`：Web 端提供 TSM 请求和绑定 key 存储适配能力。
- `unified-web-npm-package`：以一个 npm 包导出 token-core wasm 和 imKey Core wasm 能力。

### 修改的能力

- `ikc-transport`：从现有平台条件编译的 `send_apdu` 形态演进为可被 native/mobile/web adapter 复用的 transport 边界。
- `ikc-device`：绑定、激活、应用管理等依赖 TSM 和 key 文件的流程需要通过平台 adapter 获取网络和存储能力。

---

## 影响范围

- **imKey Core Rust 代码**
  - `imkey-core/ikc-transport`：定义 transport 抽象，保留 native `hidapi` 和 mobile callback 实现。
  - `imkey-core/ikc-device`：梳理 TSM client、绑定 key storage、APDU transport 的依赖边界。
  - `imkey-core/ikc`：保留现有 C ABI，对 wasm 新增专用入口或 facade。
  - `imkey-core/ikc-wallet/coin-*`：原则上不直接感知 WebUSB，仅继续依赖 APDU 发送能力。

- **WebAssembly / npm**
  - 新增 `ikc-wasm` 或统一 `wallet-core-wasm` facade crate。
  - 扩展现有 `publish/npm` 构建，使一个 npm 包同时包含 token-core wasm 和 imKey wasm。
  - 新增 TypeScript WebUSB transport、TSM client、storage adapter 类型定义。

- **现有移动端静态库**
  - 不应改变现有 `call_imkey_api`、`set_callback`、mobile callback APDU 通道的对外行为。
  - 移动端静态库继续按现有 native/mobile feature 构建，不依赖 WebUSB 或浏览器 API。

- **现有桌面端 / imKey Manager**
  - native `hidapi` 通路继续保留。
  - 可复用新的 transport 抽象，但不改变现有设备连接语义和错误码。

---

## 非目标

- 不在本提案中改造 imKey 固件或 WebUSB descriptor。
- 不在本提案中改变 imKey APDU 业务协议。
- 不在本提案中重写各链地址或签名算法。
- 不在本提案中要求前端业务页面直接构造 APDU。
- 不在本提案中移除现有 C ABI 或移动端静态库发布方式。
- 不在本提案中把 TSM 服务端迁移或重构为新后端。

---

## 上线策略

建议分阶段推进：

1. **Phase 0：技术验证**
   - 新增最小 wasm/web facade。
   - WebUSB 连接 imKey Pro。
   - 跑通 `get_seid`、`get_sn`、`get_life_time` 等基础 APDU。
   - 验证浏览器权限、endpoint、超时、断开重连和错误映射。

2. **Phase 1：onboarding 核心闭环**
   - 跑通 `device_secure_check`、`device_activate`、`bind_check`、`bind_display_code`、`bind_acquire`。
   - 引入 web storage adapter 保存绑定 key。
   - 引入 web TSM client 处理激活、绑定和应用管理所需网络请求。

3. **Phase 2：账户与签名能力**
   - 跑通 `get_address`、`register_address`、`sign_tx`、`sign_message` 的代表性链路。
   - 先覆盖 ETH/BTC/TRON 等主路径，再逐步扩展到其他 coin crate。

4. **Phase 3：统一 npm 发布**
   - 与现有 `tcx-wasm` 合并到统一 npm 包。
   - 补齐 TypeScript 类型、浏览器示例、文档和 CI 构建检查。

5. **Phase 4：应用管理与升级类能力**
   - 覆盖 `app_download`、`app_update`、`app_delete`、`check_update`。
   - COS update 能力需要单独评审浏览器稳定性、断连恢复和失败回滚策略。

---

## 已确认 / 待确认事项

### 已确认

1. Web 端优先支持 Chrome/Edge。Safari/Firefox 等不支持 WebUSB 的浏览器展示明确的不支持提示，并禁用 imKey 连接/onboarding 入口。
2. TSM 服务允许浏览器跨域访问；Web 端可优先使用 `fetch` 直接访问 TSM 服务，同时保留业务方注入 TSM client 的能力。
3. 绑定 key 存储参考 `web.imkey.im`，使用 IndexedDB 保存 encrypted binding key blob，DB 名称可沿用或调整为 SDK 内部命名。
4. WebUSB 通讯协议与现有 native HID 分包不一致，应参考 `web.imkey.im/src/infra/webusb/transport.ts`：
   - 固定 64 字节 packet。
   - first chunk: `[4 字节填充][0xC3 命令标识][2 字节数据长度][最多 57 字节数据]`。
   - next chunk: `[4 字节填充][1 字节序列号][最多 59 字节数据]`。
   - response 中 `0xFF` 表示 device busy，需要继续读取/重试。
5. WebUSB 连接管理参考 `web.imkey.im/src/infra/webusb/device-manager.ts`：
   - request filters 当前可为空数组，由用户选择设备。
   - 如果设备未选择 configuration，默认 `selectConfiguration(1)`。
   - interface 和 endpoint 优先动态探测：遍历 interfaces，寻找同时具备 in/out endpoint 且可 claim 的 interface，优先 vendor specific class (`interfaceClass === 255`)。
   - 默认 endpoint 可参考 in=5 / out=4，但不应作为唯一硬编码来源。
6. 统一 npm 包名确定为 `@imtoken/wallet-core-web`。
7. 前端公开 API 只暴露业务能力，不要求业务方直接使用 wasm-pack 生成的底层文件。
8. 开发测试阶段需要保留 wasm-pack 生成文件，供本仓库示例/测试页面直接引用；这些文件作为构建产物和内部调试入口保留，不设计为长期公开 API。
9. imKey Pro WebUSB reference descriptor 已记录在 `doc/imkey-webusb-descriptor.md`：VID=`0x096E`、PID=`0x0891`、configuration=1、vendor-specific interface 优先、参考 interface=0、IN=5、OUT=4、packet size=64；SDK 运行时以动态 descriptor 探测结果为准。
