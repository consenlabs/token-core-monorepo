## 背景

当前 imKey Core 的设备通讯路径分为两类：

- native desktop：`ikc-transport/src/hid_api.rs` 使用 `hidapi` 打开 USB HID 设备，并通过 `device.write/read/read_timeout` 收发设备消息。
- mobile：`ikc-transport/src/message.rs` 通过 `set_callback` 将 APDU 发送委托给宿主 App。

Web 端与 mobile 更接近：浏览器持有设备连接，wasm 业务逻辑不能按 native 方式直接打开系统设备。区别是 WebUSB API 是 Promise 异步模型，设备连接和传输对象存在于 JavaScript runtime 中。

因此，本方案采用“Rust/wasm 负责业务与 APDU，JavaScript 负责 WebUSB I/O”的边界。

---

## 目标 / 非目标

**目标：**

- 在浏览器中通过 WebUSB 连接 imKey Pro。
- 复用现有 `ikc`/`ikc-device`/`coin-*` 的 APDU 编排、业务流程、响应解析和错误语义。
- 新增 wasm web 入口，向前端提供业务 API，而不是让前端直接拼 APDU。
- 保持现有 native/mobile 静态库输出不受影响。
- 将平台差异限制在 transport、TSM client、storage、wasm facade 四个边界。

**非目标：**

- 不把 WebUSB API 直接写入 coin crate 或业务 crate。
- 不让 Rust wasm 直接保存浏览器 `USBDevice`。
- 不要求每个业务接口都写一份 wasm 专用实现。
- 不改变 imKey APDU 协议、错误码和现有 protobuf API 的兼容边界，除非后续评审明确批准。

---

## 总体架构

```text
前端业务页面
  -> TypeScript SDK facade
     -> WebUSB transport adapter 保存 USBDevice 并执行 transferOut/transferIn
     -> TSM client adapter 执行 fetch 或调用业务注入的网络层
     -> Storage adapter 读取/保存绑定 key
     -> wasm imKey facade
        -> ikc / ikc-device / coin-* 业务逻辑
        -> APDU 生成、响应校验、错误映射
```

核心原则：

- **连接在 JS**：`navigator.usb.requestDevice()` 返回的 `USBDevice` 由 TypeScript SDK 保存。
- **发送在 JS**：实际 `transferOut/transferIn` 由 WebUSB transport 执行。
- **业务在 Rust**：设备管理、绑定、签名等流程尽量复用 Rust 现有逻辑。
- **调用是异步的**：wasm 调用 transport 时返回 Promise/Future，不阻塞浏览器主线程。

---

## 设备连接流程

前端调用：

```ts
const imkey = await createImKeyCore({
  transport: new WebUsbImKeyTransport(),
  tsmClient,
  storage,
})

await imkey.connect()
```

内部流程：

1. TypeScript transport 调用 `navigator.usb.requestDevice(...)`，必须由用户点击等 user gesture 触发。
2. transport 调用 `device.open()`。
3. transport 根据 imKey WebUSB descriptor 选择 configuration、claim interface。
4. transport 记录 endpoint in/out、packet size、超时策略。
5. 如设备协议要求初始化握手，transport 执行握手。
6. SDK 将该 transport 与 wasm facade 绑定。

连接状态保存在 TypeScript SDK 中。wasm 不直接保存 `USBDevice`。

---

## 业务接口执行流程

以 `getSeid()` 为例：

```text
前端页面调用 imkey.getSeid()
  -> TypeScript facade 调 wasm get_seid()
  -> Rust 业务逻辑生成 APDU: 00A4040000
  -> Rust 请求发送 APDU
  -> wasm bridge 调 JS transport.sendApdu(apduHex, timeout)
  -> JS transport 使用已保存 USBDevice 执行 transferOut/transferIn
  -> JS transport 返回 APDU response hex
  -> Rust 校验 APDU status word 并解析响应
  -> wasm 返回 seid 给 TypeScript facade
  -> 前端页面获得 seid
```

签名、绑定、应用管理等复杂流程只是重复上述“Rust 生成下一条 APDU -> JS 发送 -> Rust 处理响应”的循环。

---

## Transport 抽象

### 设计选择

引入平台无关的 APDU transport 概念：

```rust
trait ApduTransport {
    async fn send_apdu(&self, apdu_hex: &str, timeout_seconds: u32) -> Result<String>;
}
```

不同平台提供不同 adapter：

| 平台 | adapter | 实际通讯方式 |
|------|---------|--------------|
| native desktop | HidApiTransport | `hidapi::HidDevice::write/read` |
| mobile | CallbackTransport | 宿主 App callback |
| web | WebUsbTransport bridge | JavaScript `USBDevice.transferOut/transferIn` |

业务逻辑只依赖 `ApduTransport`，不依赖 WebUSB、hidapi 或移动端 callback。

### 为什么不能只替换 `send_apdu`

现有 `send_apdu(apdu) -> Result<String>` 是同步函数。WebUSB 是异步 Promise API，且连接对象存在于 JavaScript runtime。直接把现有同步 `send_apdu` 替换成 WebUSB 会导致：

- Rust wasm 无法直接持有 `USBDevice`。
- 同步 Rust API 无法自然等待 Promise。
- native/mobile 现有调用方会被迫接受异步签名。
- 平台差异会扩散到业务 crate。

因此需要在 wasm web 入口上采用异步 API，同时保留 native/mobile 的现有同步 C ABI。

---

## WebUSB Transport Adapter

WebUSB adapter 优先使用 imKey 设备已经支持的 WebUSB interface 和协议参数。实现侧只承担浏览器 API 适配、连接状态管理、分包组包、超时和错误归一化，不重新定义 imKey 业务协议。

参考 `web.imkey.im/src/infra/webusb/transport.ts`，WebUSB packet framing 与现有 native HID framing 不同：

| 项目 | WebUSB | native HID |
|------|--------|------------|
| packet size | 64 bytes | 65 bytes write / 64 bytes read |
| first chunk 标识 | byte[4] = `0xC3` | byte[5] = `0x83` |
| first chunk 长度 | byte[5..6] big-endian length | byte[6..7] length |
| first chunk payload | byte[7..]，最多 57 bytes | byte[8..]，最多 57 bytes |
| next chunk 标识 | byte[4] = sequence | byte[5] = sequence |
| next chunk payload | byte[5..]，最多 59 bytes | byte[6..]，最多 59 bytes |
| busy indicator | response byte[4] = `0xFF` | native HID 现有实现未按该 WebUSB busy 规则处理 |

职责：

- 设备授权：`requestDevice`。
- 连接管理：`open`、`selectConfiguration`、`claimInterface`、`releaseInterface`、`close`。
- 数据传输：`transferOut(endpointOut, data)`、`transferIn(endpointIn, packetSize)`。
- 响应组包：根据 imKey WebUSB 协议判断一条 APDU response 是否完整。
- 错误映射：断连、权限拒绝、超时、endpoint 错误映射到 imKey SDK 可识别错误。

连接管理参考 `web.imkey.im/src/infra/webusb/device-manager.ts`：

- request filters 当前可以为空数组，由用户在浏览器设备选择器里选择设备；若后续确认正式 VID/PID，可作为默认过滤条件。
- 若 `device.configuration === null`，默认选择 configuration 1。
- 不固定 interface number。打开后遍历 `configuration.interfaces`，寻找同时具备 `in`/`out` endpoint 且可以 `claimInterface` 的 interface。
- 优先选择 vendor specific interface (`interfaceClass === 255`)；如果 protected class claim 失败则继续尝试其他候选 interface。
- 默认 endpoint 可参考 `inEndpoint = 5`、`outEndpoint = 4`，但实际 SDK 应优先采用动态探测结果。

注意事项：

- 连接只能在安全上下文和用户授权后建立。
- 用户拒绝授权应映射为明确的连接取消错误。
- 浏览器页面刷新后需要重新建立连接。
- 设备断开后需要清理 transport 状态，并让业务接口返回可恢复错误。
- 同一个 transport 上的 APDU 发送必须串行化，避免多个业务调用并发写入同一个 USB endpoint。

---

## TSM Client Adapter

现有 `ikc-common/src/https.rs` 使用 `hyper_tls`、`hyper_util` 和 `tokio::runtime::Runtime::block_on`。该实现适合 native，不适合浏览器 wasm。

Web 端应通过 adapter 注入 TSM 请求能力：

```ts
interface TsmClient {
  post(action: string, body: Uint8Array): Promise<string>
}
```

已确认 TSM 服务允许浏览器跨域访问，因此默认实现可使用 `fetch` 直连 TSM 服务。仍建议保留可注入 client，便于测试、灰度环境、私有部署或未来代理需求：

```ts
const tsmClient = {
  post: (action, body) => fetch('/api/imkey-tsm', { method: 'POST', body })
}
```

Rust 业务逻辑仍表达为“发送 TSM action + request data，得到 response data”，不关心具体网络实现。

---

## Storage Adapter

绑定流程当前通过 `file_dir` 读写本地 key 文件。浏览器没有普通文件系统路径语义。

Web 端应通过 adapter 提供绑定 key 读写：

```ts
interface ImKeyStorage {
  getBindKey(seid: string): Promise<string | null>
  setBindKey(seid: string, encryptedKey: string): Promise<void>
}
```

参考 `web.imkey.im/src/domain/device/secure-binding-store.ts`，默认实现建议使用 IndexedDB：

- DB name: `imkey_secure_storage`（最终 SDK 可按包名调整）。
- object store: `bindings`。
- key: `seid`。
- value: encrypted binding key blob 字符串。

localStorage 不作为默认方案，仅作为调试或极简 demo 备选；原因是 localStorage 同步阻塞、容量和隐私清理行为更不可控。

Rust 侧需要把“按 file path 读写 key 文件”抽象为“按 seid 读写 encrypted key blob”。native/mobile 继续可以通过文件系统 adapter 保持现有行为。

---

## 浏览器支持与降级提示

首期支持 Chrome/Edge。这里的“降级提示”不是提供完整替代通讯链路，而是在浏览器不支持 WebUSB 时做明确产品提示：

- 检测 `navigator.usb` 不存在时，连接按钮不可用或点击后提示“当前浏览器不支持 WebUSB，请使用 Chrome 或 Edge”。
- 不支持 WebUSB 的浏览器不进入 onboarding、绑定、签名、应用管理流程。
- 如果特定流程进入 Bootloader/BL 模式且只能通过 WebHID 处理，可单独在该流程内评审 WebHID fallback；这不改变正常模式优先 WebUSB 的策略。

---

## API 形态

前端应面向业务 API，而不是 APDU API：

```ts
await imkey.connect()

const info = await imkey.getDeviceInfo()
const bindStatus = await imkey.bindCheck()
await imkey.bindDisplayCode()
const bindResult = await imkey.bindAcquire(code)

const address = await imkey.getAddress({
  chainType: 'ETHEREUM',
  path: "m/44'/60'/0'/0/0",
  network: 'MAINNET',
})

const signed = await imkey.signTx(params)
```

可以保留低层 `sendApdu` 作为调试或测试能力，但不作为产品业务集成的主入口。

---

## npm 包命名与导出 API 决策

“npm 包命名、导出 API 形态和是否保留现有 `tcx_wasm` 文件名”包含三个独立决策：

### 1. 包名

包名是前端安装时使用的名称，例如：

```bash
npm install @imtoken/wallet-core-web
```

已确认包名为 `@imtoken/wallet-core-web`。该命名表达这是浏览器侧统一钱包核心 SDK，包含 token-core 软件钱包能力和 imKey 硬件钱包能力。

### 2. 导出 API 形态

导出 API 形态决定业务方如何 import 和初始化：

```ts
import {
  initTokenCore,
  createImKeyCore,
  WebUsbImKeyTransport,
  IndexedDbImKeyStorage,
  FetchTsmClient,
} from '@imtoken/wallet-core-web'
```

推荐导出分层：

- token-core 软件钱包入口：`initTokenCore()` 或 `tokenCore.*`。
- imKey 硬件钱包入口：`createImKeyCore({ transport, storage, tsmClient })`。
- 默认 web adapters：`WebUsbImKeyTransport`、`IndexedDbImKeyStorage`、`FetchTsmClient`。
- 类型定义：`ImKeyCore`、`ImKeyTransport`、`ImKeyStorage`、`TsmClient`。

这样业务侧不需要直接 import wasm-pack 生成的底层文件，也不需要知道 `tcx_wasm_bg.wasm` 这类内部产物名。

已确认公开 API 只暴露业务能力。前端业务页面应看到 `connect`、`getDeviceInfo`、`bindCheck`、`bindAcquire`、`getAddress`、`signTx` 等方法，而不是 `call_imkey_api`、`send_apdu` 或 wasm 生成文件名。

### 3. 是否保留 `tcx_wasm` 文件名

现有 `tcx-wasm` 通过 wasm-pack 生成的文件名类似：

- `tcx_wasm.js`
- `tcx_wasm.d.ts`
- `tcx_wasm_bg.wasm`

“是否保留”指的是：发布统一 npm 包后，是否仍允许业务方直接依赖这些底层文件名。

推荐策略：

- **公开 API 不暴露底层文件名**：业务方只从包入口 import。
- **开发测试阶段保留 `tcx_wasm*` / `ikc_wasm*` 生成文件**：因为当前还不会发布 npm，需要本仓库示例或测试页面可以直接引用这些构建产物验证整体流程。
- **长期公开 API 不承诺这些文件名稳定**：目前确认没有前端项目直接依赖 `tcx_wasm.js`，因此统一 npm 包正式发布时，这些文件名可以作为内部实现细节，不作为业务方长期 import 入口。

因此本提案采用“两层入口”：

1. **开发/测试入口**：保留 wasm-pack 生成文件，示例页面可以从本地 `pkg` 或 `publish/npm` 临时引用。
2. **正式 SDK 入口**：`@imtoken/wallet-core-web` 的包入口导出稳定业务 API，业务方不直接依赖 wasm-pack 文件名。

---

## 与现有 native/mobile 的兼容策略

本提案不要求把现有 C ABI 改成 async，也不要求移动端适配 WebUSB。

推荐实现策略：

1. 保留现有 `ikc` C ABI 入口。
2. 新增 wasm 专用 facade，例如 `ikc-wasm`。
3. 抽取共享业务函数，使 native C ABI 和 wasm facade 调用同一套核心逻辑。
4. native/mobile 使用同步 adapter 包装现有 transport。
5. wasm 使用异步 adapter 调用 JS transport。

后续开发新增 imKey 能力时，应优先把核心业务放在共享层；只有设备连接、发送、网络、存储需要分别适配。

---

## 依赖与 wasm 兼容性

初步编译检查显示，当前 `cargo check -p ikc --target wasm32-unknown-unknown` 会首先卡在 `getrandom 0.2.17` 未启用 wasm JS 支持。后续实现阶段需要系统处理：

- `getrandom` 0.2/0.3 wasm feature。
- `secp256k1`、`rsa`、Substrate 相关依赖的 wasm 支持。
- native-only 网络依赖 `hyper_tls`/`tokio` 的条件编译或 adapter 化。
- native-only 文件系统依赖的 adapter 化。
- wasm 包体积和 tree-shaking。

---

## 风险 / 权衡

**[异步改造范围]**  
WebUSB 是异步模型，完整复用同步 `ikc` 业务函数会遇到边界问题。缓解措施：新增 wasm facade 和 transport adapter，避免改变现有 C ABI；按业务流程逐步抽取可复用 async 核心。

**[WebUSB descriptor 依赖]**  
方案依赖 imKey Pro 已暴露可供浏览器 claim 的 WebUSB interface。缓解措施：Phase 0 先验证 descriptor、endpoint、packet size 和基础 APDU。

**[TSM CORS / 网络策略]**  
浏览器可能无法直接访问现有 TSM 服务。缓解措施：TSM client adapter 支持业务方注入代理实现。

**[绑定 key 存储安全]**  
浏览器存储比 native 文件系统更容易受站点数据清理、隐私模式和 XSS 风险影响。缓解措施：默认 IndexedDB，结合 CSP、业务域隔离和必要的加密/完整性策略评审。

**[统一 npm 包体积]**  
同时包含 token-core wasm 和 imKey wasm 可能增大包体积。缓解措施：导出拆分入口、按需初始化 wasm、评估 feature gating。

**[应用管理和 COS update 稳定性]**  
长时间、大量 APDU 流程对浏览器断连和页面生命周期更敏感。缓解措施：先覆盖 onboarding 和签名，应用管理后续单独强化恢复策略。

---

## 已确认事项

1. imKey 支持 WebUSB 通讯，本方案以 WebUSB 作为 web transport。
2. WebUSB 连接由浏览器 JS 建立并保存，wasm 不直接持有设备连接。
3. 业务接口中生成的 APDU 需要回到 JS transport，通过之前保存的 WebUSB 连接发送给设备。
4. 现有 native/mobile 静态库发布方式必须保持稳定，不应被 wasm 改造破坏。
