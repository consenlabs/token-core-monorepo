## 新增需求

### 需求：浏览器通过 WebUSB 连接 imKey Pro
系统必须支持在浏览器安全上下文中，通过用户授权的 WebUSB 流程连接 imKey Pro。WebUSB 设备连接必须由 JavaScript transport adapter 持有，Rust wasm 不直接保存浏览器 `USBDevice` 对象。

#### 场景：用户授权并连接设备
- **当** 用户在页面中触发连接操作，并选择一个符合 imKey WebUSB descriptor 的设备
- **则** TypeScript SDK 打开设备、选择 configuration、claim interface，并保存可用于后续 APDU 发送的 WebUSB 连接状态

#### 场景：用户拒绝授权
- **当** 用户取消或拒绝 WebUSB 设备授权
- **则** SDK 返回明确的连接取消错误，不进入任何 imKey 业务流程，也不调用 wasm 业务接口发送 APDU

#### 场景：页面刷新后连接状态丢失
- **当** 页面刷新导致 JavaScript runtime 重建
- **则** SDK 不假定旧 WebUSB 连接仍然可用，后续业务接口必须先重新建立或恢复连接

#### 场景：动态探测 WebUSB interface 和 endpoint
- **当** SDK 打开已授权的 imKey WebUSB 设备
- **则** SDK 在必要时选择 configuration 1，并遍历设备 interfaces，claim 同时具备 in/out endpoint 的可用 interface，优先使用 vendor specific interface；endpoint 使用探测结果，默认 in=5/out=4 仅作为参考配置

### 需求：wasm 业务逻辑通过 WebUSB transport 发送 APDU
系统必须支持 imKey wasm 业务逻辑生成 APDU 后，通过 JavaScript WebUSB transport 发送给设备，并把 APDU response 返回给 Rust 业务逻辑继续处理。

#### 场景：读取 SEID
- **当** 前端调用 `getSeid` 业务接口
- **则** Rust wasm 生成读取 SEID 所需 APDU，通过 JS transport 发送给设备，接收响应后在 Rust 侧完成 status word 校验和 SEID 解析，并将结果返回前端

#### 场景：多 APDU 业务流程
- **当** 绑定、签名或应用管理流程需要连续发送多条 APDU
- **则** Rust wasm 按业务状态机逐条生成 APDU；每条 APDU 均通过同一个已连接的 JS WebUSB transport 发送；每个响应返回 Rust 后再决定下一步

#### 场景：设备响应异常
- **当** WebUSB transport 返回超时、断连、非法响应或设备 status word 错误
- **则** wasm 业务逻辑返回与现有 imKey 错误体系兼容的错误，不吞掉底层失败，也不继续后续 APDU

#### 场景：WebUSB 分包发送 APDU
- **当** JS transport 发送一条 APDU
- **则** transport 必须按 imKey WebUSB framing 写入 64-byte packet：first chunk 使用 byte[4]=`0xC3`、byte[5..6]=总长度、byte[7..]=payload；后续 chunk 使用 byte[4]=sequence、byte[5..]=payload

#### 场景：WebUSB 读取 busy 响应
- **当** 设备响应 packet 的 byte[4] 为 `0xFF`
- **则** transport 识别为 device busy，不把该 packet 当成最终 APDU response，而是继续等待/读取，直到超时或收到完整响应

### 需求：平台通讯能力通过 APDU transport 抽象隔离
系统必须把 APDU 发送能力抽象为平台边界，使 imKey 业务逻辑不直接依赖 `hidapi`、mobile callback 或 WebUSB。

#### 场景：native desktop 使用 hidapi transport
- **当** imKey Core 以 native desktop 方式构建和运行
- **则** APDU 发送继续使用现有 `hidapi` 能力，设备连接和发送行为与当前 SDK 保持兼容

#### 场景：mobile 使用 callback transport
- **当** imKey Core 以移动端静态库方式集成
- **则** APDU 发送继续通过宿主 App callback 完成，现有 `set_callback` 集成方式保持兼容

#### 场景：web 使用 WebUSB transport
- **当** imKey Core 以 wasm web 方式运行
- **则** APDU 发送通过 JavaScript WebUSB transport 完成，Rust wasm 仅通过异步 bridge 获取发送结果

### 需求：Web 端 TSM 请求通过可注入 adapter 完成
系统必须支持 Web 端通过 `fetch` 或业务方注入的 TSM client 发送 TSM 请求，而不是在浏览器 wasm 中复用 native `hyper/tokio` 网络实现。

#### 场景：前端配置 TSM 服务地址
- **当** 前端在首个 TSM 业务请求前调用 `configureTsm(baseUrl)`
- **则** wasm 必须复用 native `configure_tsm` 的 HTTPS 校验、URL 规范化、同值幂等和禁止运行时切换规则，并让 Web TSM adapter 使用规范化后的地址发送后续请求

#### 场景：TSM 服务允许浏览器直连
- **当** TSM 服务配置允许当前 Web origin 跨域访问
- **则** 默认 web TSM client 使用 `fetch` 直接向 TSM 服务发送请求，并将响应交回 Rust 业务逻辑处理

#### 场景：TSM 服务不允许浏览器直连
- **当** TSM 服务不支持浏览器 CORS 访问
- **则** SDK 必须允许业务方注入代理 TSM client，通过业务后端 relay 完成请求

### 需求：Web 端绑定 key 通过 storage adapter 保存
系统必须支持 Web 端通过 storage adapter 保存和读取 imKey 绑定所需 encrypted key 数据，而不是依赖 native 文件系统路径。

#### 场景：默认 IndexedDB 存储
- **当** SDK 使用默认 Web storage adapter
- **则** encrypted binding key blob 必须存入 IndexedDB，并以 SEID 作为读取 key；实现可参考 `web.imkey.im` 的 `imkey_secure_storage` / `bindings`

#### 场景：首次绑定生成 key
- **当** 浏览器端执行 `bindCheck` 并发现本地没有当前 SEID 对应的 encrypted key
- **则** Rust 业务逻辑生成绑定 key 数据后，通过 web storage adapter 保存 encrypted key blob

#### 场景：已绑定设备复用 key
- **当** 浏览器端再次连接同一台 imKey 并执行 `bindCheck`
- **则** SDK 通过 storage adapter 读取当前 SEID 对应 encrypted key，交给 Rust 业务逻辑解密并继续绑定状态判断

#### 场景：storage 数据损坏
- **当** storage adapter 返回的 encrypted key 无法解密或校验失败
- **则** 业务逻辑按现有 key 文件损坏语义处理，重新生成或返回兼容错误

### 需求：统一 npm 包导出 token-core 与 imKey Core web 能力
系统必须支持以 `@imtoken/wallet-core-web` 单个 npm 包交付浏览器侧 token-core wasm 和 imKey Core wasm 能力，前端业务方无需分别管理两个独立包。

#### 场景：前端只安装一个包
- **当** 前端项目安装统一 web SDK npm 包
- **则** 可以从同一包中导入软件钱包能力和 imKey 硬件钱包能力

#### 场景：只使用 token-core 软件钱包能力
- **当** 前端只初始化 token-core wasm，不调用 imKey WebUSB 能力
- **则** SDK 不请求 WebUSB 设备权限，也不初始化 imKey transport

#### 场景：只使用 imKey 硬件钱包能力
- **当** 前端只初始化 imKey wasm 能力
- **则** SDK 不要求创建软件钱包 keystore，也不执行 token-core 专属初始化流程

#### 场景：业务方不依赖 wasm-pack 底层文件名
- **当** 前端业务方使用统一 npm 包
- **则** 业务方通过包入口导入稳定 API，不直接依赖 `tcx_wasm.js`、`tcx_wasm_bg.wasm` 或未来 `ikc_wasm_bg.wasm` 等内部生成文件名

#### 场景：开发测试页面直接引用本地 wasm 产物
- **当** 项目尚未发布 npm 包，且需要本仓库示例或测试页面验证整体流程
- **则** 构建流程必须保留 wasm-pack 生成产物，允许示例页面从本地 `pkg` 或测试输出目录直接引用；该入口仅作为开发测试入口，不代表正式 SDK 公共 API

### 需求：现有 native/mobile 发布不受 wasm 改造影响
系统必须保持现有 imKey Core native/mobile 静态库生成和对外 API 行为稳定。

#### 场景：移动端继续生成静态库
- **当** 执行现有移动端静态库构建流程
- **则** 构建产物不依赖 WebUSB、浏览器 API 或 wasm facade，现有 C ABI 和 callback 行为保持兼容

#### 场景：现有 host-safe 测试
- **当** 执行 `make test-ikc`
- **则** 现有 host-safe 测试继续通过，且不要求连接真实 WebUSB 设备

#### 场景：native desktop HID 路径
- **当** 桌面端使用现有 `hidapi` 路径连接 imKey
- **则** 设备连接、APDU 发送、错误映射和已有硬件测试预期保持兼容
