## 1. 方案确认

- [x] 1.1 参考 `web.imkey.im` 确认 WebUSB 连接策略：filters 可为空、configuration 默认 1、interface/endpoint 动态探测、默认 endpoint in=5/out=4
- [x] 1.2 参考 `web.imkey.im` 确认 WebUSB 传输 framing 与 native HID 不一致，WebUSB 使用 64-byte packet + `0xC3` first chunk + `0xFF` busy indicator
- [x] 1.3 确认 TSM 服务浏览器访问策略：允许 CORS 直连，默认 web TSM client 可使用 fetch
- [x] 1.4 确认 Web 端绑定 key 存储策略：参考 `web.imkey.im`，默认使用 IndexedDB 保存 encrypted binding key blob
- [x] 1.5 确认 npm 包命名：`@imtoken/wallet-core-web`
- [x] 1.6 确认导出结构原则：前端公开 API 只暴露业务能力，不直接暴露 wasm-pack 底层文件
- [x] 1.7 确认开发测试阶段保留 `tcx_wasm*` / `ikc_wasm*` 生成文件，供示例/测试页面直接引用；正式 npm API 不承诺这些文件名稳定
- [x] 1.8 确认 imKey Pro WebUSB reference descriptor 文档值：VID/PID、interface class、interface number、endpoint in/out、packet size；运行时仍以动态探测为准

## 2. Transport 抽象

- [x] 2.1 在 `ikc-transport` 中定义平台无关 APDU transport 边界
- [x] 2.2 保留并适配 native `hidapi` transport，确保现有桌面路径行为不变
- [x] 2.3 保留并适配 mobile callback transport，确保现有移动端静态库行为不变
- [x] 2.4 为 wasm 增加 JS bridge transport，使 Rust 业务逻辑可以异步请求 JS 发送 APDU
- [x] 2.5 将 transport 错误映射到现有 imKey 错误体系，覆盖授权拒绝、设备断开、超时、非法响应
- [x] 2.6 增加可重连 transport 能力，供 COS/BLE 固件重启后的业务状态机显式依赖

## 3. WebUSB TypeScript Adapter

- [x] 3.1 实现 `WebUsbImKeyTransport.connect()`：授权、打开设备、configuration 1 fallback、动态扫描并 claim 可用 interface、记录 endpoint
- [x] 3.2 实现 `sendApdu(apduHex, timeout)`：按 WebUSB 64-byte framing 编码请求、`transferOut` 发送、`transferIn` 接收、处理 `0xFF` busy、组包响应
- [x] 3.3 实现断开检测、重连状态清理和超时控制
- [x] 3.4 增加 transport 级单元测试，覆盖 framing、动态 endpoint、busy deadline 和并发串行化
- [x] 3.5 暴露低层诊断信息，便于调试 endpoint、超时和设备返回码
- [x] 3.6 使用已授权设备列表按 VID/PID/serial 自动恢复固件升级后的 WebUSB 连接并重新探测 endpoint

## 4. TSM 与 Storage Adapter

- [x] 4.1 定义 `TsmClient` adapter，并为 web 提供 fetch 默认实现
- [x] 4.2 定义 `ImKeyStorage` adapter，并为 web 提供 IndexedDB 默认实现
- [x] 4.3 将 `ikc-device` 中 TSM 请求从 native `https::post` 调整为可注入 client
- [x] 4.4 将绑定 key 文件读写调整为可注入 storage，同时保留 native/mobile 文件系统行为
- [x] 4.5 补齐 TSM 错误、storage 错误和现有业务错误的兼容映射
- [x] 4.6 导出 `configure_tsm` wasm 接口，并由 npm facade 同步配置 Web TSM adapter

## 5. wasm facade 与 npm 包

- [x] 5.1 新增 `ikc-wasm` 或统一 `wallet-core-wasm` facade crate
- [x] 5.2 暴露 web 友好的异步业务 API：connect、getDeviceInfo、bind、getAddress、signTx、signMessage、app management
- [x] 5.3 处理 wasm target 依赖兼容：`getrandom`、native-only network、native-only filesystem、条件编译
- [x] 5.4 扩展 `Makefile` / publish 脚本，使统一 npm 包同时包含 token-core wasm 和 imKey wasm，并在开发测试阶段输出本地示例页面可直接引用的 wasm-pack 产物
- [x] 5.5 生成 TypeScript 类型定义和 README 使用示例，文档以 `@imtoken/wallet-core-web` 的业务 API 为主
- [x] 5.6 将 `cos_check_update`、COS 升级、应用恢复和 BLE 固件升级迁移到异步 transport/TSM 业务层

## 6. 验证计划

- [x] 6.1 `cargo check -p ikc-wasm --target wasm32-unknown-unknown`
- [x] 6.2 native/mobile 回归：`make test-ikc`
- [x] 6.3 wasm 构建回归：现有 `make test-wasm` 继续通过
- [ ] 6.4 浏览器 WebUSB POC：连接设备并读取 `seid`、`sn`、`life_time`
- [ ] 6.5 onboarding 浏览器集成验证：secure check、activate、bind check/display/acquire
- [ ] 6.6 代表性签名验证：ETH/BTC/TRON 至少各一条主路径
- [ ] 6.7 应用管理验证：check update、app download/update/delete
- [ ] 6.8 断连、超时、用户拒绝授权、页面刷新后重连等异常场景验证
- [ ] 6.9 真实设备 COS/BLE 固件升级及两次设备重启后的 WebUSB 自动重连验收
