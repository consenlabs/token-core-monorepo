# TokenCore Monorepo

本仓库是 imToken 和 imKey 使用的核心钱包库 Rust workspace。它将
TokenCore 和 imKeyCore 合并在同一个 workspace 中，统一 Rust 工具链和依赖版本，
避免不同 Rust 版本构建出的库在客户端集成时产生冲突。

英文 README 见 [README.md](./README.md)。

## Workspace 结构

- `token-core/`：TokenCore 相关 crates，包括钱包 keystore、加密算法、链相关签名、
  protobuf 接口、迁移逻辑和 WASM 绑定。
- `imkey-core/`：imKeyCore 相关 crates，包括硬件钱包通信、设备接口、protobuf
  接口和链相关签名。
- `publish/`：包发布产物和说明，包括 NPM 与 Android 发布流程。
- `script/`：Android 和 iOS 本地移动端构建脚本。
- `doc/`：架构文档和安全报告。
- `examples/wasm/`：`tcx-wasm` 的浏览器 WASM 示例。

## 环境要求

- Rust 工具链由 [rust-toolchain.toml](./rust-toolchain.toml) 固定。使用 `rustup`
  时，在仓库目录执行 Cargo 命令会自动安装并选择对应工具链。
- 按需安装标准 Rust 组件：

```bash
rustup component add rustfmt clippy
```

- WASM 和包发布流程会根据命令需要额外依赖 `wasm-pack`、LLVM 工具、`wasm-opt`、
  Node.js 和 npm。
- Android 和 iOS 打包需要安装对应平台 SDK 与 Rust target。

## 快速开始

```bash
git clone git@github.com:consenlabs/token-core-monorepo.git
cd token-core-monorepo

cargo build
cargo test
```

本地测试可以降低 KDF 轮数以加快执行：

```bash
KDF_ROUNDS=1 cargo test
```

## 常用命令

```bash
# 构建整个 workspace
cargo build

# 运行全部测试
cargo test

# 构建 TokenCore crates
make build-tcx

# 构建 protobuf crate
make build-tcx-proto

# 检查 TokenCore crates
make check-tcx

# 运行 TokenCore 相关测试
make test-tcx

# 运行 imKeyCore 相关测试
make test-ikc

# 格式化并检查格式
cargo fmt --all
cargo fmt -- --check

# 运行 clippy，并将 warnings 视为 errors
cargo clippy --all-targets --all-features -- -D warnings
```

## WASM 与 NPM

```bash
# 构建浏览器 WASM 包并启动示例应用
make dev-wasm

# 构建优化后的 NPM 包到 publish/npm/
make build-npm

# 发布 NPM 包
make publish-npm
```

修改 `token-core/tcx-wasm/src/lib.rs` 或 `types.rs` 中的 `#[wasm_bindgen]`
导出时，需要同步更新 `examples/wasm/` 和
[examples/wasm/README.md](./examples/wasm/README.md)。

## 包说明

- [token-core](./token-core/README.md)
- [imkey-core](./imkey-core/README.md)
- [publish](./publish/README.md)
- [WASM 示例](./examples/wasm/README.md)

## 安全

不要提交 secrets、私钥、助记词或 keystore。签名、密钥管理、序列化和迁移相关改动
都需要按安全敏感改动处理。

安全报告：

- [imKey Security Report (CN)](./doc/imKeySecurityReport.pdf)

## License

```text
Copyright 2023 imToken PTE. LTD.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
