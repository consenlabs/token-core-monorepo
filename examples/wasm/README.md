# tcx-wasm Browser Example

Next.js web app for testing the `tcx-wasm` crate in the browser, covering keystore creation, ETH account derivation, and transaction signing via WebAssembly.

## Prerequisites

- [Rust nightly](https://rustup.rs/) (see `rust-toolchain.toml` at repo root)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [LLVM with wasm32 support](https://formulae.brew.sh/formula/llvm) (`brew install llvm`)
- Node.js >= 18

## Quick Start

```bash
# From repo root
make build-wasm        # compile WASM and copy to public/
make dev-wasm          # build + start Next.js dev server
```

Then open [http://localhost:3000](http://localhost:3000) and click **Run Tests**.

## Manual Steps

```bash
# 1. Build the WASM package
npm run build:wasm

# 2. Start the dev server
npm run dev
```

## What It Tests

| Test Case | Description |
|-----------|-------------|
| Init WASM | Load and initialize the WASM module |
| Import mnemonic | Create keystore from a known mnemonic |
| New mnemonic | Create keystore with auto-generated mnemonic |
| Derive account | Derive an Ethereum address (m/44'/60'/0'/0/0) |
| Legacy tx | Sign an EIP-155 legacy transaction |
| EIP-1559 tx | Sign a type-2 (EIP-1559) transaction |
