# tcx-wasm Browser Example

Next.js web app for testing the `tcx-wasm` crate in the browser, covering keystore creation, ETH account derivation, transaction signing, and message encryption + Schnorr signing via WebAssembly.

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
| New via entropy | Create keystore from caller-supplied entropy |
| Random | Create keystore with WASM-internal random entropy (Web Crypto) |
| Derive accounts | Derive ETH + TRON addresses |
| Legacy tx | Sign an EIP-155 legacy transaction |
| EIP-1559 tx | Sign a type-2 (EIP-1559) transaction |
| TRON tx | Sign a TRON transaction |
| Cache keystore | Cache keystore and derive without explicit JSON |
| Message pubkey | Derive x-only public key for message signing |
| Derive message key pair | Derive and cache message key pair for encryption |
| Message sign event | Encrypt content, sign event, verify decryption |
| Message encrypt/decrypt | Encrypt + decrypt roundtrip (uses cached key) |
