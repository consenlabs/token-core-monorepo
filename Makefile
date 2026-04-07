build-tcx-proto:
	cargo build -p tcx-proto

check-tcx:
	cd token-core; cargo check

build-tcx:
	cd token-core; cargo build

test-tcx:
	KDF_ROUNDS=1 cargo test --workspace --exclude 'ikc*' --exclude 'coin*'

test-ikc:
	KDF_ROUNDS=1 cargo test --workspace --exclude 'tcx*' 

build-wasm:
	CC=$$(brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)/bin/clang \
	AR=$$(brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)/bin/llvm-ar \
	wasm-pack build token-core/tcx-wasm --target web --out-dir ../../examples/wasm/src/pkg
	cp examples/wasm/src/pkg/tcx_wasm_bg.wasm examples/wasm/public/

dev-wasm: build-wasm
	cd examples/wasm && npm run dev