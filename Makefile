TEST_ENV := MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1
TCX_EXCLUDES := --exclude 'ikc*' --exclude 'coin*'
IKC_HARDWARE_EXCLUDES := --exclude 'tcx*'
WASM_CC ?= /opt/homebrew/opt/llvm/bin/clang
WASM_AR ?= /opt/homebrew/opt/llvm/bin/llvm-ar
WASM_CFLAGS ?= -Wno-implicit-function-declaration

.PHONY: build-tcx-proto check-tcx build-tcx test-tcx test-ikc test-workspace test-hardware test-wasm build-wasm build-imkey-wasm build-wasm-all build-wasm-opt dev-wasm build-npm publish-npm

build-tcx-proto:
	cargo build -p tcx-proto

check-tcx:
	cd token-core; cargo check

build-tcx:
	cd token-core; cargo build

test-tcx:
	$(TEST_ENV) cargo test --workspace $(TCX_EXCLUDES)

test-ikc:
	$(TEST_ENV) cargo test -p ikc-common
	$(TEST_ENV) cargo test -p ikc-proto
	$(TEST_ENV) cargo test -p ikc normalize_sign_param
	$(TEST_ENV) cargo test -p ikc call_imkey_api
	$(TEST_ENV) cargo test -p ikc handler::test
	$(TEST_ENV) cargo test -p ikc types::tests
	$(TEST_ENV) cargo test -p ikc-transport encode_device_message
	$(TEST_ENV) cargo test -p ikc-transport apdu_transport_trait
	$(TEST_ENV) cargo test -p ikc-transport transport_errors

test-workspace:
	$(TEST_ENV) cargo test --workspace --no-run
	$(MAKE) test-tcx
	$(MAKE) test-ikc

test-hardware:
	@echo "Requires a connected and authorized imKey device; hardware tests run serially."
	@echo "Set IMKEY_TSM_TEST_URL to select a staging or development TSM endpoint."
	$(TEST_ENV) cargo test --workspace $(IKC_HARDWARE_EXCLUDES) -- --test-threads=1 --nocapture

test-wasm:
	CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" $(TEST_ENV) cargo check -p tcx-wasm --target wasm32-unknown-unknown
	CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" $(TEST_ENV) cargo check -p ikc-wasm --target wasm32-unknown-unknown
	$(TEST_ENV) cargo test -p tcx-wasm --no-run

build-wasm:
	mkdir -p examples/wasm/public
	CC=$(WASM_CC) CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" AR=$(WASM_AR) wasm-pack build token-core/tcx-wasm --target web --out-dir ../../examples/wasm/src/pkg
	cp examples/wasm/src/pkg/tcx_wasm_bg.wasm examples/wasm/public/

build-imkey-wasm:
	mkdir -p examples/wasm/public
	CC=$(WASM_CC) CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" AR=$(WASM_AR) wasm-pack build imkey-core/ikc-wasm --target web --out-dir ../../examples/wasm/src/imkey-pkg
	cp examples/wasm/src/imkey-pkg/ikc_wasm_bg.wasm examples/wasm/public/

build-wasm-all: build-wasm build-imkey-wasm

build-wasm-opt:
	mkdir -p examples/wasm/public
	CC=$(WASM_CC) CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" AR=$(WASM_AR) CARGO_PROFILE_RELEASE_LTO=true CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=true wasm-pack build token-core/tcx-wasm --release --target web --out-dir ../../examples/wasm/src/pkg
	wasm-opt -Oz --all-features examples/wasm/src/pkg/tcx_wasm_bg.wasm -o examples/wasm/src/pkg/tcx_wasm_bg.wasm
	cp examples/wasm/src/pkg/tcx_wasm_bg.wasm examples/wasm/public/
	@echo "Optimized wasm size:" && ls -lh examples/wasm/public/tcx_wasm_bg.wasm

dev-wasm: build-wasm-all
	cd examples/wasm && npm run dev

build-npm:
	mkdir -p publish/npm
	CC=$(WASM_CC) CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" AR=$(WASM_AR) CARGO_PROFILE_RELEASE_LTO=true CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=true wasm-pack build token-core/tcx-wasm --release --target web --out-dir ../../.wasm-pack-tmp-tcx
	CC=$(WASM_CC) CC_wasm32_unknown_unknown=$(WASM_CC) CFLAGS_wasm32_unknown_unknown="$(WASM_CFLAGS)" AR=$(WASM_AR) wasm-pack build imkey-core/ikc-wasm --release --target web --out-dir ../../.wasm-pack-tmp-ikc
	cp .wasm-pack-tmp-tcx/tcx_wasm_bg.wasm publish/npm/
	cp .wasm-pack-tmp-tcx/tcx_wasm.js publish/npm/
	cp .wasm-pack-tmp-tcx/tcx_wasm.d.ts publish/npm/
	cp .wasm-pack-tmp-tcx/tcx_wasm_bg.wasm.d.ts publish/npm/
	cp .wasm-pack-tmp-ikc/ikc_wasm_bg.wasm publish/npm/
	cp .wasm-pack-tmp-ikc/ikc_wasm.js publish/npm/
	cp .wasm-pack-tmp-ikc/ikc_wasm.d.ts publish/npm/
	cp .wasm-pack-tmp-ikc/ikc_wasm_bg.wasm.d.ts publish/npm/
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -Oz --all-features publish/npm/tcx_wasm_bg.wasm -o publish/npm/tcx_wasm_bg.wasm; \
		wasm-opt -Oz --all-features publish/npm/ikc_wasm_bg.wasm -o publish/npm/ikc_wasm_bg.wasm; \
	fi
	rm -rf .wasm-pack-tmp-tcx .wasm-pack-tmp-ikc
	@echo "NPM package built in publish/npm/"
	@ls -lh publish/npm/tcx_wasm_bg.wasm
	@ls -lh publish/npm/ikc_wasm_bg.wasm

publish-npm: build-npm
	cd publish/npm && npm publish
