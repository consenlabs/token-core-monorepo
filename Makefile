build-tcx-proto:
	cargo build -p tcx-proto

check-tcx:
	cd token-core; cargo check

build-tcx:
	cd token-core; cargo build

test-tcx:
	MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test --workspace --exclude 'ikc*' --exclude 'coin*'

test-ikc:
	MACOSX_DEPLOYMENT_TARGET=10.12 KDF_ROUNDS=1 cargo test --workspace --exclude 'tcx*'
