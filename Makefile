build-tcx-proto:
	cargo build -p tcx-proto

check-tcx:
	cd token-core; cargo check

build-tcx:
	cd token-core; cargo build

test-tcx:
	cd token-core; cargo test
