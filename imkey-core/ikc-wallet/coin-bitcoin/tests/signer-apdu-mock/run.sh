#!/bin/sh
# Build a disposable copy of the SDK and inject an APDU-only mock there.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(git -C "$test_dir" rev-parse --show-toplevel)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/imkey-p2wsh-apdu.XXXXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
case "$(uname -s)" in
    Darwin|Linux) ;;
    *) echo 'This offline fixture requires macOS or Linux.' >&2; exit 1 ;;
esac
python3 - "$repo_dir" "$tmpdir" "$test_dir" <<'PY'
import pathlib
import shutil
import sys

repo = pathlib.Path(sys.argv[1])
tmp = pathlib.Path(sys.argv[2])
test_dir = pathlib.Path(sys.argv[3])
crates = [
    'imkey-core/ikc-common',
    'imkey-core/ikc-device',
    'imkey-core/ikc-transport',
    'imkey-core/ikc-wallet/coin-bitcoin',
]
for name in crates:
    source, dest = repo / name, tmp / name
    dest.mkdir(parents=True)
    shutil.copy2(source / 'Cargo.toml', dest / 'Cargo.toml')
    shutil.copytree(source / 'src', dest / 'src')

test_path = tmp / 'imkey-core/ikc-wallet/coin-bitcoin/tests/signer-apdu-mock'
test_path.mkdir(parents=True)
for name in ('Cargo.toml', 'Cargo.lock'):
    shutil.copy2(test_dir / name, test_path / name)
shutil.copytree(test_dir / 'tests', test_path / 'tests')

transport = tmp / 'imkey-core/ikc-transport/src'
shutil.copy2(test_dir / 'fixture/transport_mock.rs', transport / 'p2wsh_test_mock.rs')
lib = transport / 'lib.rs'
lib.write_text(lib.read_text() + '\n// Inserted only in the disposable offline test copy.\npub mod p2wsh_test_mock;\n')
message = transport / 'message.rs'
code = message.read_text()
original = '    hid_api::hid_send(&apdu, timeout)'
replacement = '    crate::p2wsh_test_mock::send(&apdu, timeout)'
if code.count(original) != 1:
    raise SystemExit('transport changed; refusing to run without a verified APDU interception')
code = code.replace(original, replacement, 1)
import_hid = '#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]\nuse super::hid_api;\n'
if code.count(import_hid) != 1:
    raise SystemExit('transport imports changed; verify offline fixture before running')
message.write_text(code.replace(import_hid, '', 1))
# Even a future test that calls hid_connect directly cannot reach a device.
(transport / 'hid_api.rs').write_text('''use crate::Result;
pub fn hid_connect(_: &str) -> Result<()> {
    Err(anyhow::anyhow!("offline fixture forbids physical devices"))
}
pub fn hid_send(_: &String, _: i32) -> Result<String> {
    Err(anyhow::anyhow!("offline fixture forbids physical devices"))
}
''')
PY
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$test_dir/target}" \
    cargo test --offline --locked --manifest-path "$tmpdir/imkey-core/ikc-wallet/coin-bitcoin/tests/signer-apdu-mock/Cargo.toml"
