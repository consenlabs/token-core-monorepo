# imKey WASM Method Support

This document tracks the WebUSB/WASM migration status for the existing `Method`
list in `imkey-core/ikc/src/types.rs`.

## Supported Through Async Business Layer

- `configure_tsm` as the `configureTsm(baseUrl)` web facade method
- `app_download`
- `app_update`
- `app_delete`
- `device_activate`
- `check_update`
- `device_secure_check`
- `bind_check`
- `bind_display_code`
- `bind_acquire`
- `get_seid`
- `get_sn`
- `get_ram_size`
- `get_firmware_version`
- `get_battery_power` as a standalone method only
- `get_life_time`
- `get_ble_name`
- `set_ble_name`
- `get_ble_version`
- `get_sdk_info`
- `cos_update`, including COS update, post-update app restoration, and chained
  BLE firmware update
- `cos_check_update`

`get_device_info` intentionally excludes battery power for WebUSB because wired
connections do not provide a reliable battery capability.

Bootloader status is intentionally not exposed through the Web business facade.
`cos_update` detects normal COS and bootloader recovery states from the device
certificate and owns the state transition internally.

## Partially Supported

- `get_address`: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum, Cosmos,
  Filecoin, Nervos, Polkadot, Kusama, Tron, Tezos.
- `register_address`: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum,
  Cosmos, Filecoin, Nervos, Polkadot, Kusama, Tron, Tezos.
- `register_pub_key`: EOS.
- `get_public_keys`:
  - secp256k1: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum, Cosmos,
    Filecoin, Nervos, Tron, EOS.
  - ed25519: Polkadot, Kusama.
- `get_extended_public_keys`: Bitcoin, Dogecoin, Litecoin, BitcoinCash,
  Ethereum, Cosmos, Filecoin, Nervos, Tron, EOS.
- `derive_accounts`: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum,
  Cosmos, Filecoin, Nervos, Tron, Polkadot, Kusama, EOS.
- `derive_sub_accounts`: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum,
  Cosmos, Filecoin, Nervos, Tron, EOS.
- `calc_external_address`: Bitcoin.
- `sign_tx`: Bitcoin, Dogecoin, Litecoin, BitcoinCash, Ethereum, Cosmos,
  Filecoin, Nervos, Tron, Polkadot, Kusama, Tezos, EOS.
- `sign_message`: Bitcoin, Ethereum, Tron, EOS.
- `sign_psbt`: Bitcoin.

The chain APIs currently use the async APDU transport from wasm and do not call
the synchronous native HID transport.

## Not Applicable Or Not Supported In WebUSB

- `device_connect`: native HID connection method. Web uses browser WebUSB
  permission and session setup instead.

Firmware update uses a reconnect-capable async transport. After COS or BLE
firmware restarts the device, the WebUSB adapter searches the browser's already
authorized devices for the same VID, PID, and serial number, reopens it, and
claims the newly reported interface and endpoints before the Rust state machine
continues.

## Chain-Level Async Migration

Filecoin and Nervos `sign_tx` are exposed through the same injected async APDU
transport as the other WebUSB chain methods. Their original synchronous native
HID entry points remain available for mobile and desktop SDK builds. Internal
method names follow each coin crate's established vocabulary (`sign_tx_async`
for Filecoin and `sign_transaction_async` for Nervos); this is not a difference
in the public API. Both are dispatched by the single wasm `sign_tx` entry.

The synchronous and asynchronous methods share transaction preparation,
signing payload construction, response verification, and result assembly. Only
the APDU I/O call differs between native/mobile and WebUSB.
