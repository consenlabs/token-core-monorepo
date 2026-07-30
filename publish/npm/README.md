# @imtoken/wallet-core-web

Browser SDK for TokenCore software-wallet capabilities and imKey hardware-wallet
capabilities. imKey communication uses WebUSB and supports Chrome and Edge.

## imKey

```ts
import { createImKeyCore } from "@imtoken/wallet-core-web";

const imkey = createImKeyCore();

// Configure this once, before any activation, binding, update, or app request.
await imkey.configureTsm("https://your-tsm-origin.example/imkey");

// Must run from a user click because the browser opens a USB permission dialog.
await imkey.connect();
const info = await imkey.getDeviceInfo();
const address = await imkey.getAddress({
  chainType: "ETHEREUM",
  path: "m/44'/60'/0'/0/0",
  network: "MAINNET",
});

const update = await imkey.cosCheckUpdate();
if (!update._ReturnData.isLatest) {
  await imkey.cosUpdate();
}
```

The SDK owns the WebUSB session in JavaScript. Rust/WASM generates and validates
APDUs, while `WebUsbImKeyTransport` performs `transferOut` and `transferIn`.
`IndexedDbImKeyStorage` and `FetchTsmClient` are the default browser adapters and
can be replaced through `createImKeyCore` options.

`cosUpdate()` runs the complete COS update and chained BLE firmware update. When
the device restarts during either stage, the WebUSB transport reopens the same
previously authorized device and dynamically claims its current endpoints. A
browser permission dialog cannot be opened during this automatic reconnect, so
the original device authorization and serial number must remain available.

`configureTsm` uses the same Rust validation and process-lifetime rules as the
native `configure_tsm` API. It accepts an HTTPS base URL, removes trailing
slashes, is idempotent for the same URL, and rejects switching to another URL in
the same WASM instance. Call it before the first TSM-backed operation.

Filecoin and Nervos use the same `imkey.signTx(...)` entry as all other chains.
Their chain-specific transaction inputs and outputs are described by the exported
TypeScript types `FilecoinSignTxParams`, `FilecoinSignTxResult`,
`NervosSignTxParams`, and `NervosSignTxResult`.

## TokenCore

```ts
import { initTokenCore } from "@imtoken/wallet-core-web";

const tokenCore = await initTokenCore();
```

Initializing TokenCore does not request USB permission. Initializing imKey does
not create or load a software-wallet keystore.

## Browser Support

WebUSB requires a secure context. Chrome and Edge are supported. Browsers without
`navigator.usb` receive a `webusb_unsupported` error and must not enter imKey
onboarding or signing flows.
