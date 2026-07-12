# @imtoken/wallet-core-web

Browser SDK for TokenCore software-wallet capabilities and imKey hardware-wallet
capabilities. imKey communication uses WebUSB and supports Chrome and Edge.

## imKey

```ts
import { createImKeyCore } from "@imtoken/wallet-core-web";

const imkey = createImKeyCore({
  tsm: { baseUrl: "https://your-tsm-origin.example/imkey" },
});

// Must run from a user click because the browser opens a USB permission dialog.
await imkey.connect();
const info = await imkey.getDeviceInfo();
const address = await imkey.getAddress({
  chainType: "ETHEREUM",
  path: "m/44'/60'/0'/0/0",
  network: "MAINNET",
});
```

The SDK owns the WebUSB session in JavaScript. Rust/WASM generates and validates
APDUs, while `WebUsbImKeyTransport` performs `transferOut` and `transferIn`.
`IndexedDbImKeyStorage` and `FetchTsmClient` are the default browser adapters and
can be replaced through `createImKeyCore` options.

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
