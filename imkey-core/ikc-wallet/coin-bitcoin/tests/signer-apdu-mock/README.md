# Offline SDK APDU flow regression

From the repository root, run:

```sh
imkey-core/ikc-wallet/coin-bitcoin/tests/signer-apdu-mock/run.sh
```

The script copies the working SDK crate manifests and source files into a disposable temporary directory. It inserts an APDU mock into the copy only and replaces the copied HID implementation with a hard error. The working SDK's transport source and production features are unchanged. The test supports macOS and Linux and requires Python 3, the Rust toolchain and offline-cached Cargo dependencies. The fixture uses its lockfile with `--offline --locked`; compiled files go into the ignored `target` directory unless `CARGO_TARGET_DIR` is set.

The tests call the actual synchronous `sign_psbt` and `sign_transaction` implementations from the working tree, capturing version queries, hash preparation, preview APDUs and signing. Cases cover old-version rejection, 1.6.12 and 1.10.0 P2WSH paths, existing non-P2WSH compatibility, output scripts and host-side signature verification. Inputs, authentication keys and device signatures are synthetic. This fixture does not verify applet execution, authentication, display rendering or real device signatures.
