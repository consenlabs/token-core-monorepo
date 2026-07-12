import initTokenCoreWasm, * as tokenCoreWasm from "./tcx_wasm.js";

let tokenCoreReady;

export async function initTokenCore() {
  tokenCoreReady ??= initTokenCoreWasm();
  await tokenCoreReady;
  return tokenCoreWasm;
}
