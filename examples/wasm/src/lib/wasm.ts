import init, {
  create_keystore,
  derive_accounts,
  sign_tx,
} from "../pkg/tcx_wasm";

let ready = false;

export async function initWasm(): Promise<void> {
  if (ready) return;
  await init("/tcx_wasm_bg.wasm");
  ready = true;
}

export { create_keystore, derive_accounts, sign_tx };
