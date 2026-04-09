import init, {
  create_keystore,
  derive_accounts,
  sign_tx,
  sign_message,
  cache_keystore,
  clear_cached_keystore,
  derive_message_key_pair,
  sign_message_event,
  encrypt_message,
  decrypt_message,
} from "../pkg/tcx_wasm";

let ready = false;

export async function initWasm(): Promise<void> {
  if (ready) return;
  await init("/tcx_wasm_bg.wasm");
  ready = true;
}

export {
  create_keystore,
  derive_accounts,
  sign_tx,
  sign_message,
  cache_keystore,
  clear_cached_keystore,
  derive_message_key_pair,
  sign_message_event,
  encrypt_message,
  decrypt_message,
};
