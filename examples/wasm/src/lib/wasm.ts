import init, {
  create_keystore,
  derive_accounts,
  sign_tx,
  cache_keystore,
  clear_cached_keystore,
  nostr_get_public_key,
  nostr_sign_event,
  nostr_nip44_encrypt,
  nostr_nip44_decrypt,
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
  cache_keystore,
  clear_cached_keystore,
  nostr_get_public_key,
  nostr_sign_event,
  nostr_nip44_encrypt,
  nostr_nip44_decrypt,
};
