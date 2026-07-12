import init, {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_acquire,
  bind_check,
  bind_display_code,
  check_update,
  clear_binding_storage,
  clear_transport,
  clear_tsm_client,
  calc_external_address,
  cos_check_update,
  cos_update,
  derive_accounts,
  derive_sub_accounts,
  device_connect,
  get_cert,
  get_battery_power,
  get_ble_name,
  get_ble_version,
  get_device_info,
  get_firmware_version,
  get_life_time,
  get_ram_size,
  get_sdk_info,
  get_seid,
  get_sn,
  is_bl_status,
  secure_check,
  send_apdu,
  send_apdu_unchecked,
  set_ble_name,
  set_binding_storage,
  set_transport,
  set_transport_profile,
  set_tsm_client,
  tsm_post,
} from "../imkey-pkg/ikc_wasm";
import * as ikcWasm from "../imkey-pkg/ikc_wasm";

let ready = false;

export async function initImKeyWasm(): Promise<void> {
  if (ready) return;
  await init({ module_or_path: "/ikc_wasm_bg.wasm" });
  ready = true;
}

function asyncStringExport(name: string): (value: string) => Promise<string> {
  const fn = (ikcWasm as unknown as Record<string, unknown>)[name];
  if (typeof fn !== "function") {
    throw new Error(`${name}_wasm_export_missing_run_make_build_imkey_wasm`);
  }
  return fn as (value: string) => Promise<string>;
}

export function get_address(paramsJson: string): Promise<string> {
  return asyncStringExport("get_address")(paramsJson);
}

export function register_address(paramsJson: string): Promise<string> {
  return asyncStringExport("register_address")(paramsJson);
}

export function register_pub_key(paramsJson: string): Promise<string> {
  return asyncStringExport("register_pub_key")(paramsJson);
}

export function get_public_keys(paramsJson: string): Promise<string> {
  return asyncStringExport("get_public_keys")(paramsJson);
}

export function get_extended_public_keys(paramsJson: string): Promise<string> {
  return asyncStringExport("get_extended_public_keys")(paramsJson);
}

export function derive_accounts_json(paramsJson: string): Promise<string> {
  return asyncStringExport("derive_accounts")(paramsJson);
}

export function derive_sub_accounts_json(paramsJson: string): Promise<string> {
  return asyncStringExport("derive_sub_accounts")(paramsJson);
}

export function calc_external_address_json(paramsJson: string): Promise<string> {
  return asyncStringExport("calc_external_address")(paramsJson);
}

export function sign_tx(paramsJson: string): Promise<string> {
  return asyncStringExport("sign_tx")(paramsJson);
}

export function sign_message(paramsJson: string): Promise<string> {
  return asyncStringExport("sign_message")(paramsJson);
}

export function sign_psbt(paramsJson: string): Promise<string> {
  return asyncStringExport("sign_psbt")(paramsJson);
}

export {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_acquire,
  bind_check,
  bind_display_code,
  calc_external_address,
  check_update,
  clear_binding_storage,
  clear_transport,
  clear_tsm_client,
  cos_check_update,
  cos_update,
  derive_accounts,
  derive_sub_accounts,
  device_connect,
  get_cert,
  get_battery_power,
  get_ble_name,
  get_ble_version,
  get_device_info,
  get_firmware_version,
  get_life_time,
  get_ram_size,
  get_sdk_info,
  get_seid,
  get_sn,
  is_bl_status,
  secure_check,
  send_apdu,
  send_apdu_unchecked,
  set_ble_name,
  set_binding_storage,
  set_transport,
  set_transport_profile,
  set_tsm_client,
  tsm_post,
};
