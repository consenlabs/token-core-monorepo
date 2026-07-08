import init, {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_display_code,
  check_update,
  clear_transport,
  clear_tsm_client,
  get_cert,
  get_battery_power,
  get_device_info,
  get_firmware_version,
  get_life_time,
  get_seid,
  get_sn,
  secure_check,
  send_apdu,
  send_apdu_unchecked,
  set_transport,
  set_transport_profile,
  set_tsm_client,
  tsm_post,
} from "../imkey-pkg/ikc_wasm";

let ready = false;

export async function initImKeyWasm(): Promise<void> {
  if (ready) return;
  await init({ module_or_path: "/ikc_wasm_bg.wasm" });
  ready = true;
}

export {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_display_code,
  check_update,
  clear_transport,
  clear_tsm_client,
  get_cert,
  get_battery_power,
  get_device_info,
  get_firmware_version,
  get_life_time,
  get_seid,
  get_sn,
  secure_check,
  send_apdu,
  send_apdu_unchecked,
  set_transport,
  set_transport_profile,
  set_tsm_client,
  tsm_post,
};
