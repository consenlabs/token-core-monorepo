import initImKeyCoreWasm, * as wasm from "./ikc_wasm.js";
import { connectImKeyWebUsb } from "./imkey-webusb.js";
import { IndexedDbImKeyStorage } from "./imkey-storage.js";
import { FetchTsmClient } from "./imkey-tsm.js";

let imKeyCoreReady;

export async function initImKeyCore() {
  imKeyCoreReady ??= initImKeyCoreWasm();
  await imKeyCoreReady;
}

function parseJson(value) {
  return JSON.parse(value);
}

export class ImKeyCore {
  constructor(options = {}) {
    this.tsmClient = options.tsmClient ?? new FetchTsmClient(options.tsm);
    this.storage = options.storage ?? new IndexedDbImKeyStorage();
    this.filters = options.filters ?? [];
    this.session = null;
  }

  async connect() {
    await initImKeyCore();
    wasm.set_tsm_client(this.tsmClient);
    wasm.set_binding_storage(this.storage);
    this.session = await connectImKeyWebUsb(this.filters);
    wasm.set_transport(this.session.transport);
    wasm.set_transport_profile("webusb");
    return {
      descriptors: this.session.descriptors,
      endpoints: this.session.endpoints,
    };
  }

  async disconnect() {
    wasm.clear_transport();
    wasm.clear_tsm_client();
    wasm.clear_binding_storage();
    await this.session?.disconnect();
    this.session = null;
  }

  diagnostics() {
    return this.session?.transport.getDiagnostics() ?? null;
  }

  getSdkInfo() {
    return wasm.get_sdk_info();
  }

  async configureTsm(baseUrl) {
    await initImKeyCore();
    if (typeof this.tsmClient.configure !== "function") {
      throw new Error("imkey_tsm_client_not_configurable");
    }
    const normalizedBaseUrl = wasm.configure_tsm(baseUrl);
    await this.tsmClient.configure(normalizedBaseUrl);
    wasm.set_tsm_client(this.tsmClient);
    return normalizedBaseUrl;
  }

  async getSeid() { return wasm.get_seid(); }
  async getSn() { return wasm.get_sn(); }
  async getRamSize() { return wasm.get_ram_size(); }
  async getFirmwareVersion() { return wasm.get_firmware_version(); }
  async getBatteryPower() { return wasm.get_battery_power(); }
  async getBleName() { return wasm.get_ble_name(); }
  async setBleName(name) { return wasm.set_ble_name(name); }
  async getBleVersion() { return wasm.get_ble_version(); }
  async getLifeTime() { return wasm.get_life_time(); }
  async getCert() { return wasm.get_cert(); }
  async getDeviceInfo() { return parseJson(await wasm.get_device_info()); }
  async sendRawApdu(apduHex, timeoutMs) {
    return wasm.send_apdu_unchecked(apduHex, timeoutMs);
  }

  async secureCheck() { return parseJson(await wasm.secure_check()); }
  async activateDevice() { return parseJson(await wasm.activate_device()); }
  async checkUpdate() { return parseJson(await wasm.check_update()); }
  async bindDisplayCode() { await wasm.bind_display_code(); }
  async bindCheck() { return wasm.bind_check(); }
  async bindAcquire(code) { return wasm.bind_acquire(code); }

  async getCachedBindKey(seid) {
    return this.storage.getBindKey(seid ?? await this.getSeid());
  }

  async setCachedBindKey(encryptedKey, seid) {
    await this.storage.setBindKey(seid ?? await this.getSeid(), encryptedKey);
  }

  async getAddress(params) { return parseJson(await wasm.get_address(JSON.stringify(params))); }
  async registerAddress(params) {
    return parseJson(await wasm.register_address(JSON.stringify(params)));
  }
  async registerPubKey(params) {
    return parseJson(await wasm.register_pub_key(JSON.stringify(params)));
  }
  async getPublicKeys(derivations) {
    return parseJson(await wasm.get_public_keys(JSON.stringify({ derivations })));
  }
  async getExtendedPublicKeys(derivations) {
    return parseJson(await wasm.get_extended_public_keys(JSON.stringify({ derivations })));
  }
  async deriveAccounts(params) {
    return parseJson(await wasm.derive_accounts(JSON.stringify(params)));
  }
  async deriveSubAccounts(params) {
    return parseJson(await wasm.derive_sub_accounts(JSON.stringify(params)));
  }
  async calcExternalAddress(params) {
    return parseJson(await wasm.calc_external_address(JSON.stringify(params)));
  }
  async signTx(params) { return parseJson(await wasm.sign_tx(JSON.stringify(params))); }
  async signMessage(params) {
    return parseJson(await wasm.sign_message(JSON.stringify(params)));
  }
  async signPsbt(params) { return parseJson(await wasm.sign_psbt(JSON.stringify(params))); }

  async appDownload(appName) { return parseJson(await wasm.app_download(appName)); }
  async appUpdate(appName) { return parseJson(await wasm.app_update(appName)); }
  async appDelete(appName) { return parseJson(await wasm.app_delete(appName)); }

  async cosUpdate() { await wasm.cos_update(); }
  async cosCheckUpdate() { return parseJson(await wasm.cos_check_update()); }
}

export function createImKeyCore(options = {}) {
  return new ImKeyCore(options);
}
