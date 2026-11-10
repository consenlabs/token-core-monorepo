import initImKeyCoreWasm, * as wasm from "./ikc_wasm.js";
import { connectImKeyWebUsb } from "./imkey-webusb.js";
import { IndexedDbImKeyStorage } from "./imkey-storage.js";
import { FetchTsmClient } from "./imkey-tsm.js";
import { runDeviceSession } from "./imkey-session.js";

let imKeyCoreReady;

export async function initImKeyCore() {
  imKeyCoreReady ??= initImKeyCoreWasm();
  await imKeyCoreReady;
}

function parseJson(value) {
  return JSON.parse(value);
}

export class ImKeyCore {
  #bindingContext = null;

  constructor(options = {}) {
    this.tsmClient = options.tsmClient ?? new FetchTsmClient(options.tsm);
    this.storage = options.storage ?? new IndexedDbImKeyStorage();
    this.filters = options.filters ?? [];
    this.session = null;
  }

  async connect() {
    await initImKeyCore();
    this.session = await connectImKeyWebUsb(this.filters);
    return {
      descriptors: this.session.descriptors,
      endpoints: this.session.endpoints,
    };
  }

  async disconnect() {
    const session = this.session;
    if (!session) return;
    await runDeviceSession(session.transport, wasm, async () => {
      await session.disconnect();
      if (this.session === session) {
        this.session = null;
        this.#bindingContext?.clear();
        this.#bindingContext?.free();
        this.#bindingContext = null;
      }
    });
  }

  #call(method, ...args) {
    const session = this.session;
    if (!session) return Promise.reject(new Error("imkey_transport_not_set"));
    return runDeviceSession(session.transport, wasm, async () => {
      if (this.session !== session) throw new Error("imkey_transport_not_set");
      this.#bindingContext ??= new wasm.ImKeyBindingContext();
      wasm.set_binding_context(this.#bindingContext);
      wasm.set_transport(session.transport);
      wasm.set_transport_profile("webusb");
      wasm.set_tsm_client(this.tsmClient);
      wasm.set_binding_storage(this.storage);
      return wasm[method](...args);
    });
  }

  diagnostics() {
    return this.session?.transport.getDiagnostics() ?? null;
  }

  getSdkInfo() {
    return wasm.get_sdk_info();
  }

  async configureTsm(baseUrl) {
    await initImKeyCore();
    return runDeviceSession(this.session?.transport ?? this, wasm, async () => {
      if (typeof this.tsmClient.configure !== "function") {
        throw new Error("imkey_tsm_client_not_configurable");
      }
      const normalizedBaseUrl = wasm.configure_tsm(baseUrl);
      await this.tsmClient.configure(normalizedBaseUrl);
      return normalizedBaseUrl;
    });
  }

  async getSeid() { return this.#call("get_seid"); }
  async getSn() { return this.#call("get_sn"); }
  async getRamSize() { return this.#call("get_ram_size"); }
  async getFirmwareVersion() { return this.#call("get_firmware_version"); }
  async getBatteryPower() { return this.#call("get_battery_power"); }
  async getBleName() { return this.#call("get_ble_name"); }
  async setBleName(name) { return this.#call("set_ble_name", name); }
  async getBleVersion() { return this.#call("get_ble_version"); }
  async getLifeTime() { return this.#call("get_life_time"); }
  async getCert() { return this.#call("get_cert"); }
  async getDeviceInfo() { return parseJson(await this.#call("get_device_info")); }
  async sendRawApdu(apduHex, timeoutMs) {
    return this.#call("send_apdu_unchecked", apduHex, timeoutMs);
  }

  async secureCheck() { return parseJson(await this.#call("secure_check")); }
  async activateDevice() { return parseJson(await this.#call("activate_device")); }
  async checkUpdate() { return parseJson(await this.#call("check_update")); }
  async bindDisplayCode() { await this.#call("bind_display_code"); }
  async bindCheck() { return this.#call("bind_check"); }
  async bindAcquire(code) { return this.#call("bind_acquire", code); }

  async getCachedBindKey(seid) {
    return this.storage.getBindKey(seid ?? await this.getSeid());
  }

  async setCachedBindKey(encryptedKey, seid) {
    await this.storage.setBindKey(seid ?? await this.getSeid(), encryptedKey);
  }

  async getAddress(params) { return parseJson(await this.#call("get_address", JSON.stringify(params))); }
  async registerAddress(params) {
    return parseJson(await this.#call("register_address", JSON.stringify(params)));
  }
  async registerPubKey(params) {
    return parseJson(await this.#call("register_pub_key", JSON.stringify(params)));
  }
  async getPublicKeys(derivations) {
    return parseJson(await this.#call("get_public_keys", JSON.stringify({ derivations })));
  }
  async getExtendedPublicKeys(derivations) {
    return parseJson(await this.#call("get_extended_public_keys", JSON.stringify({ derivations })));
  }
  async deriveAccounts(params) {
    return parseJson(await this.#call("derive_accounts", JSON.stringify(params)));
  }
  async deriveSubAccounts(params) {
    return parseJson(await this.#call("derive_sub_accounts", JSON.stringify(params)));
  }
  async calcExternalAddress(params) {
    return parseJson(await this.#call("calc_external_address", JSON.stringify(params)));
  }
  async signTx(params) { return parseJson(await this.#call("sign_tx", JSON.stringify(params))); }
  async signMessage(params) {
    return parseJson(await this.#call("sign_message", JSON.stringify(params)));
  }
  async signPsbt(params) { return parseJson(await this.#call("sign_psbt", JSON.stringify(params))); }

  async appDownload(appName) { return parseJson(await this.#call("app_download", appName)); }
  async appUpdate(appName) { return parseJson(await this.#call("app_update", appName)); }
  async appDelete(appName) { return parseJson(await this.#call("app_delete", appName)); }

  async cosUpdate() { await this.#call("cos_update"); }
  async cosCheckUpdate() { return parseJson(await this.#call("cos_check_update")); }
}

export function createImKeyCore(options = {}) {
  return new ImKeyCore(options);
}
