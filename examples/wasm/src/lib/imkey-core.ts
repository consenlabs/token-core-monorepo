import {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_acquire,
  bind_check,
  bind_display_code,
  calc_external_address_json,
  check_update,
  configure_tsm,
  cos_check_update,
  cos_update,
  derive_accounts_json,
  derive_sub_accounts_json,
  device_connect,
  get_cert,
  get_battery_power,
  get_ble_name,
  get_ble_version,
  get_device_info,
  get_address,
  get_extended_public_keys,
  get_firmware_version,
  get_life_time,
  get_public_keys,
  get_ram_size,
  get_sdk_info,
  get_seid,
  get_sn,
  initImKeyWasm,
  register_address,
  register_pub_key,
  secure_check,
  send_apdu_unchecked,
  sign_message,
  sign_psbt,
  sign_tx,
  set_ble_name,
  set_binding_storage,
  set_transport,
  set_transport_profile,
  set_tsm_client,
} from "@/lib/imkey";
import * as imkeyRuntime from "@/lib/imkey";
import { ImKeyBindingContext, set_binding_context } from "../imkey-pkg/ikc_wasm";
import { runDeviceSession } from "../../../../publish/npm/imkey-session.js";
import {
  connectImKeyWebUsb,
  type ImKeyDeviceDescriptor,
  type ImKeyWebUsbSession,
} from "@/lib/imkey-webusb";
import { IndexedDbImKeyStorage, type ImKeyStorage } from "@/lib/imkey-storage";
import { FetchTsmClient, type TsmClient } from "@/lib/imkey-tsm";

export interface ImKeyDeviceInfo {
  seid: string;
  sn: string;
  firmware_version: string;
  life_time: string;
}

export interface ImKeyCoreOptions {
  tsmClient?: TsmClient;
  storage?: ImKeyStorage;
}

export interface ConnectResult {
  descriptors: ImKeyDeviceDescriptor;
  endpoints: {
    interfaceNumber: number;
    inEndpoint: number;
    outEndpoint: number;
    packetSize: number;
  };
}

export interface ImKeyAddressParams {
  chainType: string;
  path: string;
  network?: string;
  segWit?: string;
}

export interface ImKeyAddressResult {
  chainType: string;
  path: string;
  address: string;
}

export interface ImKeyPublicKeyDerivation {
  chainType: string;
  curve: string;
  path: string;
  network?: string;
}

export interface ImKeyPublicKeysResult {
  publicKeys: string[];
}

export interface ImKeyExtendedPublicKeysResult {
  extendedPublicKeys: string[];
}

export interface ImKeyAccountResponse {
  chainType: string;
  address: string;
  path: string;
  curve: string;
  publicKey: string;
  extendedPublicKey: string;
  encryptedExtendedPublicKey: string;
  segWit: string;
}

export interface ImKeyDeriveAccountsResult {
  accounts: ImKeyAccountResponse[];
}

export interface ImKeyExternalAddressResult {
  address: string;
  derivedPath: string;
  type: string;
}

export interface ImKeySignTxResult {
  signature?: string | { type: number; data: string };
  txHash?: string;
  wtxHash?: string;
  cid?: string;
  message?: unknown;
  witnesses?: string[];
  edsig?: string;
  sbytes?: string;
  transMultiSigns?: Array<{ hash: string; signs: string[] }>;
}

export interface ImKeySignMessageResult {
  signature: string;
}

export interface ImKeySignPsbtResult {
  psbt: string;
}

export class ImKeyCore {
  private session: ImKeyWebUsbSession | null = null;
  private bindingContext: ImKeyBindingContext | null = null;

  constructor(
    private readonly tsmClient: TsmClient = new FetchTsmClient(),
    private readonly storage: ImKeyStorage = new IndexedDbImKeyStorage()
  ) {}

  async connect(): Promise<ConnectResult> {
    await initImKeyWasm();
    this.session = await connectImKeyWebUsb();
    return {
      descriptors: this.session.descriptors,
      endpoints: this.session.endpoints,
    };
  }

  async disconnect(): Promise<void> {
    const session = this.session;
    if (!session) return;
    await runDeviceSession(session.transport, imkeyRuntime, async () => {
      await session.disconnect();
      if (this.session === session) {
        this.session = null;
        this.bindingContext?.clear();
        this.bindingContext?.free();
        this.bindingContext = null;
      }
    });
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    const session = this.session;
    if (!session) return Promise.reject(new Error("imkey_transport_not_set"));
    return runDeviceSession(session.transport, imkeyRuntime, async () => {
      if (this.session !== session) throw new Error("imkey_transport_not_set");
      this.bindingContext ??= new ImKeyBindingContext();
      set_binding_context(this.bindingContext);
      set_transport(session.transport);
      set_transport_profile("webusb");
      set_tsm_client(this.tsmClient);
      set_binding_storage(this.storage);
      return operation();
    });
  }

  diagnostics() {
    return this.session?.transport.getDiagnostics() ?? null;
  }

  async getSeid(): Promise<string> {
    return this.run(() => get_seid());
  }

  async getSn(): Promise<string> {
    return this.run(() => get_sn());
  }

  async getRamSize(): Promise<string> {
    return this.run(() => get_ram_size());
  }

  async getFirmwareVersion(): Promise<string> {
    return this.run(() => get_firmware_version());
  }

  getSdkInfo(): string {
    return get_sdk_info();
  }

  async configureTsm(baseUrl: string): Promise<string> {
    await initImKeyWasm();
    return runDeviceSession(this.session?.transport ?? this, imkeyRuntime, async () => {
      if (typeof this.tsmClient.configure !== "function") {
        throw new Error("imkey_tsm_client_not_configurable");
      }
      const normalizedBaseUrl = configure_tsm(baseUrl);
      await this.tsmClient.configure(normalizedBaseUrl);
      return normalizedBaseUrl;
    });
  }

  async getBatteryPower(): Promise<string> {
    return this.run(() => get_battery_power());
  }

  async getBleName(): Promise<string> {
    return this.run(() => get_ble_name());
  }

  async setBleName(bleName: string): Promise<string> {
    return this.run(() => set_ble_name(bleName));
  }

  async getBleVersion(): Promise<string> {
    return this.run(() => get_ble_version());
  }

  async getLifeTime(): Promise<string> {
    return this.run(() => get_life_time());
  }

  async getCert(): Promise<string> {
    return this.run(() => get_cert());
  }

  async getDeviceInfo(): Promise<ImKeyDeviceInfo> {
    return JSON.parse(await this.run(() => get_device_info())) as ImKeyDeviceInfo;
  }

  async sendRawApdu(apduHex: string): Promise<string> {
    return this.run(() => send_apdu_unchecked(apduHex));
  }

  async secureCheck(): Promise<unknown> {
    return JSON.parse(await this.run(() => secure_check()));
  }

  async activateDevice(): Promise<unknown> {
    return JSON.parse(await this.run(() => activate_device()));
  }

  async checkUpdate(): Promise<unknown> {
    return JSON.parse(await this.run(() => check_update()));
  }

  async bindDisplayCode(): Promise<void> {
    await this.run(() => bind_display_code());
  }

  async getCachedBindKey(seid?: string): Promise<string | null> {
    return this.storage.getBindKey(seid ?? (await this.getSeid()));
  }

  async setCachedBindKey(encryptedKey: string, seid?: string): Promise<void> {
    await this.storage.setBindKey(seid ?? (await this.getSeid()), encryptedKey);
  }

  async bindCheck(): Promise<string> {
    return this.run(() => bind_check());
  }

  async bindAcquire(bindCode: string): Promise<string> {
    return this.run(() => bind_acquire(bindCode));
  }

  async getAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await this.run(() => get_address(JSON.stringify(params)))) as ImKeyAddressResult;
  }

  async registerAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await this.run(() => register_address(JSON.stringify(params)))) as ImKeyAddressResult;
  }

  async registerPubKey(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await this.run(() => register_pub_key(JSON.stringify(params)))) as ImKeyAddressResult;
  }

  async getPublicKeys(
    derivations: ImKeyPublicKeyDerivation[]
  ): Promise<ImKeyPublicKeysResult> {
    return JSON.parse(
      await this.run(() => get_public_keys(JSON.stringify({ derivations })))
    ) as ImKeyPublicKeysResult;
  }

  async getExtendedPublicKeys(
    derivations: ImKeyPublicKeyDerivation[]
  ): Promise<ImKeyExtendedPublicKeysResult> {
    return JSON.parse(
      await this.run(() => get_extended_public_keys(JSON.stringify({ derivations })))
    ) as ImKeyExtendedPublicKeysResult;
  }

  async deriveAccounts(params: unknown): Promise<ImKeyDeriveAccountsResult> {
    return JSON.parse(await this.run(() => derive_accounts_json(JSON.stringify(params)))) as ImKeyDeriveAccountsResult;
  }

  async deriveSubAccounts(params: unknown): Promise<ImKeyDeriveAccountsResult> {
    return JSON.parse(
      await this.run(() => derive_sub_accounts_json(JSON.stringify(params)))
    ) as ImKeyDeriveAccountsResult;
  }

  async calcExternalAddress(params: unknown): Promise<ImKeyExternalAddressResult> {
    return JSON.parse(
      await this.run(() => calc_external_address_json(JSON.stringify(params)))
    ) as ImKeyExternalAddressResult;
  }

  async signTx(params: unknown): Promise<ImKeySignTxResult> {
    return JSON.parse(await this.run(() => sign_tx(JSON.stringify(params)))) as ImKeySignTxResult;
  }

  async signMessage(params: unknown): Promise<ImKeySignMessageResult> {
    return JSON.parse(await this.run(() => sign_message(JSON.stringify(params)))) as ImKeySignMessageResult;
  }

  async signPsbt(params: unknown): Promise<ImKeySignPsbtResult> {
    return JSON.parse(await this.run(() => sign_psbt(JSON.stringify(params)))) as ImKeySignPsbtResult;
  }

  async appDownload(appName: string): Promise<unknown> {
    return JSON.parse(await this.run(() => app_download(appName)));
  }

  async appUpdate(appName: string): Promise<unknown> {
    return JSON.parse(await this.run(() => app_update(appName)));
  }

  async appDelete(appName: string): Promise<unknown> {
    return JSON.parse(await this.run(() => app_delete(appName)));
  }

  async deviceConnect(): Promise<void> {
    await this.run(() => device_connect());
  }

  async cosUpdate(): Promise<void> {
    await this.run(() => cos_update());
  }

  async cosCheckUpdate(): Promise<unknown> {
    return JSON.parse(await this.run(() => cos_check_update()));
  }

}

export function createImKeyCore(options: ImKeyCoreOptions = {}): ImKeyCore {
  return new ImKeyCore(options.tsmClient, options.storage);
}
