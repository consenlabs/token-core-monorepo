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
  clear_binding_storage,
  clear_transport,
  clear_tsm_client,
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
  is_bl_status,
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

  constructor(
    private readonly tsmClient: TsmClient = new FetchTsmClient(),
    private readonly storage: ImKeyStorage = new IndexedDbImKeyStorage()
  ) {}

  async connect(): Promise<ConnectResult> {
    await initImKeyWasm();
    set_tsm_client(this.tsmClient);
    set_binding_storage(this.storage);
    this.session = await connectImKeyWebUsb();
    set_transport(this.session.transport);
    set_transport_profile("webusb");
    return {
      descriptors: this.session.descriptors,
      endpoints: this.session.endpoints,
    };
  }

  async disconnect(): Promise<void> {
    clear_transport();
    clear_tsm_client();
    clear_binding_storage();
    await this.session?.disconnect();
    this.session = null;
  }

  diagnostics() {
    return this.session?.transport.getDiagnostics() ?? null;
  }

  async getSeid(): Promise<string> {
    return get_seid();
  }

  async getSn(): Promise<string> {
    return get_sn();
  }

  async getRamSize(): Promise<string> {
    return get_ram_size();
  }

  async getFirmwareVersion(): Promise<string> {
    return get_firmware_version();
  }

  getSdkInfo(): string {
    return get_sdk_info();
  }

  async configureTsm(baseUrl: string): Promise<string> {
    await initImKeyWasm();
    if (typeof this.tsmClient.configure !== "function") {
      throw new Error("imkey_tsm_client_not_configurable");
    }
    const normalizedBaseUrl = configure_tsm(baseUrl);
    await this.tsmClient.configure(normalizedBaseUrl);
    set_tsm_client(this.tsmClient);
    return normalizedBaseUrl;
  }

  async getBatteryPower(): Promise<string> {
    return get_battery_power();
  }

  async getBleName(): Promise<string> {
    return get_ble_name();
  }

  async setBleName(bleName: string): Promise<string> {
    return set_ble_name(bleName);
  }

  async getBleVersion(): Promise<string> {
    return get_ble_version();
  }

  async getLifeTime(): Promise<string> {
    return get_life_time();
  }

  async getCert(): Promise<string> {
    return get_cert();
  }

  async getDeviceInfo(): Promise<ImKeyDeviceInfo> {
    return JSON.parse(await get_device_info()) as ImKeyDeviceInfo;
  }

  async sendRawApdu(apduHex: string): Promise<string> {
    return send_apdu_unchecked(apduHex);
  }

  async secureCheck(): Promise<unknown> {
    return JSON.parse(await secure_check());
  }

  async activateDevice(): Promise<unknown> {
    return JSON.parse(await activate_device());
  }

  async checkUpdate(): Promise<unknown> {
    return JSON.parse(await check_update());
  }

  async bindDisplayCode(): Promise<void> {
    await bind_display_code();
  }

  async getCachedBindKey(seid?: string): Promise<string | null> {
    return this.storage.getBindKey(seid ?? (await this.getSeid()));
  }

  async setCachedBindKey(encryptedKey: string, seid?: string): Promise<void> {
    await this.storage.setBindKey(seid ?? (await this.getSeid()), encryptedKey);
  }

  async bindCheck(): Promise<string> {
    return bind_check();
  }

  async bindAcquire(bindCode: string): Promise<string> {
    return bind_acquire(bindCode);
  }

  async getAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await get_address(JSON.stringify(params))) as ImKeyAddressResult;
  }

  async registerAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await register_address(JSON.stringify(params))) as ImKeyAddressResult;
  }

  async registerPubKey(params: ImKeyAddressParams): Promise<ImKeyAddressResult> {
    return JSON.parse(await register_pub_key(JSON.stringify(params))) as ImKeyAddressResult;
  }

  async getPublicKeys(
    derivations: ImKeyPublicKeyDerivation[]
  ): Promise<ImKeyPublicKeysResult> {
    return JSON.parse(
      await get_public_keys(JSON.stringify({ derivations }))
    ) as ImKeyPublicKeysResult;
  }

  async getExtendedPublicKeys(
    derivations: ImKeyPublicKeyDerivation[]
  ): Promise<ImKeyExtendedPublicKeysResult> {
    return JSON.parse(
      await get_extended_public_keys(JSON.stringify({ derivations }))
    ) as ImKeyExtendedPublicKeysResult;
  }

  async deriveAccounts(params: unknown): Promise<ImKeyDeriveAccountsResult> {
    return JSON.parse(await derive_accounts_json(JSON.stringify(params))) as ImKeyDeriveAccountsResult;
  }

  async deriveSubAccounts(params: unknown): Promise<ImKeyDeriveAccountsResult> {
    return JSON.parse(
      await derive_sub_accounts_json(JSON.stringify(params))
    ) as ImKeyDeriveAccountsResult;
  }

  async calcExternalAddress(params: unknown): Promise<ImKeyExternalAddressResult> {
    return JSON.parse(
      await calc_external_address_json(JSON.stringify(params))
    ) as ImKeyExternalAddressResult;
  }

  async signTx(params: unknown): Promise<ImKeySignTxResult> {
    return JSON.parse(await sign_tx(JSON.stringify(params))) as ImKeySignTxResult;
  }

  async signMessage(params: unknown): Promise<ImKeySignMessageResult> {
    return JSON.parse(await sign_message(JSON.stringify(params))) as ImKeySignMessageResult;
  }

  async signPsbt(params: unknown): Promise<ImKeySignPsbtResult> {
    return JSON.parse(await sign_psbt(JSON.stringify(params))) as ImKeySignPsbtResult;
  }

  async appDownload(appName: string): Promise<unknown> {
    return JSON.parse(await app_download(appName));
  }

  async appUpdate(appName: string): Promise<unknown> {
    return JSON.parse(await app_update(appName));
  }

  async appDelete(appName: string): Promise<unknown> {
    return JSON.parse(await app_delete(appName));
  }

  async deviceConnect(): Promise<void> {
    await device_connect();
  }

  async cosUpdate(): Promise<void> {
    await cos_update();
  }

  async cosCheckUpdate(): Promise<unknown> {
    return JSON.parse(await cos_check_update());
  }

  async isBlStatus(): Promise<boolean> {
    return is_bl_status();
  }
}

export function createImKeyCore(options: ImKeyCoreOptions = {}): ImKeyCore {
  return new ImKeyCore(options.tsmClient, options.storage);
}
