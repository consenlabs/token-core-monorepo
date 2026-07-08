import {
  activate_device,
  app_delete,
  app_download,
  app_update,
  bind_display_code,
  check_update,
  clear_transport,
  clear_tsm_client,
  get_cert,
  get_device_info,
  get_life_time,
  get_seid,
  get_sn,
  initImKeyWasm,
  secure_check,
  send_apdu_unchecked,
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
  battery_power: string;
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

function notMigrated(method: string): never {
  throw new Error(`${method}_not_migrated_to_ikc_wasm`);
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

  async sendRawApduDirect(apduHex: string): Promise<string> {
    if (!this.session) {
      throw new Error("imkey_transport_not_set");
    }
    return this.session.transport.sendApduRaw(apduHex);
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

  async bindCheck(): Promise<never> {
    return notMigrated("bind_check");
  }

  async bindAcquire(_bindCode: string): Promise<never> {
    return notMigrated("bind_acquire");
  }

  async getAddress(_params: unknown): Promise<never> {
    return notMigrated("get_address");
  }

  async signTx(_params: unknown): Promise<never> {
    return notMigrated("sign_tx");
  }

  async signMessage(_params: unknown): Promise<never> {
    return notMigrated("sign_message");
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
}

export function createImKeyCore(options: ImKeyCoreOptions = {}): ImKeyCore {
  return new ImKeyCore(options.tsmClient, options.storage);
}
