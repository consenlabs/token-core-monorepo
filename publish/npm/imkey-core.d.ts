import type { ImKeyStorage } from "./imkey-storage";
import type { FetchTsmClientOptions, TsmClient } from "./imkey-tsm";
import type {
  ImKeyDeviceDescriptor,
  ImKeyEndpointConfig,
  ImKeyUsbFilter,
} from "./imkey-webusb";

export type ImKeyChainType =
  | "BITCOIN" | "DOGECOIN" | "LITECOIN" | "BITCOINCASH"
  | "ETHEREUM" | "COSMOS" | "FILECOIN" | "POLKADOT" | "KUSAMA"
  | "TRON" | "NERVOS" | "TEZOS" | "EOS";

export interface ImKeyCoreOptions {
  tsmClient?: TsmClient;
  tsm?: FetchTsmClientOptions;
  storage?: ImKeyStorage;
  filters?: ImKeyUsbFilter[];
}

export interface ImKeyConnectResult {
  descriptors: ImKeyDeviceDescriptor;
  endpoints: ImKeyEndpointConfig;
}

export interface ImKeyDeviceInfo {
  seid: string;
  sn: string;
  firmware_version: string;
  life_time: string;
}

export interface ImKeyAddressParams {
  chainType: ImKeyChainType;
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
  chainType: ImKeyChainType;
  curve: "secp256k1" | "ed25519";
  path: string;
  network?: string;
}

export interface ImKeyBaseSignParams<TInput, TChain extends ImKeyChainType = ImKeyChainType> {
  chainType: TChain;
  path: string;
  network?: string;
  payment?: string;
  receiver?: string;
  sender?: string;
  fee?: string;
  segWit?: string;
  input: TInput;
}

export interface FilecoinTxInput {
  to: string;
  from: string;
  nonce: number;
  value: string;
  gasLimit: number;
  gasFeeCap: string;
  gasPremium: string;
  method: number;
  params?: string;
}

export type FilecoinSignTxParams = ImKeyBaseSignParams<FilecoinTxInput, "FILECOIN">;
export interface FilecoinSignTxResult {
  cid: string;
  message: FilecoinTxInput;
  signature: { type: number; data: string };
}

export interface NervosOutPoint { txHash: string; index: number; }
export interface NervosWitness { lock?: string; inputType?: string; outputType?: string; }
export interface NervosScript { args: string; codeHash: string; hashType: string; }
export interface NervosCellInput { previousOutput?: NervosOutPoint; since?: string; }
export interface NervosCachedCell {
  capacity?: number;
  lock?: NervosScript;
  outPoint?: NervosOutPoint;
  derivedPath: string;
}
export interface NervosTxInput {
  inputs: NervosCellInput[];
  witnesses: NervosWitness[];
  cachedCells: NervosCachedCell[];
  txHash: string;
}
export type NervosSignTxParams = ImKeyBaseSignParams<NervosTxInput, "NERVOS">;
export interface NervosSignTxResult { txHash: string; witnesses: string[]; }

export interface GenericSignTxResult {
  signature?: string;
  txHash?: string;
  wtxHash?: string;
  transMultiSigns?: Array<{ hash: string; signs: string[] }>;
  edsig?: string;
  sbytes?: string;
}

export class ImKeyCore {
  constructor(options?: ImKeyCoreOptions);
  connect(): Promise<ImKeyConnectResult>;
  disconnect(): Promise<void>;
  diagnostics(): unknown;
  getSdkInfo(): string;
  configureTsm(baseUrl: string): Promise<string>;
  getSeid(): Promise<string>;
  getSn(): Promise<string>;
  getRamSize(): Promise<string>;
  getFirmwareVersion(): Promise<string>;
  getBatteryPower(): Promise<string>;
  getBleName(): Promise<string>;
  setBleName(name: string): Promise<string>;
  getBleVersion(): Promise<string>;
  getLifeTime(): Promise<string>;
  getCert(): Promise<string>;
  getDeviceInfo(): Promise<ImKeyDeviceInfo>;
  sendRawApdu(apduHex: string, timeoutMs?: number): Promise<string>;
  secureCheck(): Promise<unknown>;
  activateDevice(): Promise<unknown>;
  checkUpdate(): Promise<unknown>;
  bindDisplayCode(): Promise<void>;
  bindCheck(): Promise<string>;
  bindAcquire(code: string): Promise<string>;
  getCachedBindKey(seid?: string): Promise<string | null>;
  setCachedBindKey(encryptedKey: string, seid?: string): Promise<void>;
  getAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult>;
  registerAddress(params: ImKeyAddressParams): Promise<ImKeyAddressResult>;
  registerPubKey(params: ImKeyAddressParams): Promise<ImKeyAddressResult>;
  getPublicKeys(derivations: ImKeyPublicKeyDerivation[]): Promise<{ publicKeys: string[] }>;
  getExtendedPublicKeys(derivations: ImKeyPublicKeyDerivation[]): Promise<{ extendedPublicKeys: string[] }>;
  deriveAccounts(params: unknown): Promise<{ accounts: unknown[] }>;
  deriveSubAccounts(params: unknown): Promise<{ accounts: unknown[] }>;
  calcExternalAddress(params: unknown): Promise<unknown>;
  signTx(params: FilecoinSignTxParams): Promise<FilecoinSignTxResult>;
  signTx(params: NervosSignTxParams): Promise<NervosSignTxResult>;
  signTx(params: ImKeyBaseSignParams<unknown>): Promise<GenericSignTxResult>;
  signMessage(params: ImKeyBaseSignParams<unknown>): Promise<{ signature: string }>;
  signPsbt(params: ImKeyBaseSignParams<unknown, "BITCOIN">): Promise<{ psbt: string }>;
  appDownload(appName: string): Promise<unknown>;
  appUpdate(appName: string): Promise<unknown>;
  appDelete(appName: string): Promise<unknown>;
  cosUpdate(): Promise<void>;
  cosCheckUpdate(): Promise<unknown>;
  isBlStatus(): Promise<boolean>;
}

export function initImKeyCore(): Promise<void>;
export function createImKeyCore(options?: ImKeyCoreOptions): ImKeyCore;
