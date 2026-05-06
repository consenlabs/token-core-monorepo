import type { StoredTokenCoreWallet } from "./types";

export interface StoredWalletFile {
  version: 1;
  wallet: StoredTokenCoreWallet;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function isStoredTokenCoreWallet(
  value: unknown,
): value is StoredTokenCoreWallet {
  if (!isObject(value)) return false;
  return Boolean(
    typeof value.id === "string" &&
    typeof value.name === "string" &&
    typeof value.address === "string" &&
    typeof value.keystoreJson === "string" &&
    typeof value.publicKey === "string" &&
    typeof value.derivationPath === "string" &&
    typeof value.chainId === "number" &&
    typeof value.createdAt === "string",
  );
}

export function parseManagedWalletFile(contents: string) {
  const parsed = JSON.parse(contents) as Partial<StoredWalletFile>;
  if (!parsed.wallet || !isStoredTokenCoreWallet(parsed.wallet)) {
    throw new Error("錢包檔格式不正確。");
  }
  return parsed.wallet;
}

export function serializeManagedWalletFile(wallet: StoredTokenCoreWallet) {
  return JSON.stringify(
    {
      version: 1,
      wallet,
    } satisfies StoredWalletFile,
    null,
    2,
  );
}
