import type { Dirent } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import type { StoredTokenCoreWallet } from "../lib/types";
import {
  parseManagedWalletFile,
  serializeManagedWalletFile,
} from "../lib/wallet-file";

export interface ManagedWalletRecord {
  wallet: StoredTokenCoreWallet;
  filePath: string;
}

async function ensureWalletDirectory() {
  await mkdir(getCliWalletsDir(), { recursive: true });
}

function resolveCliHomeDir() {
  const configured = process.env.TOKENCORE_CLI_HOME?.trim();
  if (!configured) {
    return path.join(homedir(), ".tokencore-cli");
  }
  return path.resolve(configured);
}

export function getCliWalletHome() {
  return resolveCliHomeDir();
}

export function getCliWalletsDir() {
  return path.join(resolveCliHomeDir(), "wallets");
}

export async function saveManagedWallet(wallet: StoredTokenCoreWallet) {
  await ensureWalletDirectory();
  const filePath = path.join(getCliWalletsDir(), `${wallet.id}.json`);
  await writeFile(filePath, serializeManagedWalletFile(wallet), "utf8");
  return filePath;
}

export async function listManagedWallets(): Promise<ManagedWalletRecord[]> {
  await ensureWalletDirectory();
  const walletsDir = getCliWalletsDir();
  const entries = await readdir(walletsDir, { withFileTypes: true });
  const walletFiles = entries.filter(
    (entry: Dirent) => entry.isFile() && entry.name.endsWith(".json"),
  );

  const wallets = await Promise.all(
    walletFiles.map(async (entry: Dirent) => {
      const filePath = path.join(walletsDir, entry.name);
      const contents = await readFile(filePath, "utf8");
      return {
        wallet: parseManagedWalletFile(contents),
        filePath,
      } satisfies ManagedWalletRecord;
    }),
  );

  return wallets.sort((left: ManagedWalletRecord, right: ManagedWalletRecord) =>
    right.wallet.createdAt.localeCompare(left.wallet.createdAt),
  );
}

async function loadWalletFile(filePath: string): Promise<ManagedWalletRecord> {
  const contents = await readFile(filePath, "utf8");
  return {
    wallet: parseManagedWalletFile(contents),
    filePath,
  };
}

export async function resolveManagedWallet(
  walletSelector: string,
): Promise<ManagedWalletRecord> {
  const possiblePath = path.resolve(walletSelector);
  try {
    return await loadWalletFile(possiblePath);
  } catch {
    // Fallback to managed wallet lookup by id or name.
  }

  const wallets = await listManagedWallets();
  const exactId = wallets.find((item) => item.wallet.id === walletSelector);
  if (exactId) return exactId;

  const nameMatches = wallets.filter(
    (item) => item.wallet.name === walletSelector,
  );
  if (nameMatches.length === 1) return nameMatches[0];
  if (nameMatches.length > 1) {
    const list = nameMatches
      .map(
        (item) =>
          `  - id: ${item.wallet.id}  address: ${item.wallet.address}  file: ${item.filePath}`,
      )
      .join("\n");
    throw new Error(
      `找到 ${nameMatches.length} 個名稱為「${walletSelector}」的錢包，名稱重複時請改用 wallet id 指定：\n${list}`,
    );
  }

  throw new Error(
    `找不到指定錢包：${walletSelector}。請提供 wallet id、wallet name，或受管理錢包檔路徑。`,
  );
}

export async function readManagedWalletFile(filePath: string) {
  const contents = await readFile(path.resolve(filePath), "utf8");
  return parseManagedWalletFile(contents);
}
