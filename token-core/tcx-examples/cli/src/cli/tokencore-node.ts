import initTokenCore, {
  create_keystore,
  derive_accounts,
  sign_tx,
} from "@consenlabs/tcx-wasm/tcx_wasm.js";
import { readFile } from "node:fs/promises";
import { createPublicClient, http, type Address } from "viem";

import { getChainConfig, getChainKeyById } from "../lib/chains";
import type {
  DemoChainKey,
  StoredTokenCoreWallet,
  TxRequestDraft,
} from "../lib/types";

const DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/0";
const DEFAULT_RP_ID = "decode-transaction-cli";

// Gas fee multiplier in basis points (10000 = 1.0x, 12000 = 1.2x).
// Override via TOKENCORE_CLI_GAS_MULTIPLIER_BPS env var. Applied to maxFeePerGas
// and maxPriorityFeePerGas only; gasLimit is not affected.
const GAS_FEE_MULTIPLIER_BPS = BigInt(
  process.env.TOKENCORE_CLI_GAS_MULTIPLIER_BPS ?? "12000",
);
const BPS_BASE = 10000n;

let initialized = false;

interface CreateWalletOptions {
  name: string;
  password: string;
  chainKey: DemoChainKey;
  rpId?: string;
}

interface ImportWalletOptions {
  name: string;
  password: string;
  chainKey: DemoChainKey;
  keystoreJson: string;
  derivationPath?: string;
}

interface SignResult {
  rawTransaction: `0x${string}`;
  txHash: `0x${string}`;
  preparedRequest: Required<Pick<TxRequestDraft, "chainId" | "gas" | "nonce">> &
    TxRequestDraft & {
      maxFeePerGas?: bigint;
      maxPriorityFeePerGas?: bigint;
    };
}

function assertCryptoSupport() {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "目前的 Node 環境不支援 WebCrypto，無法進行 TokenCore 簽名。",
    );
  }
}

function assertInitialized() {
  if (!initialized) {
    throw new Error("TokenCore CLI 尚未初始化完成。");
  }
}

function createWalletId() {
  assertCryptoSupport();
  return globalThis.crypto.randomUUID();
}

function buildPrfKeyCandidates(prfKey: string) {
  return [prfKey, `0x${prfKey}`];
}

async function withPrfKeyCandidates<T>(
  password: string,
  runner: (prfKey: string) => T | Promise<T>,
) {
  const prfKey = await derivePrfKeyNode(password);
  let lastError: unknown;

  for (const candidate of buildPrfKeyCandidates(prfKey)) {
    try {
      return await runner(candidate);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("TokenCore 操作失敗。");
}

export async function initTokenCoreNodeWasm() {
  if (initialized) return;
  const wasmBytes = await readFile(
    new URL(
      "../../node_modules/@consenlabs/tcx-wasm/tcx_wasm_bg.wasm",
      import.meta.url,
    ),
  );
  await initTokenCore({ module_or_path: wasmBytes });
  initialized = true;
}

export async function derivePrfKeyNode(password: string) {
  assertCryptoSupport();
  const encoder = new TextEncoder();
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode("ai-wallet-cli"),
      iterations: 100_000,
      hash: "SHA-256",
    },
    baseKey,
    256,
  );

  const bytes = Array.from(new Uint8Array(bits));
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function createChainPublicClient(chainKey: DemoChainKey) {
  const config = getChainConfig(chainKey);
  return createPublicClient({
    chain: config.chain,
    transport: http(config.rpcUrl),
  });
}

function buildStoredWallet(params: {
  name: string;
  address: Address;
  publicKey: string;
  keystoreJson: string;
  chainId: number;
  derivationPath: string;
}): StoredTokenCoreWallet {
  return {
    id: createWalletId(),
    name: params.name,
    address: params.address,
    keystoreJson: params.keystoreJson,
    publicKey: params.publicKey,
    derivationPath: params.derivationPath,
    chainId: params.chainId,
    createdAt: new Date().toISOString(),
  };
}

function deriveWalletAccount(params: {
  keystoreJson: string;
  prfKey: string;
  derivationPath: string;
  chainId: number;
}) {
  const accounts = JSON.parse(
    derive_accounts(
      JSON.stringify({
        keystoreJson: params.keystoreJson,
        prfKey: params.prfKey,
        derivations: [
          {
            chain: "ETHEREUM",
            derivationPath: params.derivationPath,
            chainId: String(params.chainId),
            network: "MAINNET",
          },
        ],
      }),
    ),
  ) as Array<{ address: Address; publicKey: string }>;
  const first = accounts[0];
  if (!first) {
    throw new Error("TokenCore 未回傳可用帳戶。");
  }
  return first;
}

function ensureHexPrefix(value: string): `0x${string}` {
  return (value.startsWith("0x") ? value : `0x${value}`) as `0x${string}`;
}

function generateEntropyHex(bytesLength = 16) {
  assertCryptoSupport();
  const bytes = new Uint8Array(bytesLength);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export async function createTokenCoreWalletNode({
  name,
  password,
  chainKey,
  rpId = DEFAULT_RP_ID,
}: CreateWalletOptions) {
  await initTokenCoreNodeWasm();
  const prfKey = await derivePrfKeyNode(password);
  const chain = getChainConfig(chainKey);

  const keystoreJson = create_keystore(
    JSON.stringify({
      prfKey,
      userId: name,
      credentialId: `${name}-${chainKey}`,
      rpId,
      entropy: generateEntropyHex(),
    }),
  );

  const account = deriveWalletAccount({
    keystoreJson,
    prfKey,
    derivationPath: DEFAULT_DERIVATION_PATH,
    chainId: chain.chainId,
  });

  return {
    wallet: buildStoredWallet({
      name,
      address: account.address,
      publicKey: account.publicKey,
      keystoreJson,
      chainId: chain.chainId,
      derivationPath: DEFAULT_DERIVATION_PATH,
    }),
  };
}

export async function importTokenCoreWalletNode({
  name,
  password,
  chainKey,
  keystoreJson,
  derivationPath = DEFAULT_DERIVATION_PATH,
}: ImportWalletOptions) {
  await initTokenCoreNodeWasm();
  const chain = getChainConfig(chainKey);
  const account = await withPrfKeyCandidates(password, (prfKey) =>
    deriveWalletAccount({
      keystoreJson,
      prfKey,
      derivationPath,
      chainId: chain.chainId,
    }),
  );

  return buildStoredWallet({
    name,
    address: account.address,
    publicKey: account.publicKey,
    keystoreJson,
    chainId: chain.chainId,
    derivationPath,
  });
}

async function prepareTransactionForSigning(
  client: ReturnType<typeof createChainPublicClient>,
  account: Address,
  draft: TxRequestDraft,
) {
  const nonce =
    draft.nonce ?? (await client.getTransactionCount({ address: account }));
  const [estimatedGas, fees] = await Promise.all([
    draft.gas ??
      client
        .estimateGas({
          account,
          to: draft.to,
          data: draft.data,
          value: draft.value,
        })
        .catch(() => 250000n),
    client.estimateFeesPerGas(),
  ]);

  return {
    ...draft,
    chainId: draft.chainId,
    nonce,
    gas: estimatedGas,
    maxFeePerGas: fees.maxFeePerGas
      ? (fees.maxFeePerGas * GAS_FEE_MULTIPLIER_BPS) / BPS_BASE
      : undefined,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas
      ? (fees.maxPriorityFeePerGas * GAS_FEE_MULTIPLIER_BPS) / BPS_BASE
      : undefined,
  };
}

function resolveChainKeyForWallet(
  wallet: StoredTokenCoreWallet,
  explicitChainKey?: DemoChainKey,
) {
  return explicitChainKey ?? getChainKeyById(wallet.chainId) ?? "sepolia";
}

export async function signDraftTransactionNode(
  wallet: StoredTokenCoreWallet,
  password: string,
  draft: TxRequestDraft,
  explicitChainKey?: DemoChainKey,
): Promise<SignResult> {
  assertInitialized();
  const chainKey = resolveChainKeyForWallet(wallet, explicitChainKey);
  const client = createChainPublicClient(chainKey);
  const preparedRequest = await prepareTransactionForSigning(
    client,
    wallet.address,
    draft,
  );

  const result = await withPrfKeyCandidates(
    password,
    (prfKey) =>
      JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson: wallet.keystoreJson,
            prfKey,
            chain: "ETHEREUM",
            derivationPath: wallet.derivationPath,
            input: {
              nonce: String(preparedRequest.nonce),
              gasLimit: String(preparedRequest.gas),
              to: preparedRequest.to,
              value: String(preparedRequest.value ?? 0n),
              data: preparedRequest.data ?? "0x",
              chainId: String(preparedRequest.chainId),
              txType: "02",
              maxFeePerGas: String(preparedRequest.maxFeePerGas ?? 0n),
              maxPriorityFeePerGas: String(
                preparedRequest.maxPriorityFeePerGas ?? 0n,
              ),
              accessList: [],
            },
          }),
        ),
      ) as { signature: `0x${string}`; txHash: `0x${string}` },
  );

  return {
    rawTransaction: ensureHexPrefix(result.signature),
    txHash: ensureHexPrefix(result.txHash),
    preparedRequest,
  };
}

export async function broadcastSignedTransactionNode(
  chainKey: DemoChainKey,
  rawTransaction: `0x${string}`,
  waitTimeoutMs?: number,
) {
  const client = createChainPublicClient(chainKey);
  const hash = await client.sendRawTransaction({
    serializedTransaction: rawTransaction,
  });
  try {
    const receipt = await client.waitForTransactionReceipt({
      hash,
      timeout: waitTimeoutMs,
    });
    return { hash, receipt };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : String(error ?? "未知錯誤");
    const isTimeout = message.includes(
      "Timed out while waiting for transaction",
    );
    if (!isTimeout) {
      throw error;
    }

    try {
      const receipt = await client.getTransactionReceipt({ hash });
      return { hash, receipt };
    } catch {
      // ignore and continue checking transaction visibility
    }

    let transactionFound = false;
    try {
      await client.getTransaction({ hash });
      transactionFound = true;
    } catch {
      transactionFound = false;
    }

    if (transactionFound) {
      throw new Error(
        `交易已送出，但在等待確認時逾時；補查顯示交易仍可能在鏈上待確認。txHash=${hash}`,
      );
    }

    throw new Error(
      `交易已送出，但在等待確認時逾時；補查仍查不到 receipt。txHash=${hash}`,
    );
  }
}
