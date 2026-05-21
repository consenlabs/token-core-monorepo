import initTokenCore, {
  create_keystore,
  derive_accounts,
  sign_tx,
} from "@consenlabs/tcx-wasm";
import {
  createPublicClient,
  http,
  type Address,
  type PublicClient,
} from "viem";

import { getChainConfig } from "./chains";
import type {
  DemoChainKey,
  StoredTokenCoreWallet,
  TxRequestDraft,
} from "./types";

const DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/0";

let initialized = false;

interface CreateWalletOptions {
  name: string;
  password: string;
  chainKey: DemoChainKey;
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

function assertInit() {
  if (!initialized) {
    throw new Error("TokenCore 尚未初始化完成。");
  }
}

function createWalletId() {
  return window.crypto.randomUUID();
}

function buildPrfKeyCandidates(prfKey: string) {
  return [prfKey, `0x${prfKey}`];
}

async function withPrfKeyCandidates<T>(
  password: string,
  runner: (prfKey: string) => T | Promise<T>,
) {
  const prfKey = await derivePrfKey(password);
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
    : new Error(String(lastError ?? "TokenCore 操作失敗。"));
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
  const bytes = new Uint8Array(bytesLength);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function normalizeImportWalletError(error: unknown) {
  const message =
    error instanceof Error ? error.message.trim() : String(error ?? "").trim();

  if (
    message.includes("password") ||
    message.includes("decrypt") ||
    message.includes("invalid mac") ||
    message.includes("invalid password")
  ) {
    return new Error("錢包密碼不正確，請重新輸入。");
  }

  return new Error("匯入失敗：密碼不正確，或錢包檔內容與鏈別設定不相符。");
}

export async function initTokenCoreWasm() {
  if (initialized) return;
  await initTokenCore();
  initialized = true;
}

export async function derivePrfKey(password: string) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const bits = await window.crypto.subtle.deriveBits(
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

export async function createTokenCoreWallet({
  name,
  password,
  chainKey,
}: CreateWalletOptions) {
  await initTokenCoreWasm();
  const prfKey = await derivePrfKey(password);
  const chain = getChainConfig(chainKey);

  const keystoreJson = create_keystore(
    JSON.stringify({
      prfKey,
      userId: name,
      credentialId: `${name}-${chainKey}`,
      rpId: window.location.hostname || "localhost",
      entropy: generateEntropyHex(),
    }),
  );

  const account = deriveWalletAccount({
    keystoreJson,
    prfKey,
    derivationPath: DEFAULT_DERIVATION_PATH,
    chainId: chain.chainId,
  });

  const wallet = buildStoredWallet({
    name,
    address: account.address,
    publicKey: account.publicKey,
    keystoreJson,
    chainId: chain.chainId,
    derivationPath: DEFAULT_DERIVATION_PATH,
  });

  return { wallet };
}

export async function importTokenCoreWallet({
  name,
  password,
  chainKey,
  keystoreJson,
  derivationPath = DEFAULT_DERIVATION_PATH,
}: ImportWalletOptions) {
  await initTokenCoreWasm();
  const chain = getChainConfig(chainKey);
  let account: { address: Address; publicKey: string };
  try {
    account = await withPrfKeyCandidates(password, (prfKey) =>
      deriveWalletAccount({
        keystoreJson,
        prfKey,
        derivationPath,
        chainId: chain.chainId,
      }),
    );
  } catch (error) {
    throw normalizeImportWalletError(error);
  }

  return buildStoredWallet({
    name,
    address: account.address,
    publicKey: account.publicKey,
    keystoreJson,
    chainId: chain.chainId,
    derivationPath,
  });
}

function createChainPublicClient(chainKey: DemoChainKey) {
  const config = getChainConfig(chainKey);
  return createPublicClient({
    chain: config.chain,
    transport: http(config.rpcUrl),
  });
}

async function prepareTransactionForSigning(
  client: PublicClient,
  account: Address,
  draft: TxRequestDraft,
) {
  const nonce =
    draft.nonce ?? (await client.getTransactionCount({ address: account }));
  const [gas, fees] = await Promise.all([
    draft.gas ??
      client.estimateGas({
        account,
        to: draft.to,
        data: draft.data,
        value: draft.value,
      }),
    client.estimateFeesPerGas(),
  ]);

  return {
    ...draft,
    chainId: draft.chainId,
    nonce,
    gas,
    maxFeePerGas: fees.maxFeePerGas ?? undefined,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas ?? undefined,
  };
}

export async function signDraftTransaction(
  wallet: StoredTokenCoreWallet,
  password: string,
  chainKey: DemoChainKey,
  draft: TxRequestDraft,
): Promise<SignResult> {
  assertInit();
  const client = createChainPublicClient(chainKey);
  const preparedRequest = await prepareTransactionForSigning(
    client,
    wallet.address,
    draft,
  );

  const result = (await withPrfKeyCandidates(password, (prfKey) =>
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
    ),
  )) as { signature: `0x${string}`; txHash: `0x${string}` };

  return {
    rawTransaction: ensureHexPrefix(result.signature),
    txHash: ensureHexPrefix(result.txHash),
    preparedRequest,
  };
}

export async function broadcastSignedTransaction(
  chainKey: DemoChainKey,
  rawTransaction: `0x${string}`,
) {
  const client = createChainPublicClient(chainKey);
  const hash = await client.sendRawTransaction({
    serializedTransaction: rawTransaction,
  });
  const receipt = await client.waitForTransactionReceipt({ hash });
  return { hash, receipt };
}
