import {
  decodeFunctionData,
  parseTransaction,
  recoverTransactionAddress,
  type Abi,
  type Address,
  type Hex,
  type TransactionSerialized,
} from "viem";

import { commonAbiCandidates, selectorLabelMap } from "./abis";
import { getChainConfig, getChainKeyById } from "./chains";
import { getRuntimeEnv } from "./env";
import {
  formatNativeAmount,
  formatUnknown,
  safeAddress,
  shortenAddress,
} from "./format";
import type {
  ContractVerificationStatus,
  DecodedAction,
  DemoChainKey,
  ParsedInput,
} from "./types";

function tryParseBigInt(value: unknown) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return undefined;
}

function normalizeJsonInput(raw: string): ParsedInput {
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const chainId =
    typeof parsed.chainId === "number"
      ? parsed.chainId
      : typeof parsed.chainId === "string"
        ? Number.parseInt(parsed.chainId, 10)
        : undefined;

  const gasValue = parsed.gas ?? parsed.gasLimit;

  return {
    type: "json",
    chainId,
    from: safeAddress((parsed.account ?? parsed.from) as string | undefined),
    to: safeAddress(parsed.to as string | undefined),
    data: ((parsed.data as string | undefined) || undefined) as Hex | undefined,
    value: tryParseBigInt(parsed.value),
    nonce:
      typeof parsed.nonce === "number"
        ? parsed.nonce
        : typeof parsed.nonce === "string"
          ? Number.parseInt(parsed.nonce, 10)
          : undefined,
    gas: tryParseBigInt(gasValue),
    raw,
  };
}

async function normalizeSignedRawInput(raw: Hex): Promise<ParsedInput> {
  const serialized = raw as TransactionSerialized;
  const tx = parseTransaction(serialized);
  const from = await recoverTransactionAddress({
    serializedTransaction: serialized,
  });
  return {
    type: "signedRaw",
    chainId: tx.chainId,
    from,
    to: tx.to ?? undefined,
    data: tx.data,
    value: tx.value,
    nonce: tx.nonce,
    gas: tx.gas,
    raw,
  };
}

export async function parseRawTransactionInput(
  raw: string,
): Promise<ParsedInput> {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("請先貼上 tx request JSON 或 signed raw tx。");
  }

  if (trimmed.startsWith("{")) return normalizeJsonInput(trimmed);
  if (trimmed.startsWith("0x")) return normalizeSignedRawInput(trimmed as Hex);

  throw new Error("目前僅支援 JSON tx request 或 signed raw transaction。");
}

async function fetchEtherscanVerification(
  chainKey: DemoChainKey,
  address: Address,
): Promise<ContractVerificationStatus | null> {
  const apiKey = getRuntimeEnv("VITE_ETHERSCAN_API_KEY");
  if (!apiKey) return null;

  const chainId = getChainConfig(chainKey).chainId;
  const url = new URL("https://api.etherscan.io/v2/api");
  url.searchParams.set("chainid", String(chainId));
  url.searchParams.set("module", "contract");
  url.searchParams.set("action", "getsourcecode");
  url.searchParams.set("address", address);
  url.searchParams.set("apikey", apiKey);

  const response = await fetch(url);
  if (!response.ok) return null;
  const payload = (await response.json()) as {
    result?: Array<{
      ABI?: string;
      SourceCode?: string;
      ContractName?: string;
    }>;
  };

  const first = payload.result?.[0];
  if (!first) return null;

  const abi =
    first.ABI && first.ABI !== "Contract source code not verified"
      ? (JSON.parse(first.ABI) as readonly unknown[])
      : undefined;

  return {
    verified: Boolean(first.SourceCode && first.SourceCode !== ""),
    source: "etherscan",
    contractName: first.ContractName,
    abi,
    message: abi
      ? "已透過 Explorer API 取得驗證 ABI。"
      : "Explorer 顯示此合約未驗證。",
  };
}

async function fetchSourcifyVerification(
  chainKey: DemoChainKey,
  address: Address,
): Promise<ContractVerificationStatus | null> {
  const chainId = getChainConfig(chainKey).chainId;
  const response = await fetch(
    `https://sourcify.dev/server/v2/contract/${chainId}/${address}?fields=abi,match,verifiedAt`,
  );

  if (!response.ok) return null;

  const payload = (await response.json()) as {
    abi?: readonly unknown[];
    match?: string;
    verifiedAt?: string;
  };

  if (!payload.match) return null;

  return {
    verified: true,
    source: "sourcify",
    abi: payload.abi,
    message: payload.verifiedAt
      ? `Sourcify 已驗證，時間：${payload.verifiedAt}`
      : "Sourcify 已驗證。",
  };
}

function buildKnownContractStatus(address: Address, chainKey: DemoChainKey) {
  const chain = getChainConfig(chainKey);
  if (
    address.toLowerCase() === chain.wrappedNativeToken.address.toLowerCase()
  ) {
    return {
      verified: true,
      source: "local",
      abi: commonAbiCandidates[1],
      contractName: chain.wrappedNativeToken.symbol,
      message: "命中內建 WETH 合約設定。",
    } satisfies ContractVerificationStatus;
  }

  const router = chain.uniswap.swapRouter02;
  if (router && address.toLowerCase() === router.toLowerCase()) {
    return {
      verified: true,
      source: "local",
      abi: commonAbiCandidates[3],
      contractName: "Uniswap SwapRouter02",
      message: "命中內建 Uniswap SwapRouter02 設定。",
    } satisfies ContractVerificationStatus;
  }

  return null;
}

/**
 * Sentinel returned when the transaction is a native transfer (no calldata).
 * The target address is an EOA — contract verification is not applicable.
 */
export const NATIVE_TRANSFER_VERIFICATION: ContractVerificationStatus = {
  verified: true,
  source: "local",
  message: "這是原生幣轉帳，目標為 EOA 地址，不需要合約驗證。",
};

export async function resolveContractVerification(
  chainKey: DemoChainKey,
  address?: Address,
): Promise<ContractVerificationStatus> {
  if (!address) {
    return {
      verified: false,
      source: "unknown",
      message: "這筆交易沒有目標合約地址。",
    };
  }

  const explorer = await fetchEtherscanVerification(chainKey, address);
  if (explorer) return explorer;

  const local = buildKnownContractStatus(address, chainKey);
  if (local) return local;

  const sourcify = await fetchSourcifyVerification(chainKey, address);
  if (sourcify) return sourcify;

  return {
    verified: false,
    source: "unknown",
    message: "找不到已驗證原始碼，請提高警覺。",
  };
}

async function lookupSelector(selector: Hex) {
  try {
    const response = await fetch(
      `https://www.4byte.directory/api/v1/signatures/?hex_signature=${selector}`,
    );
    if (!response.ok) return selectorLabelMap[selector];
    const payload = (await response.json()) as {
      results?: Array<{ text_signature: string }>;
    };
    return payload.results?.[0]?.text_signature ?? selectorLabelMap[selector];
  } catch {
    return selectorLabelMap[selector];
  }
}

function buildNativeTransferAction(
  chainKey: DemoChainKey,
  to: Address | undefined,
  value: bigint | undefined,
): DecodedAction {
  return {
    kind: "nativeTransfer",
    title: "原生幣轉帳",
    summary: `把 ${formatNativeAmount(value ?? 0n, chainKey)} 轉給 ${shortenAddress(to)}。`,
    argsSummary: [
      { label: "接收地址", value: to ?? "未提供" },
      { label: "金額", value: formatNativeAmount(value ?? 0n, chainKey) },
    ],
    targetAddress: to,
    value,
  };
}

function buildUnknownAction(
  parsed: ParsedInput,
  selector?: Hex,
  signature?: string,
): DecodedAction {
  return {
    kind: parsed.data ? "contractCall" : "unknown",
    title: parsed.data ? "未知合約呼叫" : "未知交易",
    summary: parsed.data
      ? `偵測到未知 calldata${signature ? `，可能是 ${signature}` : ""}。`
      : "目前無法判斷這筆交易的用途。",
    argsSummary: [
      { label: "目標地址", value: parsed.to ?? "未提供" },
      { label: "selector", value: selector ?? "未提供" },
    ],
    targetAddress: parsed.to,
    selector,
    value: parsed.value,
    functionSignature: signature,
  };
}

function tryDecodeByAbi(abi: Abi, data: Hex) {
  try {
    return decodeFunctionData({ abi, data });
  } catch {
    return null;
  }
}

export async function decodeParsedInput(
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  verification: ContractVerificationStatus,
): Promise<DecodedAction> {
  if (!parsed.data || parsed.data === "0x") {
    return buildNativeTransferAction(chainKey, parsed.to, parsed.value);
  }

  const selector = parsed.data.slice(0, 10) as Hex;
  const candidateAbis = [
    verification.abi as Abi | undefined,
    ...commonAbiCandidates,
  ].filter(Boolean) as Abi[];

  for (const abi of candidateAbis) {
    const decoded = tryDecodeByAbi(abi, parsed.data);
    if (!decoded) continue;

    const argsSummary =
      decoded.args?.map((arg, index) => ({
        label: `參數 ${index + 1}`,
        value: formatUnknown(arg),
      })) ?? [];

    return {
      kind: "contractCall",
      functionName: decoded.functionName,
      functionSignature: selectorLabelMap[selector],
      title: `合約呼叫：${decoded.functionName}`,
      summary: `正在呼叫 ${decoded.functionName}，目標合約是 ${shortenAddress(parsed.to)}。`,
      argsSummary,
      targetAddress: parsed.to,
      selector,
      value: parsed.value,
    };
  }

  const signature = await lookupSelector(selector);
  return buildUnknownAction(parsed, selector, signature);
}

export function inferChainKey(parsed: ParsedInput): DemoChainKey {
  return getChainKeyById(parsed.chainId) ?? "sepolia";
}
