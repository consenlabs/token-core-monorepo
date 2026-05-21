import { getChainConfig, getExplorerTxUrl } from "../lib/chains";
import type { DemoChainKey, ParsedInput, TxRequestDraft } from "../lib/types";

export function buildDraftFromParsed(
  chainKey: DemoChainKey,
  input: ParsedInput,
  account?: `0x${string}`,
): TxRequestDraft {
  return {
    chainId: input.chainId ?? getChainConfig(chainKey).chainId,
    to: input.to,
    data: input.data,
    value: input.value,
    gas: input.gas,
    nonce: input.nonce,
    account: input.from ?? account,
  };
}

export function buildBlockingBroadcastPolicyWarning(policyWarning: string) {
  return policyWarning.replace(
    "CLI 仍會繼續執行 broadcast，請自行判斷是否中止。",
    "已啟用 --policy 廣播攔截；若有不符合項目將停止廣播。",
  );
}

export function buildBlockingSignPolicyWarning(policyWarning: string) {
  return policyWarning.replace(
    "CLI 仍會繼續執行 sign，請自行判斷是否中止。",
    "已啟用 --policy 簽名攔截；若有不符合項目將停止簽名。",
  );
}

export function renderBroadcastTimeoutMessage(
  chainKey: DemoChainKey,
  error: unknown,
  policyWarning?: string,
) {
  const message = error instanceof Error ? error.message : "交易廣播失敗。";
  const txHashMatch = message.match(/txHash=(0x[a-fA-F0-9]+)/);
  const txHash = txHashMatch?.[1];

  return [
    policyWarning,
    policyWarning ? "" : undefined,
    "廣播結果",
    message,
    txHash ? `txHash：${txHash}` : undefined,
    txHash ? `explorer：${getExplorerTxUrl(chainKey, txHash)}` : undefined,
  ]
    .filter(Boolean)
    .join("\n");
}
