import type { AiProvider } from "../lib/ai";
import {
  getChainConfig,
  getChainKeyById,
  getExplorerTxUrl,
} from "../lib/chains";
import { shortenAddress } from "../lib/format";
import type { AnalysisResult, StoredTokenCoreWallet } from "../lib/types";

const AI_PROVIDER_LABEL: Record<AiProvider, string> = {
  gemini: "Gemini",
  groq: "Groq / Llama",
};

export function renderAnalysisText(analysis: AnalysisResult) {
  const nonPolicyRisks = analysis.risks.filter(
    (risk) => !risk.title.startsWith("Policy 未通過："),
  );

  const sections = [
    [
      "結果摘要",
      analysis.zhTwSummary,
      ...(analysis.aiSummary
        ? [
            analysis.aiProvider
              ? `AI 強化說明（${AI_PROVIDER_LABEL[analysis.aiProvider] ?? analysis.aiProvider}）`
              : "AI 強化說明（本地規則）",
            analysis.aiSummary,
          ]
        : []),
    ],
    [
      "1. 在哪個網路以及在做什麼",
      analysis.chainLabel,
      analysis.action.title,
      analysis.action.summary,
      ...analysis.action.argsSummary.map(
        (item) => `${item.label}: ${item.value}`,
      ),
    ],
    [
      "2. 潛在風險與合約驗證",
      analysis.verification.message,
      analysis.policyViolations.length === 0
        ? "Policy 檢查：目前沒有發現不符合項目。"
        : `Policy 檢查：發現 ${analysis.policyViolations.length} 項不符合。`,
      ...analysis.policyViolations.map(
        (item) =>
          `[${item.level.toUpperCase()}] Policy 未通過：${item.policyName} ${item.description}`,
      ),
      ...nonPolicyRisks.map(
        (risk) =>
          `[${risk.level.toUpperCase()}] ${risk.title} ${risk.description}`,
      ),
    ],
    [
      "3. 模擬結果與 token 變化",
      analysis.simulation.summary,
      analysis.simulation.gasEstimate
        ? `Gas estimate: ${analysis.simulation.gasEstimate}`
        : undefined,
      analysis.simulation.preparedGas
        ? `Prepared gas: ${analysis.simulation.preparedGas}`
        : undefined,
      analysis.simulation.preparedMaxFeePerGas
        ? `Prepared maxFeePerGas: ${analysis.simulation.preparedMaxFeePerGas}`
        : undefined,
      analysis.simulation.preparedMaxPriorityFeePerGas
        ? `Prepared maxPriorityFeePerGas: ${analysis.simulation.preparedMaxPriorityFeePerGas}`
        : undefined,
      analysis.simulation.resultPreview
        ? `Result preview: ${analysis.simulation.resultPreview}`
        : undefined,
      analysis.simulation.simulationUrl
        ? `Tenderly Dashboard 連結: ${analysis.simulation.simulationUrl}`
        : undefined,
      analysis.simulation.publicSimulationUrl
        ? `Tenderly 公開分享連結: ${analysis.simulation.publicSimulationUrl}`
        : undefined,
      analysis.simulation.publicSimulationMessage,
      ...(analysis.simulation.tokenChanges.length > 0
        ? analysis.simulation.tokenChanges.map((item) =>
            [
              shortenAddress(item.address),
              item.note,
              item.amount ? `amount=${item.amount}` : undefined,
              item.tokenAddress ? `token=${item.tokenAddress}` : undefined,
            ]
              .filter(Boolean)
              .join("，"),
          )
        : ["目前沒有推估到明確 token 變化。"]),
    ],
  ];

  return sections
    .map((section) => section.filter(Boolean).join("\n"))
    .join("\n\n");
}

export function renderPolicyWarningText(params: {
  operation: "sign" | "broadcast";
  analysis?: AnalysisResult;
  errorMessage?: string;
}) {
  if (params.errorMessage) {
    return [
      `Policy 預檢警告（${params.operation}）`,
      `無法完成 policy 預檢：${params.errorMessage}`,
      `CLI 仍會繼續執行 ${params.operation}。`,
    ].join("\n");
  }

  if (!params.analysis) return "";

  if (params.analysis.policyViolations.length === 0) {
    return [
      `Policy 預檢（${params.operation}）`,
      "目前沒有發現不符合項目。",
    ].join("\n");
  }

  return [
    `Policy 預檢警告（${params.operation}）`,
    ...params.analysis.policyViolations.map(
      (item) =>
        `[${item.level.toUpperCase()}] ${item.policyName} ${item.description}`,
    ),
  ].join("\n");
}

export function renderWalletText(
  wallet: StoredTokenCoreWallet,
  filePath: string,
) {
  const chainKey = getChainConfig(getChainKeyById(wallet.chainId) ?? "sepolia");
  return [
    `錢包名稱: ${wallet.name}`,
    `錢包 ID: ${wallet.id}`,
    `錢包位置: ${filePath}`,
    `鏈上地址: ${wallet.address}`,
    `鏈別: ${chainKey.label}`,
    `建立時間: ${wallet.createdAt}`,
  ].join("\n");
}

export function renderWalletListText(
  wallets: Array<{ wallet: StoredTokenCoreWallet; filePath: string }>,
) {
  if (wallets.length === 0) {
    return "目前尚未建立任何 CLI 錢包。";
  }

  return wallets
    .map(({ wallet, filePath }, index) =>
      [
        `${index + 1}. ${wallet.name}`,
        `   id: ${wallet.id}`,
        `   address: ${wallet.address}`,
        `   file: ${filePath}`,
      ].join("\n"),
    )
    .join("\n\n");
}

export function renderSignedResultText(params: {
  rawTransaction: string;
  txHash: string;
}) {
  return [
    "簽名完成",
    `txHash: ${params.txHash}`,
    `signedRawTransaction: ${params.rawTransaction}`,
  ].join("\n");
}

export function renderBroadcastResultText(params: {
  chainKey: "sepolia" | "baseSepolia";
  hash: string;
  receipt: { status: string; blockNumber: bigint; gasUsed: bigint };
}) {
  return [
    "廣播完成",
    `txHash: ${params.hash}`,
    `status: ${params.receipt.status}`,
    `blockNumber: ${params.receipt.blockNumber.toString()}`,
    `gasUsed: ${params.receipt.gasUsed.toString()}`,
    `explorer: ${getExplorerTxUrl(params.chainKey, params.hash)}`,
    `tenderly: https://dashboard.tenderly.co/tx/${params.hash}`,
  ].join("\n");
}
