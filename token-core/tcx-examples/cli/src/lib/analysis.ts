import { formatVerificationSource } from "./format";
import type {
  AnalysisResult,
  ContractVerificationStatus,
  DecodedAction,
  PolicyViolation,
  RiskItem,
  SimulationSummary,
} from "./types";

function buildRisk(
  level: RiskItem["level"],
  title: string,
  description: string,
): RiskItem {
  return { level, title, description };
}

export function evaluateRisks(
  action: DecodedAction,
  verification: ContractVerificationStatus,
  simulation: SimulationSummary,
): RiskItem[] {
  const risks: RiskItem[] = [];

  if (action.kind !== "nativeTransfer" && !verification.verified) {
    risks.push(
      buildRisk(
        "high",
        "合約未驗證",
        "目前找不到公開驗證原始碼，表示您很難確認合約真正在做什麼。",
      ),
    );
  }

  if (action.title.includes("未知")) {
    risks.push(
      buildRisk(
        "high",
        "函式用途未知",
        "這筆交易的 selector 沒有被完整解開，對新手而言風險偏高。",
      ),
    );
  }

  if (action.functionName === "approve") {
    const amountText = action.argsSummary[1]?.value ?? "";
    if (amountText.includes("115792089")) {
      risks.push(
        buildRisk(
          "high",
          "近乎無限授權",
          "這筆 approve 看起來像是給對方極大額度，日後可能被持續扣款。",
        ),
      );
    } else {
      risks.push(
        buildRisk(
          "medium",
          "授權風險",
          "approve 不會立即轉走資產，但之後被授權方可在額度內轉走 token。",
        ),
      );
    }
  }

  if (
    action.functionName?.includes("swap") ||
    action.functionName === "exactInputSingle"
  ) {
    const amountOutMin = action.argsSummary[0]?.value ?? "";
    if (amountOutMin === "0") {
      risks.push(
        buildRisk(
          "high",
          "滑價保護偏弱",
          "swap 的最小輸出量是 0，代表您接受任何兌換結果，容易被滑價或 MEV 影響。",
        ),
      );
    } else {
      risks.push(
        buildRisk(
          "medium",
          "價格滑價與路由風險",
          "交換交易可能受到流動性、滑價、手續費與池子狀態影響。",
        ),
      );
    }
  }

  if (!simulation.success) {
    risks.push(
      buildRisk(
        "high",
        "模擬未通過",
        simulation.errorMessage || "模擬顯示交易可能失敗，請勿直接廣播。",
      ),
    );
  }

  if (risks.length === 0) {
    risks.push(
      buildRisk(
        "low",
        "未發現明顯高風險訊號",
        "仍建議再次核對目標地址、數量與網路。",
      ),
    );
  }

  return risks;
}

export function composeZhTwSummary(
  chainLabel: string,
  action: DecodedAction,
  verification: ContractVerificationStatus,
  simulation: SimulationSummary,
  risks: RiskItem[],
) {
  const riskLead = risks[0];
  const verificationSentence =
    action.kind === "nativeTransfer"
      ? "這是原生幣直接轉帳，不涉及合約互動。"
      : verification.verified
        ? `目標合約目前顯示為已驗證，來源是 ${formatVerificationSource(verification.source)}。`
        : "目標合約目前沒有查到已驗證原始碼。";

  const simulationSentence = simulation.success
    ? `模擬結果看起來可執行，來源是 ${simulation.source}。`
    : `模擬結果顯示可能失敗，原因是：${simulation.errorMessage ?? "未知錯誤"}。`;

  return [
    `這筆交易預計在 ${chainLabel} 上執行，主要行為是「${action.title}」。`,
    action.summary,
    verificationSentence,
    simulationSentence,
    `目前最需要注意的是「${riskLead.title}」：${riskLead.description}`,
  ].join(" ");
}

export function buildAnalysisResult(params: {
  chainKey: AnalysisResult["chainKey"];
  chainLabel: string;
  action: DecodedAction;
  verification: ContractVerificationStatus;
  simulation: SimulationSummary;
  policyViolations?: PolicyViolation[];
}): AnalysisResult {
  const risks = evaluateRisks(
    params.action,
    params.verification,
    params.simulation,
  );
  const policyViolations = params.policyViolations ?? [];
  const mergedRisks = [
    ...policyViolations.map((item) =>
      buildRisk(
        item.level,
        `Policy 未通過：${item.policyName}`,
        item.description,
      ),
    ),
    ...risks,
  ];
  const zhTwSummary = composeZhTwSummary(
    params.chainLabel,
    params.action,
    params.verification,
    params.simulation,
    mergedRisks,
  );

  return {
    chainKey: params.chainKey,
    chainLabel: params.chainLabel,
    action: params.action,
    verification: params.verification,
    risks: mergedRisks,
    policyViolations,
    simulation: params.simulation,
    zhTwSummary,
  };
}
