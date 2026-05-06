import { describe, expect, it } from "vitest";

import { renderAnalysisText } from "../../cli/render";
import type { AnalysisResult } from "../../lib/types";

describe("renderAnalysisText", () => {
  it("renders the main analysis sections and links", () => {
    const analysis: AnalysisResult = {
      chainKey: "sepolia",
      chainLabel: "Ethereum Sepolia",
      action: {
        kind: "contractCall",
        functionName: "transfer",
        title: "合約呼叫：transfer",
        summary: "正在呼叫 transfer，目標合約是 0x1c7D...7238。",
        argsSummary: [
          { label: "參數 1", value: "0xabc" },
          { label: "參數 2", value: "10000" },
        ],
      },
      verification: {
        verified: true,
        source: "etherscan",
        message: "已透過 Explorer API 取得驗證 ABI。",
      },
      risks: [
        {
          level: "low",
          title: "未發現明顯高風險訊號",
          description: "仍建議再次核對目標地址、數量與網路。",
        },
      ],
      policyViolations: [],
      simulation: {
        success: true,
        source: "tenderly",
        summary: "Tenderly 模擬顯示交易可執行。",
        preparedGas: "40695",
        preparedMaxFeePerGas: "6174162974",
        preparedMaxPriorityFeePerGas: "1002356",
        simulationUrl:
          "https://dashboard.tenderly.co/demo/project/simulator/123",
        publicSimulationUrl: "https://tdly.co/shared/simulation/123",
        tokenChanges: [
          {
            address: "0xe97b63899e72efbe9ab3f08967dee4edf1eb4270",
            tokenSymbol: "ERC-20",
            tokenAddress: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
            direction: "out",
            amount: "10000",
            note: "預期 token 轉出",
          },
        ],
      },
      zhTwSummary:
        "這筆交易預計在 Ethereum Sepolia 上執行，主要行為是「合約呼叫：transfer」。",
      aiSummary:
        "這筆交易主要是在 Ethereum Sepolia 上執行 transfer，合約已驗證，仍建議再次確認地址與數量。",
    };

    const output = renderAnalysisText(analysis);

    expect(output).toContain("結果摘要");
    expect(output).toContain("1. 在哪個網路以及在做什麼");
    expect(output).toContain("2. 潛在風險與合約驗證");
    expect(output).toContain("3. 模擬結果與 token 變化");
    expect(output).toContain("AI 強化說明");
    expect(output).toContain("Tenderly Dashboard 連結");
    expect(output).toContain("Tenderly 公開分享連結");
    expect(output).toContain("Policy 檢查：目前沒有發現不符合項目。");
    expect(output).not.toContain("Gas estimate：未提供");
    expect(output).not.toContain("Result preview：未提供");
  });

  it("does not duplicate policy violations in risk section", () => {
    const analysis: AnalysisResult = {
      chainKey: "sepolia",
      chainLabel: "Ethereum Sepolia",
      action: {
        kind: "contractCall",
        functionName: "transfer",
        title: "合約呼叫：transfer",
        summary: "正在呼叫 transfer，目標合約是 0x1c7D...7238。",
        argsSummary: [],
      },
      verification: {
        verified: true,
        source: "etherscan",
        message: "已透過 Explorer API 取得驗證 ABI。",
      },
      risks: [
        {
          level: "high",
          title: "Policy 未通過：USDC 轉出上限 10",
          description: "偵測到預計轉出 11 USDC，超過 policy 上限 10 USDC。",
        },
        {
          level: "low",
          title: "未發現明顯高風險訊號",
          description: "仍建議再次核對目標地址、數量與網路。",
        },
      ],
      policyViolations: [
        {
          policyId: "max-usdc-out",
          policyName: "USDC 轉出上限 10",
          level: "high",
          description: "偵測到預計轉出 11 USDC，超過 policy 上限 10 USDC。",
        },
      ],
      simulation: {
        success: true,
        source: "tenderly",
        summary: "Tenderly 模擬顯示交易可執行。",
        tokenChanges: [],
      },
      zhTwSummary: "摘要",
    };

    const output = renderAnalysisText(analysis);
    const matches = output.match(/Policy 未通過：USDC 轉出上限 10/g) ?? [];

    expect(matches).toHaveLength(1);
  });
});
