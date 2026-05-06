import { describe, expect, it } from "vitest";

import { buildAnalysisResult } from "../../lib/analysis";

describe("buildAnalysisResult", () => {
  it("flags approve as a risk", () => {
    const result = buildAnalysisResult({
      chainKey: "sepolia",
      chainLabel: "Ethereum Sepolia",
      action: {
        kind: "contractCall",
        functionName: "approve",
        title: "合約呼叫：approve",
        summary: "授權 spender 使用 token",
        argsSummary: [
          {
            label: "參數 1",
            value: "0x9999999999999999999999999999999999999999",
          },
          { label: "參數 2", value: "1000000000000000000" },
        ],
        targetAddress: "0x8888888888888888888888888888888888888888",
        selector: "0x095ea7b3",
        value: 0n,
      },
      verification: {
        verified: true,
        source: "local",
        message: "內建已知合約",
      },
      simulation: {
        success: true,
        source: "heuristic",
        summary: "成功",
        tokenChanges: [],
      },
    });

    expect(result.risks.some((risk) => risk.title.includes("授權"))).toBe(true);
    expect(result.zhTwSummary).toContain("Ethereum Sepolia");
  });

  it("flags unverifed unknown calls as high risk", () => {
    const result = buildAnalysisResult({
      chainKey: "baseSepolia",
      chainLabel: "Base Sepolia",
      action: {
        kind: "unknown",
        title: "未知合約呼叫",
        summary: "未知 calldata",
        argsSummary: [],
      },
      verification: {
        verified: false,
        source: "unknown",
        message: "未驗證",
      },
      simulation: {
        success: false,
        source: "heuristic",
        summary: "失敗",
        errorMessage: "execution reverted",
        tokenChanges: [],
      },
    });

    expect(
      result.risks.filter((risk) => risk.level === "high").length,
    ).toBeGreaterThan(1);
  });
});
