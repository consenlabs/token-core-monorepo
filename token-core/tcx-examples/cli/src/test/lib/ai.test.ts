import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { buildFallbackAiSummary, generateAiSummary } from "../../lib/ai";
import type { AnalysisResult } from "../../lib/types";

// Minimal AnalysisResult fixture that satisfies buildFallbackAiSummary
const mockAnalysis: AnalysisResult = {
  chainKey: "sepolia",
  chainLabel: "Ethereum Sepolia",
  zhTwSummary: "",
  action: {
    kind: "nativeTransfer",
    title: "ETH 轉帳",
    summary: "直接傳送原生幣",
    functionName: undefined,
    argsSummary: [],
  },
  verification: { verified: false, source: "unknown", message: "" },
  simulation: {
    success: true,
    source: "heuristic",
    summary: "ok",
    tokenChanges: [],
  },
  risks: [{ level: "low", title: "低風險", description: "無明顯風險" }],
  policyViolations: [],
  aiSummary: undefined,
};

// Helper: build a successful Gemini-style fetch response
function geminiOk(text: string) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () =>
      Promise.resolve({
        candidates: [{ content: { parts: [{ text }] } }],
      }),
  } as unknown as Response);
}

// Helper: build a successful Groq/OpenAI-compatible fetch response
function groqOk(text: string) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () =>
      Promise.resolve({
        choices: [{ message: { content: text } }],
      }),
  } as unknown as Response);
}

function errorResponse(status: number) {
  return Promise.resolve({
    ok: false,
    status,
    json: () => Promise.resolve({}),
  } as unknown as Response);
}

// A text long enough and keyword-rich enough to pass isUsefulAiSummary
const goodText =
  "這筆交易的風險需要確認，建議模擬後再送出，合約驗證狀態也請注意。" +
  "這筆交易的風險需要確認，建議模擬後再送出，合約驗證狀態也請注意。" +
  "這筆交易的風險需要確認，建議模擬後再送出，合約驗證狀態也請注意。";

describe("generateAiSummary — waterfall logic", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("returns undefined when no API keys are set", async () => {
    const result = await generateAiSummary(mockAnalysis);
    expect(result).toBeUndefined();
  });

  it("returns gemini result when Gemini succeeds", async () => {
    vi.stubEnv("VITE_GEMINI_API_KEY", "gemini-key");
    vi.mocked(fetch).mockResolvedValueOnce(
      geminiOk(goodText) as unknown as Response,
    );

    const result = await generateAiSummary(mockAnalysis);
    expect(result).toBeDefined();
    expect(result?.provider).toBe("gemini");
    expect(result?.text).toContain("風險");
  });

  it("returns groq result when Gemini fails and Groq succeeds", async () => {
    vi.stubEnv("VITE_GEMINI_API_KEY", "gemini-key");
    vi.stubEnv("VITE_GROQ_API_KEY", "groq-key");

    vi.mocked(fetch)
      .mockResolvedValueOnce(errorResponse(503) as unknown as Response) // Gemini 503 → undefined
      .mockResolvedValueOnce(groqOk(goodText) as unknown as Response); // Groq ok

    const result = await generateAiSummary(mockAnalysis);
    expect(result?.provider).toBe("groq");
  });

  it("returns undefined when Gemini and Groq both fail", async () => {
    vi.stubEnv("VITE_GEMINI_API_KEY", "gemini-key");
    vi.stubEnv("VITE_GROQ_API_KEY", "groq-key");

    vi.mocked(fetch).mockResolvedValue(
      errorResponse(503) as unknown as Response,
    );

    const result = await generateAiSummary(mockAnalysis);
    expect(result).toBeUndefined();
  });

  it("returns groq result when Gemini key is absent (no fetch for Gemini)", async () => {
    // Gemini key not set → generateGeminiSummary returns undefined immediately, no fetch call.
    // import.meta.env VITE_GEMINI_API_KEY may still be present from .env;
    // handle by having its first fetch (if any) return 503.
    vi.stubEnv("VITE_GROQ_API_KEY", "groq-key");
    vi.mocked(fetch)
      .mockResolvedValueOnce(errorResponse(503) as unknown as Response) // Gemini (if key leaked) → skip
      .mockResolvedValueOnce(groqOk(goodText) as unknown as Response); // Groq ok

    const result = await generateAiSummary(mockAnalysis);
    expect(result?.provider).toBe("groq");
  });

  it("returns undefined when provider returns text too short to be useful", async () => {
    vi.stubEnv("VITE_GEMINI_API_KEY", "gemini-key");
    vi.mocked(fetch).mockResolvedValueOnce(
      geminiOk("太短") as unknown as Response,
    );

    const result = await generateAiSummary(mockAnalysis);
    expect(result).toBeUndefined();
  });
});

describe("buildFallbackAiSummary", () => {
  it("returns a non-empty string with key domain terms", () => {
    const summary = buildFallbackAiSummary(mockAnalysis);
    expect(typeof summary).toBe("string");
    expect(summary.length).toBeGreaterThan(20);
    expect(summary).toContain("ETH 轉帳");
  });

  it("includes high-risk advice when primary risk level is high", () => {
    const highRiskAnalysis: AnalysisResult = {
      ...mockAnalysis,
      risks: [{ level: "high", title: "高風險", description: "嚴重問題" }],
    };
    const summary = buildFallbackAiSummary(highRiskAnalysis);
    expect(summary).toContain("建議先不要送出");
  });

  it("includes unverified contract warning when not verified", () => {
    const unverifiedAnalysis: AnalysisResult = {
      ...mockAnalysis,
      verification: { verified: false, source: "unknown", message: "" },
    };
    const summary = buildFallbackAiSummary(unverifiedAnalysis);
    expect(summary).toContain("查不到已驗證原始碼");
  });
});
