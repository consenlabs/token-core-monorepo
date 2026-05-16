import { getRuntimeEnv } from "./env";
import { formatVerificationSource } from "./format";
import { retry, withTimeout } from "./resilience";
import type { AnalysisResult } from "./types";

// P6-m: Only Gemini (free, native CORS) and Groq (free, OpenAI-compatible) are supported.
// Groq requires a Vite dev/preview proxy (/api/groq → https://api.groq.com) in browser context;
// the CLI calls Groq directly over Node.js (no CORS restriction).
const isBrowser = typeof window !== "undefined";

// Groq: free tier 1000 RPD (llama-3.3-70b) / 14400 RPD (llama-3.1-8b)
const GROQ_URL = isBrowser
  ? "/api/groq/openai/v1/chat/completions"
  : "https://api.groq.com/openai/v1/chat/completions";

export type AiProvider = "gemini" | "groq";

export type AiSummaryResult = {
  text: string;
  provider: AiProvider;
};

function stringifyWithBigInt(value: unknown) {
  return JSON.stringify(
    value,
    (_key, currentValue) =>
      typeof currentValue === "bigint" ? currentValue.toString() : currentValue,
    2,
  );
}

/**
 * Strip fields that are large but semantically useless for the AI prompt:
 * - simulation.raw: full Tenderly API response (can be 1.5 MB+ of contract bytecode/ABI data)
 * - verification.abi: full contract ABI array (not needed for risk narration)
 * - simulation URL / gas fee fields: machine-readable numbers; the AI should not invent conclusions from them
 */
function buildAiPromptData(analysis: AnalysisResult) {
  const { simulation, verification, ...rest } = analysis;
  const {
    raw: _raw,
    simulationUrl: _su,
    publicSimulationUrl: _psu,
    publicSimulationMessage: _psm,
    preparedGas: _pg,
    preparedMaxFeePerGas: _pmf,
    preparedMaxPriorityFeePerGas: _pmpf,
    gasEstimate: _ge,
    ...simulationCore
  } = simulation;
  const { abi: _abi, ...verificationCore } =
    verification as typeof verification & { abi?: unknown };
  return {
    ...rest,
    verification: verificationCore,
    simulation: simulationCore,
  };
}

function buildAiPrompt(analysis: AnalysisResult): string {
  return [
    "角色：你是繁體中文（Traditional Chinese）的資深鏈上交易風險分析師，專門向完全不懂區塊鏈的新手解釋交易。",
    "任務：根據提供的 analysis JSON，輸出一段給新手看的風險說明。",
    "語言：請使用繁體中文（Traditional Chinese）。",
    "格式：輸出純文字，不要使用 Markdown、星號、標題、條列符號或表格。",
    "內容要求：必須明確交代 1. 這筆交易在做什麼 2. 最大風險是什麼 3. 合約是否已驗證 4. 模擬結果代表什麼 5. 使用者下一步該如何確認。",
    "限制：不要只重述網路名稱或函式名稱；要有具體風險判讀與建議。不要杜撰 analysis JSON 沒提供的資訊。",
    "長度：請控制在 180 到 260 字之間，使用 3 到 5 句完整句子。",
    stringifyWithBigInt(buildAiPromptData(analysis)),
  ].join("\n\n");
}

function sanitizeAiSummary(value: string) {
  return value.replace(/\*+/g, "").replace(/\s+/g, " ").trim();
}

function isUsefulAiSummary(value: string) {
  const normalized = sanitizeAiSummary(value);
  if (normalized.length < 80) return false;
  const keywords = ["風險", "建議", "確認", "模擬", "合約"];
  const hits = keywords.filter((keyword) =>
    normalized.includes(keyword),
  ).length;
  return hits >= 2;
}

export function buildFallbackAiSummary(analysis: AnalysisResult) {
  const primaryRisk = analysis.risks[0];
  const verificationSentence = analysis.verification.verified
    ? `目標合約目前已驗證，來源是 ${formatVerificationSource(analysis.verification.source)}。`
    : "目標合約目前查不到已驗證原始碼，請提高警覺。";
  const simulationSentence = analysis.simulation.success
    ? "模擬結果目前看起來可執行，但仍不代表實際上鏈一定成功。"
    : `模擬結果顯示可能失敗，原因是 ${analysis.simulation.errorMessage ?? "未知錯誤"}。`;
  const adviceSentence =
    primaryRisk.level === "high"
      ? "建議先不要送出，請重新確認目標地址、數量、授權範圍與交易目的。"
      : "建議送出前再核對目標地址、數量、滑點設定與目前網路是否正確。";

  return [
    `這筆交易主要是在 ${analysis.chainLabel} 上執行「${analysis.action.title}」，${analysis.action.summary}`,
    `目前最需要注意的風險是「${primaryRisk.title}」：${primaryRisk.description}`,
    verificationSentence,
    simulationSentence,
    adviceSentence,
  ].join(" ");
}

async function generateGeminiSummary(
  analysis: AnalysisResult,
): Promise<string | undefined> {
  const apiKey = getRuntimeEnv("VITE_GEMINI_API_KEY");
  if (!apiKey) return undefined;

  const payload = {
    contents: [
      {
        role: "user",
        parts: [{ text: buildAiPrompt(analysis) }],
      },
    ],
    generationConfig: {
      temperature: 0.3,
      topK: 20,
      topP: 0.8,
      maxOutputTokens: 320,
    },
  };

  const response = await retry(
    () =>
      withTimeout(
        () =>
          fetch(
            // gemini-2.0-flash: 15 RPM / 1500 RPD (free tier) — 3x the daily quota of 2.5-flash (500 RPD)
            // and no mandatory thinking mode that can truncate short maxOutputTokens budgets.
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            },
          ),
        12000,
        "Gemini API 逾時，請稍後重試。",
      ),
    {
      retries: 1,
      delayMs: 800,
      shouldRetry: (error) =>
        error.message.includes("逾時") || error.message.includes("fetch"),
    },
  ).catch(() => undefined);

  if (!response) return undefined;
  if (!response.ok) {
    if (response.status === 503 || response.status === 429) return undefined;
    throw new Error(`Gemini API 呼叫失敗：${response.status}`);
  }

  const data = (await response.json()) as {
    candidates?: Array<{
      content?: { parts?: Array<{ text?: string }> };
    }>;
  };

  const merged = data.candidates?.[0]?.content?.parts
    ?.map((part) => part.text?.trim())
    .filter(Boolean)
    .join("")
    .trim();

  if (!merged) return undefined;
  const sanitized = sanitizeAiSummary(merged);
  return isUsefulAiSummary(sanitized) ? sanitized : undefined;
}

async function generateGroqSummary(
  analysis: AnalysisResult,
): Promise<string | undefined> {
  const apiKey = getRuntimeEnv("VITE_GROQ_API_KEY");
  if (!apiKey) return undefined;

  const response = await retry(
    () =>
      withTimeout(
        () =>
          fetch(GROQ_URL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
              // llama-3.3-70b-versatile: best Traditional Chinese quality, 1000 RPD free
              // switch to "llama-3.1-8b-instant" if you need 14400 RPD at lower quality
              model: "llama-3.3-70b-versatile",
              max_completion_tokens: 320,
              messages: [{ role: "user", content: buildAiPrompt(analysis) }],
            }),
          }),
        12000,
        "Groq API 逾時，請稍後重試。",
      ),
    {
      retries: 1,
      delayMs: 800,
      shouldRetry: (error) =>
        error.message.includes("逾時") || error.message.includes("fetch"),
    },
  ).catch(() => undefined);

  if (!response) return undefined;
  if (!response.ok) {
    if (response.status === 503 || response.status === 429) return undefined;
    throw new Error(`Groq API 呼叫失敗：${response.status}`);
  }

  const data = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };

  const text = data.choices?.[0]?.message?.content?.trim();
  if (!text) return undefined;
  const sanitized = sanitizeAiSummary(text);
  return isUsefulAiSummary(sanitized) ? sanitized : undefined;
}

export async function generateAiSummary(
  analysis: AnalysisResult,
): Promise<AiSummaryResult | undefined> {
  // Waterfall: Gemini (free, native CORS) → Groq/Llama (free, proxy) → local fallback
  const providers: Array<{
    name: AiProvider;
    fn: () => Promise<string | undefined>;
  }> = [
    { name: "gemini", fn: () => generateGeminiSummary(analysis) },
    { name: "groq", fn: () => generateGroqSummary(analysis) },
  ];

  for (const { name, fn } of providers) {
    try {
      const text = await fn();
      if (text) return { text, provider: name };
      // undefined = provider skipped (no key, rate-limited, or quality gate failed)
    } catch (err) {
      // Log to DevTools console so developers can see which provider failed and why.
      // Common causes: billing quota exhausted, invalid API key, network error.
      console.warn(
        `[ai] ${name} failed:`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  return undefined;
}
