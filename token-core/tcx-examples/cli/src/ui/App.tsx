import { useCallback, useEffect, useRef, useState } from "react";
import { formatUnits } from "viem";

import { buildFallbackAiSummary, generateAiSummary } from "../lib/ai";
import { buildAnalysisResult } from "../lib/analysis";
import {
  getChainConfig,
  getChainKeyByLabelKey,
  getExplorerTxUrl,
  getTokenPresets,
} from "../lib/chains";
import {
  NATIVE_TRANSFER_VERIFICATION,
  decodeParsedInput,
  inferChainKey,
  parseRawTransactionInput,
  resolveContractVerification,
} from "../lib/decode";
import {
  downloadTextFile,
  formatDateTime,
  formatNativeAmount,
  shortenAddress,
} from "../lib/format";
import { evaluatePolicies, parsePolicyDocument } from "../lib/policy";
import { retry, withTimeout } from "../lib/resilience";
import { estimateExecutionPreview, simulateTransaction } from "../lib/simulate";
import { createTemplateTransaction, templateOptions } from "../lib/templates";
import {
  broadcastSignedTransaction,
  signDraftTransaction,
} from "../lib/tokencore";
import type {
  AnalysisResult,
  DemoChainKey,
  ExecutionPreview,
  PolicyDocument,
  PreparedTx,
  TemplateFormValues,
} from "../lib/types";
import { quoteEthToTokenSwap } from "../lib/uniswap";
import { serializeManagedWalletFile } from "../lib/wallet-file";
import "./App.css";
import { usePolicy } from "./hooks/usePolicy";
import { useWalletManager } from "./hooks/useWalletManager";

const defaultTemplateValues: TemplateFormValues = {
  chainKey: "sepolia",
  kind: "nativeTransfer",
  amount: "0.01",
  amountIn: "0.01",
  amountOutMin: "0",
  tokenDecimals: "18",
  tokenOutDecimals: "18",
  feeBps: "500",
  value: "0",
  data: "0x",
};

function stringifyWithBigInt(value: unknown, space = 2) {
  return JSON.stringify(
    value,
    (_key, currentValue) =>
      typeof currentValue === "bigint" ? currentValue.toString() : currentValue,
    space,
  );
}

function App() {
  const policy = usePolicy();

  const [hasExplicitChainSelection, setHasExplicitChainSelection] =
    useState(false);
  const [templateValues, setTemplateValues] = useState<TemplateFormValues>(
    defaultTemplateValues,
  );

  function requireExplicitChainSelection(): DemoChainKey {
    if (!hasExplicitChainSelection) {
      throw new Error("請先在網路下拉選單選擇 eth-sepolia 或 base-sepolia。");
    }
    return templateValues.chainKey;
  }

  const walletManager = useWalletManager(requireExplicitChainSelection);

  // ── Destructure hooks for backward-compat use in JSX ──────────────────────
  const {
    policyText,
    setPolicyText,
    policyStatus,
    setPolicyStatus,
    parsedPolicyState,
    handleImportPolicyFile,
    handleResetPolicyDocument,
  } = policy;

  const {
    tokenCoreWallets,
    activeTokenCoreWalletId,
    activeTokenCoreWallet,
    tokenCoreName,
    setTokenCoreName,
    tokenCorePassword,
    setTokenCorePassword,
    tokenCoreImportName,
    setTokenCoreImportName,
    tokenCoreImportPassword,
    setTokenCoreImportPassword,
    tokenCoreImportJson,
    setTokenCoreImportJson,
    tokenCoreStatus,
    selectTokenCoreWallet,
    handleDeleteTokenCoreWallet,
    handleCreateTokenCoreWallet,
    handleImportTokenCoreWallet,
    handleImportWalletFile,
  } = walletManager;

  // ── Remaining local state ────────────────────────────────────────────────
  const [preparedTx, setPreparedTx] = useState<PreparedTx | undefined>();
  const [executionPreview, setExecutionPreview] = useState<
    ExecutionPreview | undefined
  >();
  const [templateCopyStatus, setTemplateCopyStatus] = useState("");
  const [rawInput, setRawInput] = useState("");
  const [analysis, setAnalysis] = useState<AnalysisResult | undefined>();
  const [analysisStatus, setAnalysisStatus] = useState(
    "尚未進行 decode / simulate",
  );
  const [aiStatus, setAiStatus] = useState("未啟用 AI 強化說明");
  const [tokenCoreSignPassword, setTokenCoreSignPassword] = useState("");
  const [tokenCoreSignedRaw, setTokenCoreSignedRaw] = useState<string>("");
  const [tokenCoreSignedHash, setTokenCoreSignedHash] = useState<string>("");
  const [sendStatus, setSendStatus] = useState("尚未送出交易");
  const [sentHash, setSentHash] = useState<string>("");
  const [quoteStatus, setQuoteStatus] = useState(
    "尚未估算 Uniswap amountOutMinimum",
  );
  const [isAutoAmountOutMin, setIsAutoAmountOutMin] = useState(true);
  const autoQuoteKeyRef = useRef("");

  const currentSourceAddress = activeTokenCoreWallet?.address;

  const tokenPresets = hasExplicitChainSelection
    ? getTokenPresets(templateValues.chainKey)
    : [];
  const selectedTokenOutPreset = tokenPresets.find(
    (token) =>
      token.address.toLowerCase() ===
      (templateValues.tokenOut ?? "").toLowerCase(),
  );
  const amountOutMinimumLabel = selectedTokenOutPreset
    ? `amountOutMinimum (${selectedTokenOutPreset.symbol})`
    : "amountOutMinimum（目標 Token 單位）";

  function updateTemplate<K extends keyof TemplateFormValues>(
    key: K,
    value: TemplateFormValues[K],
  ) {
    setTemplateValues((previous) => ({ ...previous, [key]: value }));
  }

  function handleTokenPresetChange(
    kind: "tokenAddress" | "tokenOut",
    value: string,
  ) {
    const preset = tokenPresets.find(
      (item) => item.address.toLowerCase() === value.toLowerCase(),
    );

    if (kind === "tokenAddress") {
      setTemplateValues((previous) => ({
        ...previous,
        tokenAddress: value ? (value as `0x${string}`) : undefined,
        tokenDecimals: preset
          ? String(preset.decimals)
          : previous.tokenDecimals,
      }));
      return;
    }

    setTemplateValues((previous) => ({
      ...previous,
      tokenOut: value ? (value as `0x${string}`) : undefined,
      tokenOutDecimals: preset
        ? String(preset.decimals)
        : previous.tokenOutDecimals,
    }));
  }

  const handleAutoQuoteAmountOutMinimum = useCallback(async () => {
    try {
      if (templateValues.kind !== "uniswapV2SwapExactETHForTokens") {
        throw new Error("只有 Uniswap 範本需要自動估值。");
      }
      if (!templateValues.tokenOut) {
        throw new Error("請先選擇 tokenOut。");
      }
      if (!templateValues.amountIn?.trim()) {
        throw new Error("請先輸入 amountIn。");
      }
      if (!currentSourceAddress) {
        throw new Error("請先提供來源地址。");
      }

      const tokenOut = templateValues.tokenOut;
      const amountIn = templateValues.amountIn;
      const recipientAddress = (templateValues.recipient ??
        currentSourceAddress) as `0x${string}`;

      setQuoteStatus("正在鏈上查詢池子價格並估算 amountOutMinimum...");
      const quote = await retry(
        () =>
          withTimeout(
            () =>
              quoteEthToTokenSwap({
                chainKey: templateValues.chainKey,
                tokenOut,
                amountIn,
                tokenOutDecimals: templateValues.tokenOutDecimals,
                slippageBps: 1000,
                account: currentSourceAddress,
                recipient: recipientAddress,
              }),
            10000,
            "鏈上估值逾時，請稍後重試。",
          ),
        {
          retries: 1,
          delayMs: 500,
        },
      );

      setTemplateValues((previous) => ({
        ...previous,
        feeBps: String(quote.poolFee),
        amountOutMin: formatUnits(
          quote.amountOutMinimum,
          quote.tokenOutDecimals,
        ),
        tokenOutDecimals: String(quote.tokenOutDecimals),
      }));
      setIsAutoAmountOutMin(true);
      autoQuoteKeyRef.current = [
        templateValues.chainKey,
        templateValues.tokenOut,
        templateValues.amountIn,
        templateValues.recipient ?? currentSourceAddress,
      ].join("|");
      setQuoteStatus(
        `已依鏈上池子估算 amountOutMinimum=${formatUnits(quote.amountOutMinimum, quote.tokenOutDecimals)}，fee=${quote.poolFee}，已套用 10% 滑點保護。`,
      );
    } catch (error) {
      setQuoteStatus(
        error instanceof Error ? error.message : "自動估值失敗，請手動輸入。",
      );
    }
  }, [
    currentSourceAddress,
    templateValues.amountIn,
    templateValues.chainKey,
    templateValues.kind,
    templateValues.recipient,
    templateValues.tokenOut,
    templateValues.tokenOutDecimals,
  ]);

  useEffect(() => {
    if (templateValues.kind !== "uniswapV2SwapExactETHForTokens") return;
    if (!templateValues.tokenOut || !templateValues.amountIn?.trim()) return;
    if (!currentSourceAddress) return;
    if (!isAutoAmountOutMin && templateValues.amountOutMin?.trim()) return;

    const quoteKey = [
      templateValues.chainKey,
      templateValues.tokenOut,
      templateValues.amountIn,
      templateValues.recipient ?? currentSourceAddress,
    ].join("|");
    if (autoQuoteKeyRef.current === quoteKey) return;

    const timer = window.setTimeout(() => {
      void handleAutoQuoteAmountOutMinimum();
    }, 350);

    return () => window.clearTimeout(timer);
  }, [
    currentSourceAddress,
    handleAutoQuoteAmountOutMinimum,
    isAutoAmountOutMin,
    templateValues.amountIn,
    templateValues.amountOutMin,
    templateValues.chainKey,
    templateValues.kind,
    templateValues.recipient,
    templateValues.tokenOut,
    templateValues.tokenOutDecimals,
  ]);

  async function handleGenerateTemplate() {
    try {
      requireExplicitChainSelection();
      let nextValues = {
        ...templateValues,
        chainKey: templateValues.chainKey,
        from: currentSourceAddress,
      };

      if (
        templateValues.kind === "uniswapV2SwapExactETHForTokens" &&
        templateValues.tokenOut &&
        templateValues.amountIn?.trim() &&
        (!templateValues.amountOutMin || templateValues.amountOutMin === "0")
      ) {
        const tokenOut = templateValues.tokenOut;
        const amountIn = templateValues.amountIn;
        const recipientAddress = (templateValues.recipient ??
          currentSourceAddress) as `0x${string}`;
        const quote = await retry(
          () =>
            withTimeout(
              () =>
                quoteEthToTokenSwap({
                  chainKey: templateValues.chainKey,
                  tokenOut,
                  amountIn,
                  tokenOutDecimals: templateValues.tokenOutDecimals,
                  slippageBps: 1000,
                  account: currentSourceAddress,
                  recipient: recipientAddress,
                }),
              10000,
              "建立模板前的鏈上估值逾時。",
            ),
          {
            retries: 1,
            delayMs: 500,
          },
        );
        nextValues = {
          ...nextValues,
          feeBps: String(quote.poolFee),
          amountOutMin: formatUnits(
            quote.amountOutMinimum,
            quote.tokenOutDecimals,
          ),
          tokenOutDecimals: String(quote.tokenOutDecimals),
        };
        setIsAutoAmountOutMin(true);
        setTemplateValues(nextValues);
        setQuoteStatus(
          `建立模板前已自動估算 amountOutMinimum=${formatUnits(quote.amountOutMinimum, quote.tokenOutDecimals)}，fee=${quote.poolFee}。`,
        );
      }

      const tx = createTemplateTransaction(nextValues);
      const preview = await estimateExecutionPreview(tx.chainKey, {
        from: tx.request.account,
        to: tx.request.to,
        data: tx.request.data,
        value: tx.request.value,
        gas: tx.request.gas,
      }).catch(() => undefined);
      const preparedWithPreview = preview
        ? {
            ...tx,
            request: {
              ...tx.request,
              gas: preview.gas,
            },
          }
        : tx;
      setPreparedTx(preparedWithPreview);
      setExecutionPreview(preview);
      setTemplateCopyStatus("");
      setRawInput(
        stringifyWithBigInt(
          preview
            ? {
                ...tx.request,
                gas: preview.gas,
              }
            : tx.request,
        ),
      );
      setAnalysis(undefined);
      setTokenCoreSignedRaw("");
      setTokenCoreSignedHash("");
      setSendStatus("模板已建立，尚未送出交易");
      setSentHash("");
      setAnalysisStatus(`已產生模板：${tx.title}`);
    } catch (error) {
      setExecutionPreview(undefined);
      setAnalysisStatus(
        error instanceof Error ? error.message : "建立模板失敗。",
      );
    }
  }

  async function handleCopyCliInput(jsonLine: string) {
    try {
      await navigator.clipboard.writeText(jsonLine);
      setTemplateCopyStatus("已複製 CLI 可用的一列式 JSON。");
    } catch {
      setTemplateCopyStatus("複製失敗，請手動選取下方文字。");
    }
  }

  async function handleAnalyzeRawInput() {
    try {
      requireExplicitChainSelection();
      setAnalysisStatus("正在解碼與模擬交易...");
      setAiStatus("AI 強化說明尚未產生");
      let policyDocument: PolicyDocument;
      try {
        policyDocument = parsePolicyDocument(policyText);
        setPolicyStatus(`已解析 ${policyDocument.policies.length} 條 policy`);
      } catch (error) {
        throw new Error(
          error instanceof Error
            ? `Policy JSON 格式錯誤：${error.message}`
            : "Policy JSON 格式錯誤。",
        );
      }
      const parsed = await parseRawTransactionInput(rawInput);
      const chainKey = parsed.chainId
        ? inferChainKey(parsed)
        : templateValues.chainKey;
      const isNativeTransfer = !parsed.data || parsed.data === "0x";
      const verification = isNativeTransfer
        ? NATIVE_TRANSFER_VERIFICATION
        : await resolveContractVerification(chainKey, parsed.to);
      const action = await decodeParsedInput(chainKey, parsed, verification);
      const simulation = await simulateTransaction(chainKey, parsed, action);
      const policyViolations = evaluatePolicies({
        document: policyDocument,
        chainKey,
        parsed,
        action,
        verification,
        simulation,
      }).violations;
      const analysisResult = buildAnalysisResult({
        chainKey,
        chainLabel: getChainConfig(chainKey).label,
        action,
        verification,
        simulation,
        policyViolations,
      });

      setAnalysis(analysisResult);
      setAnalysisStatus("decode / simulate 完成");

      try {
        const aiResult = await generateAiSummary(analysisResult);
        if (aiResult) {
          setAnalysis((previous) =>
            previous ? { ...previous, aiSummary: aiResult.text } : previous,
          );
          const providerLabel: Record<string, string> = {
            gemini: "Gemini",
            groq: "Groq / Llama",
          };
          setAiStatus(
            `已透過 ${providerLabel[aiResult.provider] ?? aiResult.provider} 產生繁體中文加強版說明`,
          );
        } else {
          const fallbackAiSummary = buildFallbackAiSummary(analysisResult);
          setAnalysis((previous) =>
            previous ? { ...previous, aiSummary: fallbackAiSummary } : previous,
          );
          setAiStatus(
            "所有 AI 服務暫時忙碌或回覆品質不足，已改用本地加強版說明",
          );
        }
      } catch (error) {
        setAiStatus(
          error instanceof Error
            ? `AI 強化說明失敗，已退回本地規則：${error.message}`
            : "AI 強化說明失敗，已退回本地規則",
        );
      }
    } catch (error) {
      setAnalysis(undefined);
      setAnalysisStatus(error instanceof Error ? error.message : "解析失敗。");
    }
  }

  async function handleTokenCoreSign() {
    try {
      requireExplicitChainSelection();
      if (!preparedTx) throw new Error("請先建立一筆交易模板。");
      if (!activeTokenCoreWallet) throw new Error("請先選擇 TokenCore 錢包。");
      if (!tokenCoreSignPassword.trim())
        throw new Error("請輸入 TokenCore 簽名密碼。");

      if (!analysis) {
        throw new Error(
          "請先點擊「Decode + Simulate」完成解析與 policy 評估，再執行簽名。",
        );
      }
      if (analysis.policyViolations.length > 0) {
        throw new Error(
          `Policy 未通過，已停止簽名。違反項目：${analysis.policyViolations.map((v) => v.policyName).join("、")}`,
        );
      }

      const result = await signDraftTransaction(
        activeTokenCoreWallet,
        tokenCoreSignPassword,
        preparedTx.chainKey,
        {
          ...preparedTx.request,
          account: activeTokenCoreWallet.address,
        },
      );
      setTokenCoreSignedRaw(result.rawTransaction);
      setTokenCoreSignedHash(result.txHash);
      setRawInput(result.rawTransaction);
      setSendStatus("TokenCore 已完成簽名，可選擇再廣播上鏈");
    } catch (error) {
      setSendStatus(
        error instanceof Error ? error.message : "TokenCore 簽名失敗。",
      );
    }
  }

  async function handleTokenCoreBroadcast() {
    try {
      requireExplicitChainSelection();
      if (!preparedTx || !tokenCoreSignedRaw) {
        throw new Error("請先完成 TokenCore 簽名。");
      }

      if (!analysis) {
        throw new Error(
          "請先點擊「Decode + Simulate」完成解析與 policy 評估，再執行廣播。",
        );
      }
      if (analysis.policyViolations.length > 0) {
        throw new Error(
          `Policy 未通過，已停止廣播。違反項目：${analysis.policyViolations.map((v) => v.policyName).join("、")}`,
        );
      }

      const result = await broadcastSignedTransaction(
        preparedTx.chainKey,
        tokenCoreSignedRaw as `0x${string}`,
      );
      setSentHash(result.hash);
      setSendStatus(`TokenCore 已廣播並確認：${result.hash}`);
    } catch (error) {
      setSendStatus(
        error instanceof Error ? error.message : "TokenCore 廣播失敗。",
      );
    }
  }

  const cliInputLine = preparedTx
    ? stringifyWithBigInt(
        executionPreview
          ? {
              ...preparedTx.request,
              gas: executionPreview.gas,
              maxFeePerGas: executionPreview.maxFeePerGas,
              maxPriorityFeePerGas: executionPreview.maxPriorityFeePerGas,
            }
          : preparedTx.request,
        0,
      )
    : "";

  return (
    <main className="app-shell">
      <section className="hero-panel">
        <div>
          <p className="eyebrow">TokenCore CLI UI Tools</p>
          <h1>看懂一筆 EVM 交易</h1>
          <p className="hero-copy">
            這個 Demo 會協助您建立測試網交易、解碼
            calldata、查驗合約是否已驗證、進行模擬並說明潛在風險，最後再由
            TokenCore 決定是否送上鏈。
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="step-label">區塊 1</p>
            <h2>Policy 規則</h2>
          </div>
        </div>

        <div className="grid-two">
          <div className="card">
            <label className="full-span">
              Policy JSON
              <textarea
                value={policyText}
                onChange={(event) => setPolicyText(event.target.value)}
                placeholder='{"version":1,"name":"...","policies":[]}'
              />
            </label>
            <div className="copy-row">
              <label>
                載入 policy JSON 檔
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={handleImportPolicyFile}
                />
              </label>
              <button type="button" onClick={handleResetPolicyDocument}>
                重設為預設 Policy
              </button>
            </div>
            <p className="status-text">{policyStatus}</p>
            <p className="small-text">
              {parsedPolicyState.error ??
                "Policy JSON 格式正確，可直接用於 Decode + Simulate。"}
            </p>
          </div>

          <div className="card">
            <h3>目前載入的 Policy</h3>
            {parsedPolicyState.document ? (
              <>
                <p className="status-text">{parsedPolicyState.document.name}</p>
                <p className="small-text">
                  {parsedPolicyState.document.description ?? "未提供說明"}
                </p>
                <ul>
                  {parsedPolicyState.document.policies.map((policy) => (
                    <li key={policy.id}>
                      <strong>{policy.name}</strong>{" "}
                      {policy.enabled === false ? "（停用）" : "（啟用）"}
                      {policy.description ? ` ${policy.description}` : ""}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="small-text">
                目前 policy JSON 無法解析，請先修正內容。
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="step-label">區塊 2</p>
            <h2>建立新的帳號</h2>
          </div>
        </div>

        <>
          <div className="grid-two">
            <div className="card">
              <h3>TokenCore 新帳號</h3>
              <label>
                錢包名稱
                <input
                  value={tokenCoreName}
                  onChange={(event) => setTokenCoreName(event.target.value)}
                  placeholder="demo-wallet"
                />
              </label>
              <label>
                建立密碼
                <input
                  type="password"
                  value={tokenCorePassword}
                  onChange={(event) => setTokenCorePassword(event.target.value)}
                  placeholder="請輸入密碼"
                />
              </label>
              <button onClick={handleCreateTokenCoreWallet}>
                建立 TokenCore 錢包
              </button>
              <p className="status-text">{tokenCoreStatus}</p>
            </div>
            <div className="card">
              <h3>匯入既有 TokenCore 錢包檔</h3>
              <label>
                錢包名稱
                <input
                  value={tokenCoreImportName}
                  onChange={(event) =>
                    setTokenCoreImportName(event.target.value)
                  }
                  placeholder="imported-wallet"
                />
              </label>
              <label>
                錢包密碼
                <input
                  type="password"
                  value={tokenCoreImportPassword}
                  onChange={(event) =>
                    setTokenCoreImportPassword(event.target.value)
                  }
                  placeholder="請輸入錢包密碼"
                />
              </label>
              <label>
                選擇錢包檔
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={handleImportWalletFile}
                />
              </label>
              <label>
                或直接貼上錢包檔 JSON
                <textarea
                  value={tokenCoreImportJson}
                  onChange={(event) =>
                    setTokenCoreImportJson(event.target.value)
                  }
                  placeholder='{"version":1,"wallet":{"id":"...","name":"...","address":"0x..."}}'
                />
              </label>
              <button onClick={handleImportTokenCoreWallet}>
                匯入 TokenCore 錢包
              </button>
            </div>
          </div>

          <div className="card">
            <h3>已儲存的 TokenCore 錢包</h3>
            <div className="wallet-list">
              {tokenCoreWallets.length === 0 ? (
                <p className="small-text">尚未建立 TokenCore 錢包。</p>
              ) : (
                tokenCoreWallets.map((wallet) => (
                  <div key={wallet.id} className="wallet-row">
                    <button
                      className={
                        wallet.id === activeTokenCoreWalletId
                          ? "wallet-chip active"
                          : "wallet-chip"
                      }
                      onClick={() => selectTokenCoreWallet(wallet.id)}
                    >
                      <span>{wallet.name}</span>
                      <strong>{shortenAddress(wallet.address)}</strong>
                    </button>
                    <button
                      type="button"
                      className="danger-button"
                      onClick={() => handleDeleteTokenCoreWallet(wallet.id)}
                    >
                      刪除
                    </button>
                  </div>
                ))
              )}
            </div>
            {activeTokenCoreWallet ? (
              <div className="info-box">
                <p>
                  建立時間：{formatDateTime(activeTokenCoreWallet.createdAt)}
                </p>
                <button
                  onClick={() =>
                    downloadTextFile(
                      `${activeTokenCoreWallet.name}.wallet.json`,
                      serializeManagedWalletFile(activeTokenCoreWallet),
                    )
                  }
                >
                  下載共用錢包檔
                </button>
              </div>
            ) : null}
          </div>
        </>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="step-label">區塊 3</p>
            <h2>建立常見 tx raw data</h2>
          </div>
        </div>

        <div className="grid-two">
          <div className="card form-grid">
            <label>
              網路
              <select
                value={
                  hasExplicitChainSelection
                    ? getChainConfig(templateValues.chainKey).chainLabelKey
                    : ""
                }
                onChange={(event) => {
                  if (!event.target.value) {
                    setHasExplicitChainSelection(false);
                    return;
                  }
                  const nextChainKey = getChainKeyByLabelKey(
                    event.target.value,
                  );
                  if (!nextChainKey) return;
                  setHasExplicitChainSelection(true);
                  updateTemplate("chainKey", nextChainKey);
                }}
              >
                <option value="">請先選擇</option>
                <option value="eth-sepolia">eth-sepolia</option>
                <option value="base-sepolia">base-sepolia</option>
              </select>
            </label>
            <label>
              範本
              <select
                value={templateValues.kind}
                onChange={(event) =>
                  updateTemplate(
                    "kind",
                    event.target.value as TemplateFormValues["kind"],
                  )
                }
              >
                {templateOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="address-field">
              來源地址
              <input
                className="address-control"
                value={currentSourceAddress ?? ""}
                onChange={(event) =>
                  updateTemplate("from", event.target.value as `0x${string}`)
                }
                placeholder="自動帶入當前模式地址"
              />
            </label>
            {(templateValues.kind === "nativeTransfer" ||
              templateValues.kind === "erc20Transfer" ||
              templateValues.kind === "uniswapV2SwapExactETHForTokens") && (
              <label className="address-field">
                recipient
                <input
                  className="address-control"
                  value={templateValues.recipient ?? ""}
                  onChange={(event) =>
                    updateTemplate(
                      "recipient",
                      event.target.value as `0x${string}`,
                    )
                  }
                  placeholder="0x..."
                />
              </label>
            )}
            {(templateValues.kind === "erc20Transfer" ||
              templateValues.kind === "erc20Approve") && (
              <label className="address-field">
                Token 預設
                <select
                  className="address-control"
                  value={templateValues.tokenAddress ?? ""}
                  onChange={(event) =>
                    handleTokenPresetChange("tokenAddress", event.target.value)
                  }
                >
                  <option value="">手動輸入</option>
                  {tokenPresets.map((token) => (
                    <option key={token.address} value={token.address}>
                      {token.symbol} ({token.address})
                    </option>
                  ))}
                </select>
              </label>
            )}
            {(templateValues.kind === "erc20Transfer" ||
              templateValues.kind === "erc20Approve") && (
              <label className="address-field">
                Token 合約
                <input
                  className="address-control"
                  value={templateValues.tokenAddress ?? ""}
                  onChange={(event) =>
                    updateTemplate(
                      "tokenAddress",
                      event.target.value as `0x${string}`,
                    )
                  }
                  placeholder="0x..."
                />
              </label>
            )}
            {(templateValues.kind === "erc20Transfer" ||
              templateValues.kind === "erc20Approve") && (
              <label>
                Token decimals
                <input
                  value={templateValues.tokenDecimals ?? ""}
                  onChange={(event) =>
                    updateTemplate("tokenDecimals", event.target.value)
                  }
                  placeholder="6"
                />
              </label>
            )}
            {templateValues.kind === "erc20Approve" && (
              <label className="address-field">
                spender
                <input
                  className="address-control"
                  value={templateValues.spender ?? ""}
                  onChange={(event) =>
                    updateTemplate(
                      "spender",
                      event.target.value as `0x${string}`,
                    )
                  }
                  placeholder="0x..."
                />
              </label>
            )}
            {(templateValues.kind === "nativeTransfer" ||
              templateValues.kind === "erc20Transfer" ||
              templateValues.kind === "erc20Approve" ||
              templateValues.kind === "wethDeposit" ||
              templateValues.kind === "wethWithdraw") && (
              <label>
                數量
                <input
                  value={templateValues.amount ?? ""}
                  onChange={(event) =>
                    updateTemplate("amount", event.target.value)
                  }
                  placeholder="0.01"
                />
              </label>
            )}
            {templateValues.kind === "uniswapV2SwapExactETHForTokens" && (
              <>
                <label className="address-field">
                  Router (SwapRouter02)
                  <input
                    className="address-control"
                    value={
                      templateValues.routerAddress ??
                      getChainConfig(templateValues.chainKey).uniswap
                        .swapRouter02 ??
                      ""
                    }
                    onChange={(event) =>
                      updateTemplate(
                        "routerAddress",
                        event.target.value as `0x${string}`,
                      )
                    }
                    placeholder="0x..."
                  />
                </label>
                <label className="address-field">
                  tokenOut 預設
                  <select
                    className="address-control"
                    value={templateValues.tokenOut ?? ""}
                    onChange={(event) =>
                      handleTokenPresetChange("tokenOut", event.target.value)
                    }
                  >
                    <option value="">手動輸入</option>
                    {tokenPresets.map((token) => (
                      <option key={token.address} value={token.address}>
                        {token.symbol} ({token.address})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="address-field">
                  tokenOut
                  <input
                    className="address-control"
                    value={templateValues.tokenOut ?? ""}
                    onChange={(event) =>
                      updateTemplate(
                        "tokenOut",
                        event.target.value as `0x${string}`,
                      )
                    }
                    placeholder="0x..."
                  />
                </label>
                <label>
                  tokenOut decimals
                  <input
                    value={templateValues.tokenOutDecimals ?? ""}
                    onChange={(event) =>
                      updateTemplate("tokenOutDecimals", event.target.value)
                    }
                    placeholder="6"
                  />
                </label>
                <label>
                  amountIn (ETH)
                  <input
                    value={templateValues.amountIn ?? ""}
                    onChange={(event) =>
                      updateTemplate("amountIn", event.target.value)
                    }
                    placeholder="0.01"
                  />
                </label>
                <label>
                  pool fee
                  <select
                    value={templateValues.feeBps ?? "500"}
                    onChange={(event) =>
                      updateTemplate("feeBps", event.target.value)
                    }
                  >
                    {getChainConfig(
                      templateValues.chainKey,
                    ).uniswap.feeOptions.map((fee) => (
                      <option key={fee} value={String(fee)}>
                        {fee}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  {amountOutMinimumLabel}
                  <input
                    value={templateValues.amountOutMin ?? ""}
                    onChange={(event) => {
                      setIsAutoAmountOutMin(false);
                      updateTemplate("amountOutMin", event.target.value);
                    }}
                    placeholder={selectedTokenOutPreset ? `例如：6.0` : "0"}
                  />
                </label>
                <div className="full-span">
                  <button onClick={handleAutoQuoteAmountOutMinimum}>
                    依鏈上價格自動填入 amountOutMinimum（10% 滑點）
                  </button>
                  <p className="small-text">{quoteStatus}</p>
                </div>
              </>
            )}
            {templateValues.kind === "customCall" && (
              <>
                <label className="address-field">
                  targetAddress
                  <input
                    className="address-control"
                    value={templateValues.targetAddress ?? ""}
                    onChange={(event) =>
                      updateTemplate(
                        "targetAddress",
                        event.target.value as `0x${string}`,
                      )
                    }
                    placeholder="0x..."
                  />
                </label>
                <label>
                  value (ETH)
                  <input
                    value={templateValues.value ?? ""}
                    onChange={(event) =>
                      updateTemplate("value", event.target.value)
                    }
                    placeholder="0"
                  />
                </label>
                <label className="full-span">
                  calldata
                  <textarea
                    value={templateValues.data ?? "0x"}
                    onChange={(event) =>
                      updateTemplate(
                        "data",
                        event.target.value as `0x${string}`,
                      )
                    }
                    placeholder="0x"
                  />
                </label>
              </>
            )}
            <button onClick={handleGenerateTemplate}>建立模板</button>
          </div>

          <div className="card">
            <h3>模板輸出</h3>
            {preparedTx ? (
              <>
                <p className="status-text">{preparedTx.title}</p>
                <p className="small-text">{preparedTx.description}</p>
                <p className="small-text">
                  to: {preparedTx.to ?? "無"}，value:{" "}
                  {formatNativeAmount(preparedTx.value, preparedTx.chainKey)}
                </p>
                {executionPreview ? (
                  <div className="info-box">
                    <strong>執行前參數預估</strong>
                    <p>gas：{executionPreview.gas.toString()}</p>
                    <p>
                      maxFeePerGas：{executionPreview.maxFeePerGas.toString()}
                    </p>
                    <p>
                      maxPriorityFeePerGas：
                      {executionPreview.maxPriorityFeePerGas.toString()}
                    </p>
                  </div>
                ) : (
                  <p className="small-text">
                    尚未取得 gas / fee 預估，畫面先顯示原始模板 draft。
                  </p>
                )}
                <pre>{stringifyWithBigInt(preparedTx.request)}</pre>
                <div className="info-box">
                  <strong>CLI `--input` 一列式 JSON</strong>
                  <textarea
                    className="cli-json-output"
                    readOnly
                    value={cliInputLine}
                  />
                  <div className="copy-row">
                    <button onClick={() => handleCopyCliInput(cliInputLine)}>
                      複製給 CLI 使用
                    </button>
                    <span className="small-text">{templateCopyStatus}</span>
                  </div>
                </div>
              </>
            ) : (
              <p className="small-text">尚未建立模板。</p>
            )}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="step-label">區塊 4</p>
            <h2>raw data 繁中及模擬資訊</h2>
          </div>
        </div>

        <div className="grid-two">
          <div className="card">
            <label className="full-span">
              貼上 tx request JSON 或 signed raw tx
              <textarea
                value={rawInput}
                onChange={(event) => setRawInput(event.target.value)}
                placeholder='{"chainId":11155111,"to":"0x...","data":"0x...","value":"0"}'
              />
            </label>
            <button onClick={handleAnalyzeRawInput}>Decode + Simulate</button>
            <p className="status-text">{analysisStatus}</p>
            <p className="small-text">{aiStatus}</p>
          </div>

          <div className="card">
            <h3>結果摘要</h3>
            {analysis ? (
              <>
                <div className="info-box">
                  <p>{analysis.zhTwSummary}</p>
                </div>
                {analysis.aiSummary ? (
                  <div className="info-box accent-box">
                    <strong>AI 強化說明</strong>
                    <p>{analysis.aiSummary}</p>
                  </div>
                ) : null}
              </>
            ) : (
              <p className="small-text">尚未產生分析結果。</p>
            )}
          </div>
        </div>

        {analysis ? (
          <div className="analysis-grid">
            <div className="card">
              <h3>1. 在哪個網路以及在做什麼</h3>
              <p>{analysis.chainLabel}</p>
              <p>{analysis.action.title}</p>
              <p>{analysis.action.summary}</p>
              <ul>
                {analysis.action.argsSummary.map((item) => (
                  <li key={`${item.label}-${item.value}`}>
                    <strong>{item.label}：</strong>
                    {item.value}
                  </li>
                ))}
              </ul>
            </div>

            <div className="card">
              <h3>2. 潛在風險與合約驗證</h3>
              <p>{analysis.verification.message}</p>
              <p>
                Policy 檢查：
                {analysis.policyViolations.length === 0 ? (
                  "目前載入的 policy 全數通過。"
                ) : (
                  <span className="policy-violation-summary">
                    發現 {analysis.policyViolations.length}{" "}
                    項不符合，已封鎖簽名與廣播。
                  </span>
                )}
              </p>
              {analysis.policyViolations.length > 0 ? (
                <div className="card policy-violation-box">
                  <ul>
                    {analysis.policyViolations.map((item) => (
                      <li
                        key={`${item.policyId}-${item.policyName}`}
                        className="policy-violation-item"
                      >
                        <strong>
                          [{item.level.toUpperCase()}] {item.policyName}
                        </strong>{" "}
                        {item.description}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <ul>
                {analysis.risks
                  .filter((risk) => !risk.title.startsWith("Policy 未通過："))
                  .map((risk) => (
                    <li key={`${risk.level}-${risk.title}`}>
                      <strong>
                        [{risk.level.toUpperCase()}] {risk.title}
                      </strong>{" "}
                      {risk.description}
                    </li>
                  ))}
              </ul>
            </div>

            <div className="card">
              <h3>3. 模擬結果與 token 變化</h3>
              <p>{analysis.simulation.summary}</p>
              {analysis.simulation.gasEstimate ? (
                <p>Gas estimate：{analysis.simulation.gasEstimate}</p>
              ) : null}
              {analysis.simulation.preparedGas ? (
                <p>Prepared gas：{analysis.simulation.preparedGas}</p>
              ) : null}
              {analysis.simulation.preparedMaxFeePerGas ? (
                <p>
                  Prepared maxFeePerGas：
                  {analysis.simulation.preparedMaxFeePerGas}
                </p>
              ) : null}
              {analysis.simulation.preparedMaxPriorityFeePerGas ? (
                <p>
                  Prepared maxPriorityFeePerGas：
                  {analysis.simulation.preparedMaxPriorityFeePerGas}
                </p>
              ) : null}
              {analysis.simulation.resultPreview ? (
                <p>Result preview：{analysis.simulation.resultPreview}</p>
              ) : null}
              {analysis.simulation.simulationUrl ? (
                <p>
                  Tenderly Dashboard 連結：
                  <a
                    href={analysis.simulation.simulationUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    開啟模擬詳情
                  </a>
                </p>
              ) : null}
              {analysis.simulation.publicSimulationUrl ? (
                <p>
                  Tenderly 公開分享連結：
                  <a
                    href={analysis.simulation.publicSimulationUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    開啟公開模擬頁
                  </a>
                </p>
              ) : null}
              {analysis.simulation.publicSimulationMessage ? (
                <p className="small-text">
                  {analysis.simulation.publicSimulationMessage}
                </p>
              ) : null}
              <ul>
                {analysis.simulation.tokenChanges.length === 0 ? (
                  <li>目前沒有推估到明確 token 變化。</li>
                ) : (
                  analysis.simulation.tokenChanges.map((item, index) => (
                    <li key={`${item.address}-${item.note}-${index}`}>
                      <strong>{shortenAddress(item.address)}</strong>{" "}
                      {item.note}
                      {item.amount ? `，amount=${item.amount}` : ""}
                      {item.tokenAddress ? `，token=${item.tokenAddress}` : ""}
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="step-label">區塊 5</p>
            <h2>若按下確認，顯示上鏈後 tx 資訊及 explorer 連結</h2>
          </div>
        </div>

        <div className="grid-two">
          <div className="card">
            <h3>TokenCore 路徑</h3>
            <label>
              簽名密碼
              <input
                type="password"
                value={tokenCoreSignPassword}
                onChange={(event) =>
                  setTokenCoreSignPassword(event.target.value)
                }
                placeholder="用建立錢包時的密碼"
              />
            </label>
            <button onClick={handleTokenCoreSign}>先簽名</button>
            <button onClick={handleTokenCoreBroadcast}>再廣播</button>
            <p className="small-text">signed raw tx：</p>
            <pre>{tokenCoreSignedRaw || "尚未簽名"}</pre>
            <p className="small-text">
              預估 tx hash：{tokenCoreSignedHash || "尚未簽名"}
            </p>
          </div>
        </div>

        <div className="card">
          <h3>上鏈結果</h3>
          <p className="status-text">{sendStatus}</p>
          {sentHash && preparedTx ? (
            <>
              <a
                href={getExplorerTxUrl(preparedTx.chainKey, sentHash)}
                target="_blank"
                rel="noreferrer"
                style={{ display: "block" }}
              >
                前往 Explorer 檢視：{sentHash}
              </a>
              <a
                href={`https://dashboard.tenderly.co/tx/${sentHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ display: "block" }}
              >
                前往 Tenderly 檢視：{sentHash}
              </a>
            </>
          ) : null}
        </div>
      </section>
    </main>
  );
}

export default App;
