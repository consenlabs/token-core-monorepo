import { createPublicClient, http, type Address } from "viem";

import { getChainConfig } from "./chains";
import { getRuntimeEnv } from "./env";
import { safeAddress } from "./format";
import { retry, withTimeout } from "./resilience";
import type {
  DecodedAction,
  DemoChainKey,
  ExecutionPreview,
  ParsedInput,
  SimulationSummary,
  TokenChange,
} from "./types";

function toHex(value: bigint | number) {
  return `0x${value.toString(16)}`;
}

function buildHeuristicTokenChanges(
  parsed: ParsedInput,
  action: DecodedAction,
): TokenChange[] {
  const from = parsed.from;
  const to = parsed.to;
  const changes: TokenChange[] = [];

  if (
    action.kind === "nativeTransfer" &&
    from &&
    to &&
    parsed.value !== undefined
  ) {
    changes.push({
      address: from,
      tokenSymbol: "ETH",
      direction: "out",
      amount: parsed.value.toString(),
      note: "送出原生幣",
    });
    changes.push({
      address: to,
      tokenSymbol: "ETH",
      direction: "in",
      amount: parsed.value.toString(),
      note: "收到原生幣",
    });
    return changes;
  }

  if (action.functionName === "transfer" && from) {
    const recipient = safeAddress(action.argsSummary[0]?.value);
    const amount = action.argsSummary[1]?.value;
    changes.push({
      address: from,
      tokenSymbol: "ERC-20",
      tokenAddress: to,
      direction: "out",
      amount,
      note: "預期 token 轉出",
    });
    if (recipient) {
      changes.push({
        address: recipient,
        tokenSymbol: "ERC-20",
        tokenAddress: to,
        direction: "in",
        amount,
        note: "預期 token 轉入",
      });
    }
  }

  if (action.functionName === "approve" && from) {
    const spender = safeAddress(action.argsSummary[0]?.value);
    changes.push({
      address: from,
      tokenSymbol: "ERC-20",
      tokenAddress: to,
      direction: "approve",
      amount: action.argsSummary[1]?.value,
      note: spender ? `授權給 ${spender}` : "調整授權額度",
    });
  }

  if (action.functionName === "deposit" && from && parsed.value !== undefined) {
    changes.push({
      address: from,
      tokenSymbol: "ETH",
      direction: "out",
      amount: parsed.value.toString(),
      note: "預期轉成 WETH",
    });
    changes.push({
      address: from,
      tokenSymbol: "WETH",
      tokenAddress: to,
      direction: "in",
      amount: parsed.value.toString(),
      note: "預期收到 WETH",
    });
  }

  if (action.functionName === "withdraw" && from) {
    const amount = action.argsSummary[0]?.value;
    changes.push({
      address: from,
      tokenSymbol: "WETH",
      tokenAddress: to,
      direction: "out",
      amount,
      note: "預期銷毀 WETH",
    });
    changes.push({
      address: from,
      tokenSymbol: "ETH",
      direction: "in",
      amount,
      note: "預期領回 ETH",
    });
  }

  if (
    (action.functionName?.includes("swap") ||
      action.functionName === "exactInputSingle") &&
    from
  ) {
    changes.push({
      address: from,
      tokenSymbol: "ETH / Token",
      direction: "unknown",
      amount: undefined,
      note: "交換交易的最終資產變化建議優先參考 Tenderly 模擬。",
    });
  }

  return changes;
}

export async function estimateExecutionPreview(
  chainKey: DemoChainKey,
  parsed: Pick<ParsedInput, "from" | "to" | "data" | "value" | "gas">,
): Promise<ExecutionPreview> {
  const chain = getChainConfig(chainKey);
  const client = createPublicClient({
    chain: chain.chain,
    transport: http(chain.rpcUrl),
  });

  const [latestBlock, feeEstimate] = await Promise.all([
    client.getBlock({ blockTag: "latest" }),
    client.estimateFeesPerGas().catch(() => undefined),
  ]);

  const maxPriorityFeePerGas =
    feeEstimate?.maxPriorityFeePerGas ?? 1_500_000_000n;
  const maxFeePerGas =
    feeEstimate?.maxFeePerGas ??
    (latestBlock.baseFeePerGas
      ? latestBlock.baseFeePerGas * 2n + maxPriorityFeePerGas
      : maxPriorityFeePerGas * 2n);

  let gas = parsed.gas;
  if (gas === undefined && parsed.from && parsed.to) {
    try {
      gas = await client.estimateGas({
        account: parsed.from,
        to: parsed.to,
        data: parsed.data,
        value: parsed.value,
      });
    } catch {
      gas = 250000n;
    }
  }

  return {
    gas: gas ?? 250000n,
    maxFeePerGas,
    maxPriorityFeePerGas,
  };
}

function getTenderlyPublicShareConfig() {
  const tenderlyApiAccessKey = getRuntimeEnv("VITE_TENDERLY_ACCESS_TOKEN");
  const tenderlyAccountSlug = getRuntimeEnv("VITE_TENDERLY_ACCOUNT_SLUG");
  const tenderlyProjectSlug = getRuntimeEnv("VITE_TENDERLY_PROJECT_SLUG");
  if (!tenderlyApiAccessKey || !tenderlyAccountSlug || !tenderlyProjectSlug) {
    return null;
  }

  return {
    accessKey: tenderlyApiAccessKey,
    accountSlug: tenderlyAccountSlug,
    projectSlug: tenderlyProjectSlug,
  };
}

interface TenderlyRestConfig {
  accessKey: string;
  accountSlug: string;
  projectSlug: string;
}

async function fetchWithRetryAndTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
) {
  return retry(
    () =>
      withTimeout(() => fetch(url, init), timeoutMs, `網路請求逾時：${url}`),
    {
      retries: 1,
      delayMs: 500,
      shouldRetry: (error) =>
        error.message.includes("逾時") || error.message.includes("fetch"),
    },
  );
}

// ── REST API simulation (preferred) ─────────────────────────────────────────
// Calls Tenderly /simulate REST API with save=true / save_if_fails=true.
// This is the primary simulation path: creates a persisted simulation record
// so we always have a Dashboard URL even for failing transactions, eliminating
// the previous dual-call architecture where the RPC result had no associated URL.
//
// HTTP 400 retry strategy:
// Tenderly rejects requests with HTTP 400 *before* running the simulation when
// the sender has insufficient ETH (pre-validation). In that case we retry once
// with a `state_objects` balance override (10,000 ETH) so the simulation actually
// executes and gets persisted — giving us a URL to inspect the execution trace.
// When a balance override was used, `success` is forced to `false` (the
// transaction still can't be sent on-chain) and `errorMessage` preserves the
// original rejection reason.
async function simulateWithTenderlyRestApi(
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  feeParams: ExecutionPreview,
  fallbackChanges: TokenChange[],
  config: TenderlyRestConfig,
): Promise<SimulationSummary> {
  const simulateUrl = `https://api.tenderly.co/api/v1/account/${config.accountSlug}/project/${config.projectSlug}/simulate`;
  const baseHeaders = {
    "Content-Type": "application/json",
    "X-Access-Key": config.accessKey,
  };

  const buildBody = (overrideBalance = false) =>
    JSON.stringify({
      network_id: String(getChainConfig(chainKey).chainId),
      from: parsed.from,
      to: parsed.to,
      input: parsed.data ?? "0x",
      gas: Number(feeParams.gas),
      value: (parsed.value ?? 0n).toString(),
      save: true,
      save_if_fails: true,
      simulation_type: "full",
      ...(overrideBalance && parsed.from
        ? {
            state_objects: {
              // 10,000 ETH — ensures simulation runs even when on-chain balance is low
              [parsed.from]: { balance: "0x21E19E0C9BAB2400000" },
            },
          }
        : {}),
    });

  let simulateResponse = await fetchWithRetryAndTimeout(
    simulateUrl,
    { method: "POST", headers: baseHeaders, body: buildBody(false) },
    12000,
  );

  let balanceOverrideUsed = false;
  let firstAttemptError = "";

  if (!simulateResponse.ok) {
    // Capture first-attempt error before consuming the response body.
    try {
      const errBody = (await simulateResponse.json()) as {
        error?: { message?: string };
      };
      firstAttemptError =
        errBody.error?.message ??
        `HTTP ${simulateResponse.status} ${simulateResponse.statusText}`;
    } catch {
      firstAttemptError = `HTTP ${simulateResponse.status} ${simulateResponse.statusText}`;
    }

    // Retry with balance override so the simulation is saved and URL is available.
    const retryResp = await fetchWithRetryAndTimeout(
      simulateUrl,
      { method: "POST", headers: baseHeaders, body: buildBody(true) },
      12000,
    ).catch(() => null);

    if (retryResp?.ok) {
      simulateResponse = retryResp;
      balanceOverrideUsed = true;
    }
  }

  if (!simulateResponse.ok) {
    let errorDetail = firstAttemptError ? `：${firstAttemptError}` : "";
    if (!firstAttemptError) {
      try {
        const errBody = (await simulateResponse.json()) as {
          error?: { message?: string };
        };
        errorDetail = errBody.error?.message
          ? `：${errBody.error.message}`
          : "";
      } catch {
        /* ignore */
      }
    }
    return {
      success: false,
      source: "tenderly",
      summary: `Tenderly 模擬 API 呼叫失敗（HTTP ${simulateResponse.status}${errorDetail}）。`,
      errorMessage: `HTTP ${simulateResponse.status} ${simulateResponse.statusText}${errorDetail}`,
      preparedGas: feeParams.gas.toString(),
      preparedMaxFeePerGas: feeParams.maxFeePerGas.toString(),
      preparedMaxPriorityFeePerGas: feeParams.maxPriorityFeePerGas.toString(),
      tokenChanges: fallbackChanges,
    };
  }

  const payload = (await simulateResponse.json()) as {
    simulation?: { id?: string };
    transaction?: {
      status?: boolean;
      gas_used?: number;
      error_message?: string;
      error_info?: { error_message?: string };
    };
    error?: { message?: string };
  };

  const simulationId = payload.simulation?.id;
  // When balance was overridden to allow the simulation to run, always treat
  // the result as failure: the tx cannot actually be sent on-chain.
  const rawSuccess = payload.transaction?.status !== false;
  const success = balanceOverrideUsed ? false : rawSuccess;
  const gasUsed = payload.transaction?.gas_used;
  const txErrorMessage =
    payload.transaction?.error_message ??
    payload.transaction?.error_info?.error_message ??
    payload.error?.message;
  const errorMessage = balanceOverrideUsed
    ? firstAttemptError || txErrorMessage
    : txErrorMessage;

  let simulationUrl: string | undefined;
  let publicSimulationUrl: string | undefined;
  let publicSimulationMessage: string | undefined;

  if (!simulationId) {
    publicSimulationMessage =
      errorMessage ?? "Tenderly Simulation API 未回傳 simulation id。";
  } else {
    simulationUrl = `https://dashboard.tenderly.co/${config.accountSlug}/${config.projectSlug}/simulator/${simulationId}`;

    const shareResponse = await fetchWithRetryAndTimeout(
      `https://api.tenderly.co/api/v1/account/${config.accountSlug}/project/${config.projectSlug}/simulations/${simulationId}/share`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Access-Key": config.accessKey,
        },
      },
      10000,
    ).catch(() => null);

    if (shareResponse?.ok) {
      publicSimulationUrl = `https://tdly.co/shared/simulation/${simulationId}`;
    } else {
      publicSimulationMessage = shareResponse
        ? `Tenderly 模擬已儲存，但公開分享失敗：HTTP ${shareResponse.status} ${shareResponse.statusText}`
        : "Tenderly 公開分享請求失敗。";
    }
  }

  return {
    success,
    source: "tenderly",
    summary: balanceOverrideUsed
      ? "Tenderly 模擬顯示交易可能失敗（原始請求因餘額不足被拒，模擬時已覆蓋帳戶餘額以生成檢視連結）。"
      : success
        ? "Tenderly 模擬顯示交易可執行。"
        : "Tenderly 模擬顯示交易可能失敗。",
    gasEstimate: gasUsed !== undefined ? String(gasUsed) : undefined,
    preparedGas: feeParams.gas.toString(),
    preparedMaxFeePerGas: feeParams.maxFeePerGas.toString(),
    preparedMaxPriorityFeePerGas: feeParams.maxPriorityFeePerGas.toString(),
    errorMessage,
    simulationUrl,
    publicSimulationUrl,
    publicSimulationMessage,
    tokenChanges: fallbackChanges,
    raw: payload,
  };
}

// ── Node RPC simulation (fallback) ───────────────────────────────────────────
// Used when REST API credentials (VITE_TENDERLY_ACCESS_TOKEN etc.) are absent
// but VITE_TENDERLY_NODE_ACCESS_KEY is set. Provides simulation data without
// persisted record — no Dashboard URL is generated.
async function simulateWithTenderlyRpc(
  parsed: ParsedInput,
  feeParams: ExecutionPreview,
  fallbackChanges: TokenChange[],
  rpcUrl: string,
): Promise<SimulationSummary> {
  const response = await fetchWithRetryAndTimeout(
    rpcUrl,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "tenderly_simulateTransaction",
        params: [
          {
            from: parsed.from,
            to: parsed.to,
            gas: toHex(feeParams.gas),
            value: toHex(parsed.value ?? 0n),
            input: parsed.data ?? "0x",
            maxFeePerGas: toHex(feeParams.maxFeePerGas),
            maxPriorityFeePerGas: toHex(feeParams.maxPriorityFeePerGas),
          },
          "latest",
        ],
      }),
    },
    12000,
  );

  if (!response.ok) {
    return {
      success: false,
      source: "tenderly",
      summary: "Tenderly RPC 呼叫失敗。",
      errorMessage: `HTTP ${response.status} ${response.statusText}`,
      tokenChanges: fallbackChanges,
    };
  }

  const payload = (await response.json()) as {
    result?: {
      status?: boolean;
      gasUsed?: string;
      error_message?: string;
      assetChanges?: Array<{
        type?: string;
        amount?: string;
        symbol?: string;
        dollar_value?: string;
        from?: string;
        to?: string;
        contract_address?: string;
      }>;
    };
    error?: { message?: string };
  };

  if (!payload.result) {
    return {
      success: false,
      source: "tenderly",
      summary: "Tenderly 模擬失敗。",
      errorMessage: payload.error?.message ?? "Tenderly 未回傳結果。",
      preparedGas: feeParams.gas.toString(),
      preparedMaxFeePerGas: feeParams.maxFeePerGas.toString(),
      preparedMaxPriorityFeePerGas: feeParams.maxPriorityFeePerGas.toString(),
      tokenChanges: fallbackChanges,
      raw: payload,
    };
  }

  const success = payload.result.status !== false;
  const assetChanges =
    payload.result.assetChanges?.map((item) => ({
      address: (safeAddress(item.to) ??
        safeAddress(item.from) ??
        parsed.from) as Address,
      tokenSymbol: item.symbol || "UNKNOWN",
      tokenAddress: safeAddress(item.contract_address),
      direction:
        item.type === "approve" ? ("approve" as const) : ("unknown" as const),
      amount: item.amount,
      note: item.dollar_value
        ? `Tenderly 估計價值約 ${item.dollar_value} USD`
        : "Tenderly 資產變化",
    })) ?? fallbackChanges;

  return {
    success,
    source: "tenderly",
    summary: !success
      ? "Tenderly 模擬顯示交易可能失敗。"
      : "Tenderly 模擬顯示交易可執行。",
    gasEstimate: payload.result.gasUsed
      ? String(parseInt(payload.result.gasUsed, 16))
      : undefined,
    preparedGas: feeParams.gas.toString(),
    preparedMaxFeePerGas: feeParams.maxFeePerGas.toString(),
    preparedMaxPriorityFeePerGas: feeParams.maxPriorityFeePerGas.toString(),
    errorMessage: payload.result.error_message,
    tokenChanges: assetChanges,
    raw: payload.result,
  };
}

// ── Orchestrator ─────────────────────────────────────────────────────────────
// Priority 1: REST API simulation (VITE_TENDERLY_ACCESS_TOKEN + ACCOUNT_SLUG + PROJECT_SLUG)
//   → persisted simulation → always has Dashboard URL, even for reverts
// Priority 2: Node RPC simulation (VITE_TENDERLY_NODE_ACCESS_KEY)
//   → transient simulation → no URL, but provides simulation data
// Priority 3: return null → caller falls back to simulateWithRpc (Alchemy/public RPC)
async function simulateWithTenderly(
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  fallbackChanges: TokenChange[],
): Promise<SimulationSummary | null> {
  if (!parsed.from || !parsed.to) return null;

  const feeParams = await estimateExecutionPreview(chainKey, parsed);

  const restConfig = getTenderlyPublicShareConfig();
  if (restConfig) {
    return simulateWithTenderlyRestApi(
      chainKey,
      parsed,
      feeParams,
      fallbackChanges,
      restConfig,
    );
  }

  const rpcUrl = getChainConfig(chainKey).tenderlyRpcUrl;
  if (!rpcUrl) {
    return {
      success: false,
      source: "heuristic",
      summary:
        "未啟用 Tenderly 模擬。若您剛更新 .env，請重新啟動 Vite dev server 後再試一次。",
      errorMessage:
        "找不到 Tenderly 設定。請設定 VITE_TENDERLY_ACCESS_TOKEN、VITE_TENDERLY_ACCOUNT_SLUG、VITE_TENDERLY_PROJECT_SLUG（REST API），或 VITE_TENDERLY_NODE_ACCESS_KEY（Node RPC）。",
      tokenChanges: fallbackChanges,
    };
  }

  return simulateWithTenderlyRpc(parsed, feeParams, fallbackChanges, rpcUrl);
}

async function simulateWithRpc(
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  action: DecodedAction,
): Promise<SimulationSummary> {
  const chain = getChainConfig(chainKey);
  const client = createPublicClient({
    chain: chain.chain,
    transport: http(chain.rpcUrl),
  });
  const tokenChanges = buildHeuristicTokenChanges(parsed, action);

  try {
    const gasEstimate = await client.estimateGas({
      account: parsed.from,
      to: parsed.to,
      data: parsed.data,
      value: parsed.value,
    });

    let resultPreview = "此交易沒有回傳資料。";
    if (parsed.to && parsed.data) {
      const callResult = await client.call({
        account: parsed.from,
        to: parsed.to,
        data: parsed.data,
        value: parsed.value,
      });
      if (callResult.data && callResult.data !== "0x") {
        resultPreview = callResult.data;
      }
    }

    return {
      success: true,
      source: "rpc",
      summary: "以標準 RPC 進行模擬，未發現立即 revert。",
      gasEstimate: gasEstimate.toString(),
      resultPreview,
      tokenChanges,
    };
  } catch (error) {
    return {
      success: false,
      source: "heuristic",
      summary: "RPC 模擬失敗，退回規則型推估。",
      errorMessage: error instanceof Error ? error.message : "未知錯誤",
      tokenChanges,
    };
  }
}

export async function simulateTransaction(
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  action: DecodedAction,
): Promise<SimulationSummary> {
  const fallbackChanges = buildHeuristicTokenChanges(parsed, action);

  let tenderlyFailure: SimulationSummary | undefined;

  try {
    const tenderly = await simulateWithTenderly(
      chainKey,
      parsed,
      fallbackChanges,
    );
    if (tenderly?.source === "tenderly") return tenderly;
    if (tenderly) tenderlyFailure = tenderly;
  } catch (error) {
    tenderlyFailure = {
      success: false,
      source: "heuristic",
      summary: "Tenderly 模擬初始化失敗，已退回 RPC 模擬。",
      errorMessage: error instanceof Error ? error.message : "未知錯誤",
      tokenChanges: fallbackChanges,
    };
  }

  const rpcResult = await simulateWithRpc(chainKey, parsed, action);
  if (!tenderlyFailure) return rpcResult;

  return {
    ...rpcResult,
    summary: `${tenderlyFailure.summary} 目前顯示的是 ${rpcResult.source} fallback 結果。`,
    errorMessage: tenderlyFailure.errorMessage ?? rpcResult.errorMessage,
  };
}
