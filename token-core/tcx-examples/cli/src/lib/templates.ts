import {
  encodeFunctionData,
  parseEther,
  parseUnits,
  type Address,
  type Hex,
} from "viem";

import { erc20Abi, uniswapV3SwapRouterAbi, wethAbi } from "./abis";
import { getChainConfig } from "./chains";
import { safeAddress } from "./format";
import type {
  PreparedTx,
  TemplateFormValues,
  TemplateKind,
  TxRequestDraft,
} from "./types";

function stringifyWithBigInt(value: unknown) {
  return JSON.stringify(
    value,
    (_key, currentValue) =>
      typeof currentValue === "bigint" ? currentValue.toString() : currentValue,
    2,
  );
}

function buildDraft(
  values: TemplateFormValues,
  title: string,
  description: string,
  draft: TxRequestDraft,
): PreparedTx {
  return {
    chainKey: values.chainKey,
    chainId: getChainConfig(values.chainKey).chainId,
    templateKind: values.kind,
    title,
    description,
    to: draft.to,
    data: draft.data,
    value: draft.value,
    from: draft.account,
    request: draft,
    rawInput: stringifyWithBigInt(draft),
  };
}

function ensureAddress(value: Address | undefined, label: string) {
  if (!value) throw new Error(`請提供有效的 ${label} 地址。`);
  return value;
}

function ensureAmount(value: string | undefined, fallback = "0") {
  return parseEther(value && value.trim().length > 0 ? value : fallback);
}

function ensureTokenAmount(
  value: string | undefined,
  decimals: string | undefined,
  fallback = "0",
) {
  const parsedDecimals = Number.parseInt(decimals || "18", 10);
  return parseUnits(
    value && value.trim().length > 0 ? value : fallback,
    Number.isFinite(parsedDecimals) ? parsedDecimals : 18,
  );
}

export const templateOptions: Array<{ value: TemplateKind; label: string }> = [
  { value: "nativeTransfer", label: "原生 ETH 轉帳" },
  { value: "erc20Transfer", label: "ERC-20 transfer" },
  { value: "erc20Approve", label: "ERC-20 approve" },
  { value: "wethDeposit", label: "WETH deposit / wrap ETH" },
  { value: "wethWithdraw", label: "WETH withdraw / unwrap ETH" },
  {
    value: "uniswapV2SwapExactETHForTokens",
    label: "Uniswap V3 ETH -> Token exactInputSingle",
  },
  { value: "customCall", label: "自訂合約呼叫" },
];

export function createTemplateTransaction(
  values: TemplateFormValues,
): PreparedTx {
  const chain = getChainConfig(values.chainKey);
  const from = safeAddress(values.from);

  switch (values.kind) {
    case "nativeTransfer": {
      const to = ensureAddress(
        safeAddress(values.recipient ?? values.to),
        "收款",
      );
      const value = ensureAmount(values.amount);
      return buildDraft(
        values,
        "原生 ETH 轉帳",
        "把測試網 ETH 直接轉給另一個地址。",
        {
          chainId: chain.chainId,
          account: from,
          to,
          value,
        },
      );
    }
    case "erc20Transfer": {
      const tokenAddress = ensureAddress(
        safeAddress(values.tokenAddress),
        "Token 合約",
      );
      const recipient = ensureAddress(safeAddress(values.recipient), "接收人");
      const amount = ensureTokenAmount(values.amount, values.tokenDecimals);
      return buildDraft(
        values,
        "ERC-20 transfer",
        "呼叫 token 合約的 transfer 函式。",
        {
          chainId: chain.chainId,
          account: from,
          to: tokenAddress,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: "transfer",
            args: [recipient, amount],
          }),
          value: 0n,
        },
      );
    }
    case "erc20Approve": {
      const tokenAddress = ensureAddress(
        safeAddress(values.tokenAddress),
        "Token 合約",
      );
      const spender = ensureAddress(safeAddress(values.spender), "spender");
      const amount = ensureTokenAmount(values.amount, values.tokenDecimals);
      return buildDraft(
        values,
        "ERC-20 approve",
        "授權 spender 在未來可動用指定數量的 token。",
        {
          chainId: chain.chainId,
          account: from,
          to: tokenAddress,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: "approve",
            args: [spender, amount],
          }),
          value: 0n,
        },
      );
    }
    case "wethDeposit": {
      const amount = ensureAmount(values.amount);
      return buildDraft(values, "Wrap ETH", "把 ETH 包裝成 WETH。", {
        chainId: chain.chainId,
        account: from,
        to: chain.wrappedNativeToken.address,
        data: encodeFunctionData({
          abi: wethAbi,
          functionName: "deposit",
        }),
        value: amount,
      });
    }
    case "wethWithdraw": {
      const amount = ensureAmount(values.amount);
      return buildDraft(values, "Unwrap WETH", "把 WETH 解包回 ETH。", {
        chainId: chain.chainId,
        account: from,
        to: chain.wrappedNativeToken.address,
        data: encodeFunctionData({
          abi: wethAbi,
          functionName: "withdraw",
          args: [amount],
        }),
        value: 0n,
      });
    }
    case "uniswapV2SwapExactETHForTokens": {
      const routerAddress = ensureAddress(
        safeAddress(values.routerAddress ?? chain.uniswap.swapRouter02),
        "Uniswap Router",
      );
      const recipient = ensureAddress(
        safeAddress(values.recipient ?? from),
        "接收人",
      );
      const tokenOut = ensureAddress(
        safeAddress(values.tokenOut),
        "目標 Token",
      );
      const amountIn = ensureAmount(values.amountIn ?? values.amount);
      return buildDraft(
        values,
        "Uniswap V3 ETH -> Token 交換",
        "使用 SwapRouter02 的 exactInputSingle，把 ETH 換成指定 token。",
        {
          chainId: chain.chainId,
          account: from,
          to: routerAddress,
          data: encodeFunctionData({
            abi: uniswapV3SwapRouterAbi,
            functionName: "exactInputSingle",
            args: [
              {
                tokenIn: chain.wrappedNativeToken.address,
                tokenOut,
                fee: Number.parseInt(values.feeBps || "500", 10),
                recipient,
                amountIn,
                amountOutMinimum: ensureTokenAmount(
                  values.amountOutMin,
                  values.tokenOutDecimals,
                  "0",
                ),
                sqrtPriceLimitX96: 0n,
              },
            ],
          }),
          value: amountIn,
        },
      );
    }
    case "customCall": {
      const targetAddress = ensureAddress(
        safeAddress(values.targetAddress),
        "目標合約",
      );
      const data = (values.data?.trim() || "0x") as Hex;
      const value = values.value ? ensureAmount(values.value) : 0n;

      return buildDraft(
        values,
        "自訂合約呼叫",
        "直接指定 target / data / value 的自訂交易。",
        {
          chainId: chain.chainId,
          account: from,
          to: targetAddress,
          data,
          value,
        },
      );
    }
    default: {
      throw new Error("不支援的模板類型。");
    }
  }
}
