import type { Address } from "viem";
import { formatEther, formatUnits, isAddress } from "viem";

import { getChainConfig } from "./chains";
import type { ContractVerificationStatus, DemoChainKey } from "./types";

export function shortenAddress(address?: string) {
  if (!address) return "未提供";
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function safeAddress(value?: string): Address | undefined {
  if (!value) return undefined;
  return isAddress(value) ? (value as Address) : undefined;
}

export function formatNativeAmount(
  value: bigint | undefined,
  chainKey: DemoChainKey,
) {
  if (value === undefined) return "0";
  return `${trimNumber(formatEther(value))} ${getChainConfig(chainKey).nativeSymbol}`;
}

export function formatTokenAmount(
  value: bigint | undefined,
  decimals = 18,
  symbol?: string,
) {
  if (value === undefined) return "0";
  const label = trimNumber(formatUnits(value, decimals));
  return symbol ? `${label} ${symbol}` : label;
}

export function trimNumber(value: string) {
  if (!value.includes(".")) return value;
  return value.replace(/\.?0+$/, "");
}

export function formatDateTime(value: string) {
  return new Date(value).toLocaleString("zh-TW", {
    hour12: false,
  });
}

export function formatUnknown(value: unknown): string {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return value;
  if (Array.isArray(value))
    return value.map((item) => formatUnknown(item)).join(", ");
  if (value && typeof value === "object") {
    return JSON.stringify(
      value,
      (_key, currentValue) =>
        typeof currentValue === "bigint"
          ? currentValue.toString()
          : currentValue,
      2,
    );
  }
  return String(value);
}

export function formatVerificationSource(
  source: ContractVerificationStatus["source"],
) {
  switch (source) {
    case "etherscan":
      return "Etherscan Explorer API";
    case "sourcify":
      return "Sourcify";
    case "local":
      return "內建合約資料";
    default:
      return "未知來源";
  }
}

export function downloadTextFile(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
