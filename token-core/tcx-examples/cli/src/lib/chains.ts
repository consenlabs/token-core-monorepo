import type { Chain } from "viem";
import { baseSepolia, sepolia } from "viem/chains";

import { getRuntimeEnv } from "./env";
import type { DemoChainKey, TokenPreset } from "./types";

interface ChainConfig {
  key: DemoChainKey;
  chainLabelKey: "eth-sepolia" | "base-sepolia";
  label: string;
  chainId: number;
  chain: Chain;
  explorerBaseUrl: string;
  explorerName: string;
  rpcUrl: string;
  nativeSymbol: string;
  wrappedNativeToken: {
    symbol: string;
    address: `0x${string}`;
    decimals: number;
  };
  uniswap: {
    v3Factory?: `0x${string}`;
    swapRouter02?: `0x${string}`;
    universalRouter?: `0x${string}`;
    quoterV2?: `0x${string}`;
    feeOptions: readonly number[];
  };
  tenderlyRpcUrl?: string;
  tokenPresets: readonly TokenPreset[];
}

const DEMO_CHAIN_ALIASES: Record<string, DemoChainKey> = {
  sepolia: "sepolia",
  "eth-sepolia": "sepolia",
  baseSepolia: "baseSepolia",
  "base-sepolia": "baseSepolia",
};

function buildAlchemyRpcUrl(networkSlug: "eth-sepolia" | "base-sepolia") {
  const alchemyApiKey = getRuntimeEnv("VITE_ALCHEMY_API_KEY");
  if (!alchemyApiKey) return undefined;
  return `https://${networkSlug}.g.alchemy.com/v2/${alchemyApiKey}`;
}

function buildChainConfigs(): Record<DemoChainKey, ChainConfig> {
  const tenderlyAccessKey = getRuntimeEnv("VITE_TENDERLY_NODE_ACCESS_KEY");

  return {
    sepolia: {
      key: "sepolia",
      chainLabelKey: "eth-sepolia",
      label: "Ethereum Sepolia",
      chainId: sepolia.id,
      chain: sepolia,
      explorerBaseUrl: "https://sepolia.etherscan.io",
      explorerName: "Sepolia Etherscan",
      rpcUrl:
        buildAlchemyRpcUrl("eth-sepolia") ?? sepolia.rpcUrls.default.http[0],
      nativeSymbol: "ETH",
      wrappedNativeToken: {
        symbol: "WETH",
        address: "0xfff9976782d46cc05630d1f6ebab18b2324d6b14",
        decimals: 18,
      },
      uniswap: {
        v3Factory: "0x0227628f3F023bb0B980b67D528571c95c6DaC1c",
        swapRouter02: "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E",
        universalRouter: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
        quoterV2: "0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3",
        feeOptions: [100, 500, 3000, 10000] as const,
      },
      tenderlyRpcUrl: tenderlyAccessKey
        ? `https://sepolia.gateway.tenderly.co/${tenderlyAccessKey}`
        : undefined,
      tokenPresets: [
        {
          symbol: "USDC",
          address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
          decimals: 6,
        },
        {
          symbol: "EURC",
          address: "0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4",
          decimals: 6,
        },
      ],
    },
    baseSepolia: {
      key: "baseSepolia",
      chainLabelKey: "base-sepolia",
      label: "Base Sepolia",
      chainId: baseSepolia.id,
      chain: baseSepolia,
      explorerBaseUrl: "https://sepolia.basescan.org",
      explorerName: "BaseScan",
      rpcUrl:
        buildAlchemyRpcUrl("base-sepolia") ??
        baseSepolia.rpcUrls.default.http[0],
      nativeSymbol: "ETH",
      wrappedNativeToken: {
        symbol: "WETH",
        address: "0x4200000000000000000000000000000000000006",
        decimals: 18,
      },
      uniswap: {
        v3Factory: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
        swapRouter02: "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4",
        universalRouter: "0x050E797f3625EC8785265e1d9BDd4799b97528A1",
        feeOptions: [100, 500, 3000, 10000] as const,
      },
      tenderlyRpcUrl: tenderlyAccessKey
        ? `https://base-sepolia.gateway.tenderly.co/${tenderlyAccessKey}`
        : undefined,
      tokenPresets: [
        {
          symbol: "USDC",
          address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          decimals: 6,
        },
        {
          symbol: "EURC",
          address: "0x808456652fdb597867f38412077A9182bf77359F",
          decimals: 6,
        },
      ],
    },
  };
}

export function getChainConfigs() {
  return buildChainConfigs();
}

export function getChainConfig(chainKey: DemoChainKey) {
  return getChainConfigs()[chainKey];
}

export function parseDemoChainKey(value?: string): DemoChainKey | undefined {
  if (!value) return undefined;
  return DEMO_CHAIN_ALIASES[value];
}

export function getChainKeyByLabelKey(
  labelKey: string,
): DemoChainKey | undefined {
  return parseDemoChainKey(labelKey);
}

export function getChainKeyById(
  chainId: number | undefined,
): DemoChainKey | undefined {
  if (!chainId) return undefined;
  return (Object.values(getChainConfigs()).find(
    (item) => item.chainId === chainId,
  )?.key ?? undefined) as DemoChainKey | undefined;
}

export function getExplorerTxUrl(chainKey: DemoChainKey, hash: string) {
  return `${getChainConfig(chainKey).explorerBaseUrl}/tx/${hash}`;
}

export function getExplorerAddressUrl(chainKey: DemoChainKey, address: string) {
  return `${getChainConfig(chainKey).explorerBaseUrl}/address/${address}`;
}

export function getTokenPresets(chainKey: DemoChainKey) {
  return getChainConfig(chainKey).tokenPresets;
}

export function getSupportedChainLabelKeys() {
  return Object.values(getChainConfigs()).map((chain) => chain.chainLabelKey);
}

export function resolveTargetChainKey(params: {
  explicitChainKey?: DemoChainKey;
  parsedChainId?: number;
  walletChainId?: number;
}): DemoChainKey {
  const walletChainKey = getChainKeyById(params.walletChainId);
  const parsedChainKey = getChainKeyById(params.parsedChainId);

  const chainKey =
    params.explicitChainKey ?? parsedChainKey ?? walletChainKey ?? "sepolia";

  if (walletChainKey && walletChainKey !== chainKey) {
    throw new Error(
      `指定錢包屬於 ${walletChainKey}，但交易目標鏈是 ${chainKey}，請確認是否選錯錢包或 chain。`,
    );
  }

  return chainKey;
}
