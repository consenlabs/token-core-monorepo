import { createPublicClient, http, parseUnits, type Address } from "viem";

import { erc20Abi, uniswapV3FactoryAbi, uniswapV3SwapRouterAbi } from "./abis";
import { getChainConfig, getTokenPresets } from "./chains";
import type { DemoChainKey } from "./types";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

function parseDecimals(value: string | undefined, fallback = 18) {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function readTokenDecimals(
  chainKey: DemoChainKey,
  tokenAddress: Address,
  preferred?: string,
) {
  const preset = getTokenPresets(chainKey).find(
    (item) => item.address.toLowerCase() === tokenAddress.toLowerCase(),
  );
  if (preset) return preset.decimals;
  if (preferred) return parseDecimals(preferred, 18);

  const chain = getChainConfig(chainKey);
  const client = createPublicClient({
    chain: chain.chain,
    transport: http(chain.rpcUrl),
  });
  try {
    return await client.readContract({
      address: tokenAddress,
      abi: erc20Abi,
      functionName: "decimals",
    });
  } catch {
    return 18;
  }
}

export async function quoteEthToTokenSwap(params: {
  chainKey: DemoChainKey;
  tokenOut: Address;
  amountIn: string;
  tokenOutDecimals?: string;
  slippageBps?: number;
  account?: Address;
  recipient?: Address;
}) {
  const chain = getChainConfig(params.chainKey);
  const tokenOutDecimals = await readTokenDecimals(
    params.chainKey,
    params.tokenOut,
    params.tokenOutDecimals,
  );
  const amountIn = parseUnits(params.amountIn || "0", 18);
  const client = createPublicClient({
    chain: chain.chain,
    transport: http(chain.rpcUrl),
  });

  if (!chain.uniswap.v3Factory) {
    throw new Error("目前這條鏈未設定 Uniswap v3 factory。");
  }
  if (!chain.uniswap.swapRouter02) {
    throw new Error("目前這條鏈未設定 Uniswap v3 SwapRouter02。");
  }

  let best:
    | {
        fee: number;
        pool: Address;
        amountOut: bigint;
      }
    | undefined;

  for (const fee of chain.uniswap.feeOptions) {
    const pool = await client.readContract({
      address: chain.uniswap.v3Factory,
      abi: uniswapV3FactoryAbi,
      functionName: "getPool",
      args: [chain.wrappedNativeToken.address, params.tokenOut, fee],
    });

    if (!pool || pool.toLowerCase() === ZERO_ADDRESS) continue;

    try {
      const quoteResult = await client.simulateContract({
        address: chain.uniswap.swapRouter02,
        abi: uniswapV3SwapRouterAbi,
        functionName: "exactInputSingle",
        account: params.account ?? params.recipient,
        args: [
          {
            tokenIn: chain.wrappedNativeToken.address,
            tokenOut: params.tokenOut,
            fee,
            recipient:
              params.recipient ??
              params.account ??
              chain.wrappedNativeToken.address,
            amountIn,
            amountOutMinimum: 0n,
            sqrtPriceLimitX96: 0n,
          },
        ],
        value: amountIn,
      });

      const amountOut = quoteResult.result;

      if (!best || amountOut > best.amountOut) {
        best = { fee, pool, amountOut };
      }
    } catch {
      continue;
    }
  }

  if (!best) {
    throw new Error(
      "目前找不到這組 token 在 Uniswap 測試網上的可用池子，請改用其他 token 或手動填寫 amountOutMinimum。",
    );
  }

  const slippageBps = params.slippageBps ?? 1000;
  const amountOutMinimum =
    (best.amountOut * BigInt(10_000 - slippageBps)) / 10_000n;

  return {
    poolFee: best.fee,
    poolAddress: best.pool,
    quotedAmountOut: best.amountOut,
    amountOutMinimum,
    tokenOutDecimals,
  };
}
