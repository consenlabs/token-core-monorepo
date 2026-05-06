import { describe, expect, it } from "vitest";

import {
  getChainConfig,
  getChainKeyById,
  getTokenPresets,
} from "../../lib/chains";
import { parsePolicyDocument } from "../../lib/policy";
import { createTemplateTransaction } from "../../lib/templates";
import type { PolicyRule } from "../../lib/types";
import defaultRiskPolicyJson from "../../policies/default-risk-policy.json";

describe("sepolia/baseSepolia compatibility smoke", () => {
  it("maps chainId to chain key correctly", () => {
    const sepolia = getChainConfig("sepolia");
    const baseSepolia = getChainConfig("baseSepolia");

    expect(getChainKeyById(sepolia.chainId)).toBe("sepolia");
    expect(getChainKeyById(baseSepolia.chainId)).toBe("baseSepolia");
    expect(getChainKeyById(999999)).toBeUndefined();
  });

  it("builds native transfer template for both chains", () => {
    for (const chainKey of ["sepolia", "baseSepolia"] as const) {
      const tx = createTemplateTransaction({
        chainKey,
        kind: "nativeTransfer",
        from: "0x1111111111111111111111111111111111111111",
        recipient: "0x2222222222222222222222222222222222222222",
        amount: "0.01",
      });

      expect(tx.chainId).toBe(getChainConfig(chainKey).chainId);
      expect(tx.request.to).toBe("0x2222222222222222222222222222222222222222");
      expect(tx.request.data).toBeUndefined();
      expect(tx.request.value).toBeGreaterThan(0n);
    }
  });

  it("builds uniswap exactInputSingle template for both chains", () => {
    for (const chainKey of ["sepolia", "baseSepolia"] as const) {
      const chain = getChainConfig(chainKey);
      const tokenOut = getTokenPresets(chainKey)[0]?.address;
      expect(chain.uniswap.swapRouter02).toBeDefined();
      expect(tokenOut).toBeDefined();

      const tx = createTemplateTransaction({
        chainKey,
        kind: "uniswapV2SwapExactETHForTokens",
        from: "0x1111111111111111111111111111111111111111",
        recipient: "0x1111111111111111111111111111111111111111",
        tokenOut,
        amountIn: "0.01",
        amountOutMin: "1",
        tokenOutDecimals: "6",
        feeBps: "500",
      });

      expect(tx.request.to?.toLowerCase()).toBe(
        chain.uniswap.swapRouter02?.toLowerCase(),
      );
      expect(tx.request.data?.slice(0, 10)).toBe("0x04e45aaf");
    }
  });

  it("keeps default policy token mapping aligned with chain presets", () => {
    const document = parsePolicyDocument(JSON.stringify(defaultRiskPolicyJson));
    const tokenRules = document.policies.filter(
      (policy) => policy.type === "maxAssetOut" && policy.assetKind === "erc20",
    ) as Array<Extract<PolicyRule, { type: "maxAssetOut" }>>;

    for (const chainKey of ["sepolia", "baseSepolia"] as const) {
      const presetMap = new Map(
        getTokenPresets(chainKey).map((token) => [
          token.symbol.toLowerCase(),
          token.address.toLowerCase(),
        ]),
      );

      for (const rule of tokenRules) {
        const expected = presetMap.get(rule.symbol.toLowerCase());
        const configured = rule.tokenAddressByChain?.[chainKey]?.toLowerCase();
        expect(configured).toBe(expected);
      }
    }
  });
});
