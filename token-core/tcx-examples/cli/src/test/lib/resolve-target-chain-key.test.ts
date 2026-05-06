import { describe, expect, it } from "vitest";

import { resolveTargetChainKey } from "../../lib/chains";

// sepolia chainId = 11155111, baseSepolia chainId = 84532

describe("resolveTargetChainKey — chain conflict detection logic", () => {
  it("returns explicitChainKey directly when provided", () => {
    const result = resolveTargetChainKey({ explicitChainKey: "sepolia" });
    expect(result).toBe("sepolia");
  });

  it("returns default sepolia when no params are given", () => {
    const result = resolveTargetChainKey({});
    expect(result).toBe("sepolia");
  });

  it("returns sepolia when only parsedChainId is sepolia", () => {
    const result = resolveTargetChainKey({ parsedChainId: 11155111 });
    expect(result).toBe("sepolia");
  });

  it("returns baseSepolia when only parsedChainId is baseSepolia", () => {
    const result = resolveTargetChainKey({ parsedChainId: 84532 });
    expect(result).toBe("baseSepolia");
  });

  it("returns sepolia when only walletChainId is sepolia", () => {
    const result = resolveTargetChainKey({ walletChainId: 11155111 });
    expect(result).toBe("sepolia");
  });

  it("does not throw when explicitChainKey and walletChainId agree", () => {
    const result = resolveTargetChainKey({
      explicitChainKey: "baseSepolia",
      walletChainId: 84532,
    });
    expect(result).toBe("baseSepolia");
  });

  it("does not throw when parsedChainId and walletChainId agree", () => {
    const result = resolveTargetChainKey({
      parsedChainId: 11155111,
      walletChainId: 11155111,
    });
    expect(result).toBe("sepolia");
  });

  it("throws on chain conflict (walletChainKey differs from resolved chainKey)", () => {
    // wallet is on sepolia, but explicitChainKey targets baseSepolia
    expect(() =>
      resolveTargetChainKey({
        explicitChainKey: "baseSepolia",
        walletChainId: 11155111,
      }),
    ).toThrow(/指定錢包屬於 sepolia，但交易目標鏈是 baseSepolia/);
  });

  it("throws when walletChainId and parsedChainId conflict", () => {
    // wallet is on sepolia, transaction chainId is baseSepolia
    expect(() =>
      resolveTargetChainKey({
        parsedChainId: 84532,
        walletChainId: 11155111,
      }),
    ).toThrow(/指定錢包屬於 sepolia，但交易目標鏈是 baseSepolia/);
  });

  it("explicitChainKey takes precedence over parsedChainId", () => {
    // parsedChainId is baseSepolia, but explicit forces sepolia (no walletChainId)
    const result = resolveTargetChainKey({
      explicitChainKey: "sepolia",
      parsedChainId: 84532,
    });
    expect(result).toBe("sepolia");
  });

  it("unknown parsedChainId does not affect result (returns default sepolia)", () => {
    const result = resolveTargetChainKey({ parsedChainId: 9999999 });
    expect(result).toBe("sepolia");
  });
});
