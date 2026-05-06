import { afterEach, describe, expect, it, vi } from "vitest";

import { simulateTransaction } from "../../lib/simulate";
import type { DecodedAction, ParsedInput } from "../../lib/types";

// Mock viem createPublicClient to avoid real RPC calls.
vi.mock("viem", async (importOriginal) => {
  const actual = await importOriginal<typeof import("viem")>();
  return {
    ...actual,
    createPublicClient: vi.fn(() => ({
      getBlock: vi.fn().mockResolvedValue({ baseFeePerGas: 1_000_000_000n }),
      estimateFeesPerGas: vi.fn().mockResolvedValue({
        maxFeePerGas: 2_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
      call: vi.fn().mockResolvedValue({ data: "0x" }),
    })),
  };
});

// Mock getRuntimeEnv so that the Node RPC fallback path is active.
// (REST API creds are intentionally absent → falls back to RPC)
vi.mock("../../lib/env", () => ({
  getRuntimeEnv: (key: string) => {
    if (key === "VITE_TENDERLY_NODE_ACCESS_KEY") return "test-access-key";
    return undefined;
  },
}));

const PARSED: ParsedInput = {
  type: "json",
  raw: "{}",
  from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  to: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  data: "0x",
  value: 1000000000000000n,
  chainId: 11155111,
};

const ACTION: DecodedAction = {
  kind: "nativeTransfer",
  title: "原生幣轉帳",
  summary: "ETH 轉帳",
  argsSummary: [],
  value: 1000000000000000n,
};

// Build a successful Tenderly Node RPC response (camelCase fields).
function makeTenderlySuccessResponse() {
  return {
    result: {
      status: true,
      gasUsed: "0x5208",
      assetChanges: [
        {
          type: "transfer",
          from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          to: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          symbol: "ETH",
          amount: "1000000000000000",
          dollar_value: "3.50",
          contract_address: null,
        },
      ],
    },
  };
}

// Build a failed Tenderly Node RPC response.
function makeTenderlyFailureResponse() {
  return {
    result: {
      status: false,
      gasUsed: "0x0",
      error_message: "execution reverted",
      assetChanges: [],
    },
  };
}

function mockFetch(body: unknown, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status: ok ? 200 : 500,
    statusText: ok ? "OK" : "Internal Server Error",
    json: () => Promise.resolve(body),
  });
}

describe("simulateWithTenderly — Node RPC fallback response field normalisation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("source is tenderly and tokenChanges come from assetChanges (not heuristic fallback)", async () => {
    // Mock fetch to return camelCase assetChanges.
    vi.stubGlobal("fetch", mockFetch(makeTenderlySuccessResponse()));

    const result = await simulateTransaction("sepolia", PARSED, ACTION);

    // source must be tenderly, not falling back to heuristic.
    expect(result.source).toBe("tenderly");
    expect(result.success).toBe(true);
    // assetChanges parsed correctly; symbol comes from Tenderly.
    expect(result.tokenChanges.length).toBeGreaterThan(0);
    expect(result.tokenChanges[0].tokenSymbol).toBe("ETH");
    // gasEstimate converted from hex gasUsed (0x5208 = 21000).
    expect(result.gasEstimate).toBe("21000");
  });

  it("success is false when Tenderly returns status: false", async () => {
    vi.stubGlobal("fetch", mockFetch(makeTenderlyFailureResponse()));

    const result = await simulateTransaction("sepolia", PARSED, ACTION);

    expect(result.source).toBe("tenderly");
    expect(result.success).toBe(false);
  });

  it("success is false on Tenderly HTTP error (source still marked as tenderly)", async () => {
    // Mock fetch to return HTTP 500.
    vi.stubGlobal("fetch", mockFetch({}, false));

    const result = await simulateTransaction("sepolia", PARSED, ACTION);

    // HTTP failure → success: false; source stays tenderly so the UI can display the origin.
    expect(result.success).toBe(false);
    expect(result.source).toBe("tenderly");
    expect(result.errorMessage).toContain("HTTP 500");
  });

  it("tokenChanges is empty when assetChanges is an empty array (no Tenderly asset movements)", async () => {
    // Mock fetch with empty assetChanges (not undefined) — Tenderly detected no asset movements.
    vi.stubGlobal(
      "fetch",
      mockFetch({ result: { status: true, gasUsed: "0x0", assetChanges: [] } }),
    );

    const result = await simulateTransaction("sepolia", PARSED, ACTION);

    expect(result.source).toBe("tenderly");
    // assetChanges: [] → parsed as empty array, not a heuristic fallback.
    expect(result.tokenChanges).toHaveLength(0);
  });
});
