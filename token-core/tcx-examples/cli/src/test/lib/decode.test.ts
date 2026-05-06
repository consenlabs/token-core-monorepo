import { afterEach, describe, expect, it, vi } from "vitest";

import { decodeParsedInput } from "../../lib/decode";
import type { ContractVerificationStatus, ParsedInput } from "../../lib/types";

const unknownVerification: ContractVerificationStatus = {
  verified: false,
  source: "unknown",
  message: "test",
};

describe("decodeParsedInput", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("decodes ERC-20 transfer calldata with built-in ABI candidates", async () => {
    const parsed: ParsedInput = {
      type: "json",
      chainId: 11155111,
      to: "0x1111111111111111111111111111111111111111",
      data: "0xa9059cbb00000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000064",
      value: 0n,
      raw: "{}",
    };

    const action = await decodeParsedInput(
      "sepolia",
      parsed,
      unknownVerification,
    );

    expect(action.kind).toBe("contractCall");
    expect(action.functionName).toBe("transfer");
    expect(action.selector).toBe("0xa9059cbb");
    expect(action.argsSummary).toHaveLength(2);
    expect(action.title).toContain("transfer");
  });

  it("falls back to unknown action when ABI does not match", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("network unavailable"),
    );

    const parsed: ParsedInput = {
      type: "json",
      chainId: 11155111,
      to: "0x1111111111111111111111111111111111111111",
      data: "0x12345678",
      value: 0n,
      raw: "{}",
    };

    const action = await decodeParsedInput(
      "sepolia",
      parsed,
      unknownVerification,
    );

    expect(action.functionName).toBeUndefined();
    expect(action.title).toBe("未知合約呼叫");
    expect(action.selector).toBe("0x12345678");
  });
});
