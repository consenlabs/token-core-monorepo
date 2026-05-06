import { describe, expect, it } from "vitest";

import { createTemplateTransaction } from "../../lib/templates";

describe("createTemplateTransaction", () => {
  it("builds ERC-20 transfer calldata", () => {
    const tx = createTemplateTransaction({
      chainKey: "sepolia",
      kind: "erc20Transfer",
      from: "0x1111111111111111111111111111111111111111",
      tokenAddress: "0x2222222222222222222222222222222222222222",
      recipient: "0x3333333333333333333333333333333333333333",
      amount: "1.5",
    });

    expect(tx.request.to).toBe("0x2222222222222222222222222222222222222222");
    expect(tx.request.data?.slice(0, 10)).toBe("0xa9059cbb");
    expect(tx.request.value).toBe(0n);
  });

  it("builds native transfer request", () => {
    const tx = createTemplateTransaction({
      chainKey: "baseSepolia",
      kind: "nativeTransfer",
      from: "0x1111111111111111111111111111111111111111",
      recipient: "0x4444444444444444444444444444444444444444",
      amount: "0.25",
    });

    expect(tx.request.to).toBe("0x4444444444444444444444444444444444444444");
    expect(tx.request.data).toBeUndefined();
    expect(tx.request.value).toBe(250000000000000000n);
  });
});
