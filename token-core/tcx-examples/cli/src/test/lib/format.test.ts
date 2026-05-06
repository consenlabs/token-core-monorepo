import { describe, expect, it } from "vitest";

import {
  formatDateTime,
  formatNativeAmount,
  formatTokenAmount,
  formatUnknown,
  formatVerificationSource,
  safeAddress,
  shortenAddress,
  trimNumber,
} from "../../lib/format";

describe("shortenAddress", () => {
  it("returns 未提供 for undefined", () => {
    expect(shortenAddress(undefined)).toBe("未提供");
  });

  it("returns 未提供 for empty string", () => {
    expect(shortenAddress("")).toBe("未提供");
  });

  it("shortens a full address", () => {
    // Vitalik's address - valid EIP-55 checksum
    const addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    expect(shortenAddress(addr)).toBe("0xd8dA...6045");
  });
});

describe("safeAddress", () => {
  it("returns undefined for undefined input", () => {
    expect(safeAddress(undefined)).toBeUndefined();
  });

  it("returns undefined for invalid address", () => {
    expect(safeAddress("not-an-address")).toBeUndefined();
  });

  it("returns typed Address for valid 0x address", () => {
    // Vitalik's address - valid EIP-55 checksum
    const addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    expect(safeAddress(addr)).toBe(addr);
  });
});

describe("trimNumber", () => {
  it("leaves integers unchanged", () => {
    expect(trimNumber("1000")).toBe("1000");
  });

  it("trims trailing zeros after decimal", () => {
    expect(trimNumber("1.5000")).toBe("1.5");
  });

  it("trims trailing dot and zeros", () => {
    expect(trimNumber("2.0000")).toBe("2");
  });

  it("keeps significant decimals", () => {
    expect(trimNumber("0.001")).toBe("0.001");
  });
});

describe("formatNativeAmount", () => {
  it("returns 0 when value is undefined", () => {
    expect(formatNativeAmount(undefined, "sepolia")).toBe("0");
  });

  it("formats ETH with correct symbol for sepolia", () => {
    const result = formatNativeAmount(1_000_000_000_000_000_000n, "sepolia");
    expect(result).toContain("1");
    expect(result).toContain("ETH");
  });

  it("formats ETH with correct symbol for baseSepolia", () => {
    const result = formatNativeAmount(500_000_000_000_000_000n, "baseSepolia");
    expect(result).toContain("ETH");
  });
});

describe("formatTokenAmount", () => {
  it("returns 0 when value is undefined", () => {
    expect(formatTokenAmount(undefined)).toBe("0");
  });

  it("formats with symbol", () => {
    const result = formatTokenAmount(1_000_000n, 6, "USDC");
    expect(result).toBe("1 USDC");
  });

  it("formats without symbol", () => {
    const result = formatTokenAmount(1_000_000n, 6);
    expect(result).toBe("1");
  });
});

describe("formatDateTime", () => {
  it("returns a non-empty string for a valid ISO date", () => {
    const result = formatDateTime("2026-01-15T10:30:00.000Z");
    expect(result.length).toBeGreaterThan(0);
    expect(result).toMatch(/2026/);
  });
});

describe("formatUnknown", () => {
  it("converts bigint to string", () => {
    expect(formatUnknown(1234567890n)).toBe("1234567890");
  });

  it("returns string as-is", () => {
    expect(formatUnknown("hello")).toBe("hello");
  });

  it("joins array elements", () => {
    expect(formatUnknown([1n, "two"])).toBe("1, two");
  });

  it("serializes objects to JSON", () => {
    const result = formatUnknown({ key: "value" });
    expect(result).toContain('"key"');
    expect(result).toContain('"value"');
  });

  it("converts null via String()", () => {
    expect(formatUnknown(null)).toBe("null");
  });
});

describe("formatVerificationSource", () => {
  it("returns Etherscan label", () => {
    expect(formatVerificationSource("etherscan")).toContain("Etherscan");
  });

  it("returns Sourcify label", () => {
    expect(formatVerificationSource("sourcify")).toBe("Sourcify");
  });

  it("returns 內建 for local", () => {
    expect(formatVerificationSource("local")).toContain("內建");
  });

  it("returns 未知來源 for unknown", () => {
    expect(formatVerificationSource("unknown")).toBe("未知來源");
  });
});
