import { describe, expect, it } from "vitest";

import {
  evaluatePolicies,
  parsePolicyDocument,
  stringifyPolicyDocument,
} from "../../lib/policy";
import type {
  ContractVerificationStatus,
  DecodedAction,
  ParsedInput,
  PolicyDocument,
  SimulationSummary,
} from "../../lib/types";

// ── fixtures ─────────────────────────────────────────────────────────────────

const baseVerification: ContractVerificationStatus = {
  verified: true,
  source: "etherscan",
  message: "ok",
};

const baseAction: DecodedAction = {
  kind: "contractCall",
  title: "Transfer",
  summary: "transfer",
  functionName: "transfer",
  argsSummary: [],
};

const nativeTransferAction: DecodedAction = {
  kind: "nativeTransfer",
  title: "原生幣轉帳",
  summary: "把 0.01 ETH 轉給 0x1234",
  argsSummary: [
    { label: "接收地址", value: "0x1234" },
    { label: "金額", value: "0.01 ETH" },
  ],
};

const baseSimulation: SimulationSummary = {
  success: true,
  source: "tenderly",
  summary: "success",
  tokenChanges: [],
};

const baseParsed: ParsedInput = {
  type: "json",
  raw: "{}",
  value: 0n,
};

function makeDoc(policies: PolicyDocument["policies"]): PolicyDocument {
  return { version: 1, name: "test", policies };
}

// ── stringifyPolicyDocument ──────────────────────────────────────────────────

describe("stringifyPolicyDocument", () => {
  it("serialises round-trip correctly", () => {
    const doc = parsePolicyDocument(
      JSON.stringify({
        version: 1,
        name: "test-policy",
        policies: [
          { id: "p1", name: "Verified", type: "requireVerifiedContract" },
        ],
      }),
    );
    const json = stringifyPolicyDocument(doc);
    const reparsed = parsePolicyDocument(json);
    expect(reparsed.name).toBe("test-policy");
    expect(reparsed.policies).toHaveLength(1);
    expect(reparsed.policies[0]!.id).toBe("p1");
  });

  it("produces pretty-printed JSON", () => {
    const doc = makeDoc([]);
    const result = stringifyPolicyDocument(doc);
    expect(result).toContain("\n");
  });
});

// ── evaluatePolicies ─────────────────────────────────────────────────────────

describe("evaluatePolicies — requireVerifiedContract", () => {
  const policy = {
    id: "vc1",
    name: "Verified",
    type: "requireVerifiedContract" as const,
  };

  it("passes when contract is verified", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("violates when contract is not verified", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: { ...baseVerification, verified: false },
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]!.policyId).toBe("vc1");
  });

  it("skips disabled policy", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([{ ...policy, enabled: false }]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: { ...baseVerification, verified: false },
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("does not violate for native transfer even when target is unverified", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: { ...baseParsed, value: 10_000_000_000_000_000n },
      action: nativeTransferAction,
      verification: { ...baseVerification, verified: false },
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });
});

describe("evaluatePolicies — requireSimulationSuccess", () => {
  const policy = {
    id: "sim1",
    name: "Sim",
    type: "requireSimulationSuccess" as const,
  };

  it("passes on successful simulation", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("violates on failed simulation", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: baseVerification,
      simulation: {
        ...baseSimulation,
        success: false,
        errorMessage: "revert",
      },
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]!.description).toContain("revert");
  });
});

describe("evaluatePolicies — forbidUnknownFunction", () => {
  const policy = {
    id: "uk1",
    name: "NoUnknown",
    type: "forbidUnknownFunction" as const,
  };

  it("passes when function is identified", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: baseAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("violates when functionName is undefined", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: { ...baseAction, functionName: undefined, title: "未知函式" },
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(1);
  });

  it("does not violate for native transfer (functionName is legitimately absent)", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: { ...baseParsed, value: 10_000_000_000_000_000n },
      action: nativeTransferAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });
});

describe("evaluatePolicies — forbidUnlimitedApproval", () => {
  const policy = {
    id: "ua1",
    name: "NoUnlimited",
    type: "forbidUnlimitedApproval" as const,
  };
  const maxUint256 = (2n ** 256n - 1n).toString();

  it("passes for normal approve amount", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: {
        ...baseAction,
        functionName: "approve",
        argsSummary: [
          { label: "spender", value: "0x1111" },
          { label: "amount", value: "1000000" },
        ],
      },
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("violates for max uint256 approve", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: {
        ...baseAction,
        functionName: "approve",
        argsSummary: [
          { label: "spender", value: "0x1111" },
          { label: "amount", value: maxUint256 },
        ],
      },
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]!.description).toContain("approve");
  });
});

describe("evaluatePolicies — maxAssetOut (native)", () => {
  const policy = {
    id: "mo1",
    name: "MaxETH",
    type: "maxAssetOut" as const,
    assetKind: "native" as const,
    symbol: "ETH",
    decimals: 18,
    max: "0.1",
  };

  it("passes when value is below max", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: { ...baseParsed, value: 50_000_000_000_000_000n }, // 0.05 ETH
      action: baseAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });

  it("violates when value exceeds max", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: { ...baseParsed, value: 200_000_000_000_000_000n }, // 0.2 ETH
      action: baseAction,
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]!.description).toContain("ETH");
  });
});

describe("evaluatePolicies — requireSwapMinimumOutput", () => {
  const policy = {
    id: "sw1",
    name: "MinOutput",
    type: "requireSwapMinimumOutput" as const,
  };

  it("violates when swap has amountOutMinimum = 0", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: {
        ...baseAction,
        functionName: "exactInputSingle",
        argsSummary: [
          {
            label: "params",
            value: JSON.stringify({ amountOutMinimum: "0" }),
          },
        ],
      },
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]!.description).toContain("amountOutMinimum");
  });

  it("passes when amountOutMinimum is set", () => {
    const { violations } = evaluatePolicies({
      document: makeDoc([policy]),
      chainKey: "sepolia",
      parsed: baseParsed,
      action: {
        ...baseAction,
        functionName: "exactInputSingle",
        argsSummary: [
          {
            label: "params",
            value: JSON.stringify({ amountOutMinimum: "100000" }),
          },
        ],
      },
      verification: baseVerification,
      simulation: baseSimulation,
    });
    expect(violations).toHaveLength(0);
  });
});
