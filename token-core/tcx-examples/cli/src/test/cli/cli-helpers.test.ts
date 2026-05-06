import { describe, expect, it } from "vitest";

import {
  buildBlockingBroadcastPolicyWarning,
  buildBlockingSignPolicyWarning,
  buildDraftFromParsed,
  renderBroadcastTimeoutMessage,
} from "../../cli/helpers";

// Sepolia chainId = 11155111, baseSepolia chainId = 84532

describe("buildDraftFromParsed", () => {
  it("fills chainId from chainConfig when not present in input", () => {
    const result = buildDraftFromParsed("sepolia", { type: "json", raw: "{}" });
    expect(result.chainId).toBe(11155111);
  });

  it("uses input.chainId when present", () => {
    const result = buildDraftFromParsed("sepolia", {
      type: "json",
      chainId: 84532,
      raw: "{}",
    });
    expect(result.chainId).toBe(84532);
  });

  it("uses input.from as account when account param not provided", () => {
    const from = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`;
    const result = buildDraftFromParsed("sepolia", {
      type: "json",
      from,
      raw: "{}",
    });
    expect(result.account).toBe(from);
  });

  it("uses account param when input.from is missing", () => {
    const account =
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as `0x${string}`;
    const result = buildDraftFromParsed(
      "sepolia",
      { type: "json", raw: "{}" },
      account,
    );
    expect(result.account).toBe(account);
  });

  it("input.from takes priority over account param", () => {
    const from = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`;
    const account =
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as `0x${string}`;
    const result = buildDraftFromParsed(
      "sepolia",
      { type: "json", from, raw: "{}" },
      account,
    );
    expect(result.account).toBe(from);
  });

  it("maps to/data/value/gas/nonce from input", () => {
    const to = "0xcccccccccccccccccccccccccccccccccccccccc" as `0x${string}`;
    const data = "0xdeadbeef" as `0x${string}`;
    const result = buildDraftFromParsed("sepolia", {
      type: "json",
      to,
      data,
      value: 1n,
      gas: 21000n,
      nonce: 5,
      raw: "{}",
    });
    expect(result.to).toBe(to);
    expect(result.data).toBe(data);
    expect(result.value).toBe(1n);
    expect(result.gas).toBe(21000n);
    expect(result.nonce).toBe(5);
  });

  it("uses baseSepolia chainId when key is baseSepolia and no input chainId", () => {
    const result = buildDraftFromParsed("baseSepolia", {
      type: "json",
      raw: "{}",
    });
    expect(result.chainId).toBe(84532);
  });
});

describe("buildBlockingBroadcastPolicyWarning", () => {
  it("replaces non-blocking broadcast message with blocking message", () => {
    const input =
      "policy warning\nCLI 仍會繼續執行 broadcast，請自行判斷是否中止。\nend";
    const result = buildBlockingBroadcastPolicyWarning(input);
    expect(result).toContain(
      "已啟用 --policy 廣播攔截；若有不符合項目將停止廣播。",
    );
    expect(result).not.toContain("CLI 仍會繼續執行 broadcast");
  });

  it("returns unchanged string when pattern not found", () => {
    const input = "no matching pattern here";
    expect(buildBlockingBroadcastPolicyWarning(input)).toBe(input);
  });
});

describe("buildBlockingSignPolicyWarning", () => {
  it("replaces non-blocking sign message with blocking message", () => {
    const input =
      "policy warning\nCLI 仍會繼續執行 sign，請自行判斷是否中止。\nend";
    const result = buildBlockingSignPolicyWarning(input);
    expect(result).toContain(
      "已啟用 --policy 簽名攔截；若有不符合項目將停止簽名。",
    );
    expect(result).not.toContain("CLI 仍會繼續執行 sign");
  });

  it("returns unchanged string when pattern not found", () => {
    const input = "no matching pattern here";
    expect(buildBlockingSignPolicyWarning(input)).toBe(input);
  });
});

describe("renderBroadcastTimeoutMessage", () => {
  it("includes 廣播結果 header and error message", () => {
    const result = renderBroadcastTimeoutMessage(
      "sepolia",
      new Error("交易逾時。"),
    );
    expect(result).toContain("廣播結果");
    expect(result).toContain("交易逾時。");
  });

  it("uses fallback message for non-Error value", () => {
    const result = renderBroadcastTimeoutMessage("sepolia", "some string");
    expect(result).toContain("交易廣播失敗。");
  });

  it("extracts txHash from error message and includes explorer url", () => {
    const err = new Error(
      "broadcast failed txHash=0xabc123deadbeef0000000000000000000000000000000000000000000000000",
    );
    const result = renderBroadcastTimeoutMessage("sepolia", err);
    expect(result).toContain(
      "txHash：0xabc123deadbeef0000000000000000000000000000000000000000000000000",
    );
    expect(result).toContain("explorer：");
  });

  it("does not include txHash line when no hash in message", () => {
    const result = renderBroadcastTimeoutMessage(
      "sepolia",
      new Error("generic failure"),
    );
    expect(result).not.toContain("txHash：");
    expect(result).not.toContain("explorer：");
  });

  it("prepends policyWarning before 廣播結果 when provided", () => {
    const result = renderBroadcastTimeoutMessage(
      "sepolia",
      new Error("err"),
      "policy警告內容",
    );
    expect(result.startsWith("policy警告內容\n廣播結果")).toBe(true);
  });

  it("starts with 廣播結果 when no policyWarning", () => {
    const result = renderBroadcastTimeoutMessage("sepolia", new Error("err"));
    expect(result.startsWith("廣播結果")).toBe(true);
  });
});
