/// <reference types="node" />

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const cliEntrypoint = fileURLToPath(new URL("../../cli.ts", import.meta.url));
const projectRoot = fileURLToPath(new URL("../../..", import.meta.url));
const requiredPolicyError =
  "analyze、sign、broadcast 皆必須提供 --policy（可為 JSON 檔案路徑或 inline JSON 字串，以 { 開頭自動判斷）。";
const requiredChainError =
  "缺少必要參數 --chain。合法值：eth-sepolia、base-sepolia。";

function runCli(args: string[]) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", cliEntrypoint, ...args],
    {
      cwd: projectRoot,
      encoding: "utf8",
    },
  );
}

describe("cli policy gating", () => {
  it("rejects analyze when policy is missing", () => {
    const result = runCli([
      "analyze",
      "--chain",
      "eth-sepolia",
      "--input",
      '{"chainId":11155111,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredPolicyError);
  });

  it("rejects sign when policy is missing", () => {
    const result = runCli([
      "sign",
      "--chain",
      "eth-sepolia",
      "--input",
      '{"chainId":11155111,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredPolicyError);
  });

  it("rejects broadcast when policy is missing", () => {
    const result = runCli([
      "broadcast",
      "--chain",
      "eth-sepolia",
      "--input",
      "0x02f86d83aa36a780808252089411111111111111111111111111111111111111118080c001a0676cbf820cb6f87f9f7f26f9ea31bf08a803f6d26c5f390d05f9b0a7f620951ba0768cf87f1fd95dff4a6f5ac2e4f0d4f533f35d4f53fbe7e3189f581f3eddd4b8",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredPolicyError);
  });
});

describe("cli exit code contract", () => {
  it("returns 0 for --help", () => {
    const result = runCli(["--help"]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("用法：");
  });

  it("returns 0 for wallet list", () => {
    const result = runCli(["wallet", "list"]);

    expect(result.status).toBe(0);
  });

  it("returns 1 for unknown command", () => {
    const result = runCli(["unknown-command"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("未知命令");
  });

  it("returns 1 for unsupported wallet subcommand", () => {
    const result = runCli(["wallet", "remove"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "wallet 子命令僅支援 create、import、list。",
    );
  });

  it("returns 1 when analyze misses input", () => {
    const result = runCli([
      "analyze",
      "--chain",
      "eth-sepolia",
      "--policy",
      '{"version":1,"name":"demo","policies":[]}',
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("請提供 --input 或 --input-file。");
  });

  it("returns 1 when analyze misses --chain", () => {
    const result = runCli([
      "analyze",
      "--input",
      '{"chainId":11155111,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
      "--policy",
      '{"version":1,"name":"demo","policies":[]}',
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredChainError);
    expect(result.stderr).toContain("範例：");
    expect(result.stderr).toContain(
      "npm run cli -- analyze --chain eth-sepolia",
    );
    expect(result.stderr).toContain("目前命令：analyze");
  });

  it("returns 1 when wallet create misses --chain", () => {
    const result = runCli([
      "wallet",
      "create",
      "--name",
      "test-wallet",
      "--password",
      "test123",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredChainError);
    expect(result.stderr).toContain("目前命令：wallet create");
  });

  it("returns 1 when wallet import misses --chain", () => {
    const result = runCli([
      "wallet",
      "import",
      "--wallet",
      "/tmp/nonexistent.wallet.json",
      "--password",
      "test123",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(requiredChainError);
    expect(result.stderr).toContain("目前命令：wallet import");
  });
});

describe("cli chain compatibility gating (P6-a)", () => {
  const minimalPolicy = '{"version":1,"name":"demo","policies":[]}';

  it("rejects sign when --chain conflicts with input chainId (eth-sepolia vs base-sepolia)", () => {
    const result = runCli([
      "sign",
      "--chain",
      "eth-sepolia",
      "--input",
      '{"chainId":84532,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
      "--policy",
      minimalPolicy,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("input.chainId 84532");
    expect(result.stderr).toContain("Base Sepolia");
    expect(result.stderr).toContain("簽名已停止");
  });

  it("rejects broadcast (unsigned) when --chain conflicts with input chainId (base-sepolia vs eth-sepolia)", () => {
    const result = runCli([
      "broadcast",
      "--chain",
      "base-sepolia",
      "--input",
      '{"chainId":11155111,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
      "--policy",
      minimalPolicy,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("input.chainId 11155111");
    expect(result.stderr).toContain("Ethereum Sepolia");
    expect(result.stderr).toContain("廣播已停止");
  });

  it("allows sign to proceed past chain check when --chain matches input chainId", () => {
    // Chains match (both eth-sepolia / chainId 11155111) → chain check passes.
    // No --wallet provided → fails later at wallet resolution, NOT at chain check.
    const result = runCli([
      "sign",
      "--chain",
      "eth-sepolia",
      "--input",
      '{"chainId":11155111,"to":"0x1111111111111111111111111111111111111111","data":"0x","value":"0"}',
      "--policy",
      minimalPolicy,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).not.toContain("簽名已停止");
    expect(result.stderr).toContain("缺少必要參數 --wallet");
  });
});
