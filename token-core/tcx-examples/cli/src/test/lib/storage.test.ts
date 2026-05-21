// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadStoredWallets, saveStoredWallets } from "../../lib/storage";
import type { StoredTokenCoreWallet } from "../../lib/types";

const STORAGE_KEY = "tokencore-cli.tokencore-wallets";

const mockWallet: StoredTokenCoreWallet = {
  id: "wallet-001",
  name: "Test Wallet",
  address: "0xAbCd1234567890AbCd1234567890AbCd12345678",
  keystoreJson: '{"version":3}',
  publicKey: "0xpubkey",
  derivationPath: "m/44'/60'/0'/0/0",
  chainId: 11155111,
  createdAt: "2026-01-01T00:00:00.000Z",
};

describe("loadStoredWallets", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("returns empty array when nothing is stored", () => {
    expect(loadStoredWallets()).toEqual([]);
  });

  it("returns stored wallets after saveStoredWallets", () => {
    saveStoredWallets([mockWallet]);
    const result = loadStoredWallets();
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe("wallet-001");
  });

  it("returns empty array on invalid JSON in localStorage", () => {
    window.localStorage.setItem(STORAGE_KEY, "not-valid-json{{");
    expect(loadStoredWallets()).toEqual([]);
  });

  it("returns empty array when localStorage has null for key", () => {
    window.localStorage.removeItem(STORAGE_KEY);
    expect(loadStoredWallets()).toEqual([]);
  });
});

describe("saveStoredWallets", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("persists multiple wallets", () => {
    const second = { ...mockWallet, id: "wallet-002", name: "Second" };
    saveStoredWallets([mockWallet, second]);
    const result = loadStoredWallets();
    expect(result).toHaveLength(2);
    expect(result.map((w) => w.id)).toEqual(["wallet-001", "wallet-002"]);
  });

  it("overwrites previous storage on second call", () => {
    saveStoredWallets([mockWallet]);
    saveStoredWallets([]);
    expect(loadStoredWallets()).toEqual([]);
  });
});
