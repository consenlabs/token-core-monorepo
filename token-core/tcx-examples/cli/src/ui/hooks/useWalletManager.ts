import { type ChangeEvent, useEffect, useMemo, useState } from "react";

import { loadStoredWallets, saveStoredWallets } from "../../lib/storage";
import {
  createTokenCoreWallet,
  importTokenCoreWallet,
  initTokenCoreWasm,
} from "../../lib/tokencore";
import type { DemoChainKey, StoredTokenCoreWallet } from "../../lib/types";
import { parseManagedWalletFile } from "../../lib/wallet-file";

export function useWalletManager(requireChainSelected: () => DemoChainKey) {
  const [tokenCoreWallets, setTokenCoreWallets] = useState<
    StoredTokenCoreWallet[]
  >([]);
  const [activeTokenCoreWalletId, setActiveTokenCoreWalletId] =
    useState<string>("");
  const [tokenCoreName, setTokenCoreName] = useState("demo-wallet");
  const [tokenCorePassword, setTokenCorePassword] = useState("");
  const [tokenCoreImportName, setTokenCoreImportName] =
    useState("imported-wallet");
  const [tokenCoreImportPassword, setTokenCoreImportPassword] = useState("");
  const [tokenCoreImportJson, setTokenCoreImportJson] = useState("");
  const [hasLoadedStoredWallets, setHasLoadedStoredWallets] = useState(false);
  const [tokenCoreStatus, setTokenCoreStatus] =
    useState("尚未建立 TokenCore 帳號");

  useEffect(() => {
    initTokenCoreWasm().catch(() => {
      setTokenCoreStatus("TokenCore wasm 初始化失敗，請重新整理頁面。");
    });
  }, []);

  useEffect(() => {
    const wallets = loadStoredWallets();
    setTokenCoreWallets(wallets);
    if (wallets[0]) setActiveTokenCoreWalletId(wallets[0].id);
    setHasLoadedStoredWallets(true);
  }, []);

  useEffect(() => {
    if (!hasLoadedStoredWallets) return;
    saveStoredWallets(tokenCoreWallets);
  }, [hasLoadedStoredWallets, tokenCoreWallets]);

  const activeTokenCoreWallet = useMemo(
    () =>
      tokenCoreWallets.find((wallet) => wallet.id === activeTokenCoreWalletId),
    [activeTokenCoreWalletId, tokenCoreWallets],
  );

  function upsertTokenCoreWallet(nextWallet: StoredTokenCoreWallet) {
    setTokenCoreWallets((previous) => {
      const filtered = previous.filter(
        (wallet) =>
          !(
            wallet.address.toLowerCase() === nextWallet.address.toLowerCase() &&
            wallet.chainId === nextWallet.chainId
          ),
      );
      return [nextWallet, ...filtered];
    });
    setActiveTokenCoreWalletId(nextWallet.id);
  }

  function selectTokenCoreWallet(walletId: string) {
    setActiveTokenCoreWalletId(walletId);
  }

  function formatTokenCoreUiError(
    error: unknown,
    fallback: string,
    context: "create" | "import",
  ) {
    if (!(error instanceof Error)) return fallback;
    const message = error.message.trim();
    if (!message) return fallback;

    if (context === "import") {
      if (
        message.includes("JSON") ||
        message.includes("Unexpected token") ||
        message.includes("Expected property name") ||
        message.includes("錢包檔格式不正確")
      ) {
        return "錢包檔 JSON 格式不正確，請重新確認內容。";
      }
      if (
        message.includes("密碼不正確") ||
        message.includes("invalid password") ||
        message.includes("invalid mac") ||
        message.includes("decrypt") ||
        message.includes("password")
      ) {
        return "錢包密碼不正確，請重新輸入。";
      }
      return `匯入失敗：${message}`;
    }

    return message;
  }

  function handleDeleteTokenCoreWallet(walletId: string) {
    const targetWallet = tokenCoreWallets.find(
      (wallet) => wallet.id === walletId,
    );
    if (!targetWallet) return;

    const confirmed = window.confirm(
      `確定要永久刪除錢包「${targetWallet.name}」嗎？此動作無法復原。`,
    );
    if (!confirmed) return;

    setTokenCoreWallets((previous) =>
      previous.filter((wallet) => wallet.id !== walletId),
    );
    if (activeTokenCoreWalletId === walletId) {
      const nextWallet = tokenCoreWallets.find(
        (wallet) => wallet.id !== walletId,
      );
      setActiveTokenCoreWalletId(nextWallet?.id ?? "");
    }
    setTokenCoreStatus(`已永久刪除 TokenCore 錢包：${targetWallet.address}`);
  }

  async function handleCreateTokenCoreWallet() {
    try {
      const chainKey = requireChainSelected();
      if (!tokenCorePassword.trim()) {
        throw new Error("請先輸入建立 TokenCore 錢包的密碼。");
      }

      const result = await createTokenCoreWallet({
        name: tokenCoreName.trim() || `wallet-${tokenCoreWallets.length + 1}`,
        password: tokenCorePassword,
        chainKey,
      });

      upsertTokenCoreWallet(result.wallet);
      setTokenCoreStatus(`已建立 TokenCore 錢包：${result.wallet.address}`);
    } catch (error) {
      setTokenCoreStatus(
        formatTokenCoreUiError(error, "建立 TokenCore 錢包失敗。", "create"),
      );
    }
  }

  async function handleImportTokenCoreWallet() {
    try {
      const chainKey = requireChainSelected();
      if (!tokenCoreImportPassword.trim()) {
        throw new Error("請先輸入匯入錢包所需密碼。");
      }
      if (!tokenCoreImportJson.trim()) {
        throw new Error("請先貼上或選擇錢包檔 JSON。");
      }

      const importedWallet = parseManagedWalletFile(tokenCoreImportJson);
      const wallet = await importTokenCoreWallet({
        name:
          tokenCoreImportName.trim() ||
          importedWallet.name ||
          `imported-${tokenCoreWallets.length + 1}`,
        password: tokenCoreImportPassword,
        chainKey,
        keystoreJson: importedWallet.keystoreJson,
        derivationPath: importedWallet.derivationPath,
      });

      upsertTokenCoreWallet(wallet);
      setTokenCoreImportPassword("");
      setTokenCoreImportJson("");
      setTokenCoreStatus(`已匯入 TokenCore 錢包：${wallet.address}`);
    } catch (error) {
      setTokenCoreStatus(
        formatTokenCoreUiError(error, "匯入 TokenCore 錢包失敗。", "import"),
      );
    }
  }

  async function handleImportWalletFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      setTokenCoreImportJson(content);
      try {
        const importedWallet = parseManagedWalletFile(content);
        setTokenCoreImportName(importedWallet.name);
      } catch {
        // keep raw content for user to fix
      }
      setTokenCoreStatus(`已載入錢包檔：${file.name}`);
    } catch (error) {
      setTokenCoreStatus(
        String(error instanceof Error ? error.message : error),
      );
    }
  }

  return {
    tokenCoreWallets,
    activeTokenCoreWalletId,
    activeTokenCoreWallet,
    tokenCoreName,
    setTokenCoreName,
    tokenCorePassword,
    setTokenCorePassword,
    tokenCoreImportName,
    setTokenCoreImportName,
    tokenCoreImportPassword,
    setTokenCoreImportPassword,
    tokenCoreImportJson,
    setTokenCoreImportJson,
    tokenCoreStatus,
    selectTokenCoreWallet,
    handleDeleteTokenCoreWallet,
    handleCreateTokenCoreWallet,
    handleImportTokenCoreWallet,
    handleImportWalletFile,
  };
}
