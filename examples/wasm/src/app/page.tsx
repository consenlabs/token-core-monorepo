"use client";

import { useCallback, useState } from "react";
import {
  initWasm,
  create_keystore,
  derive_accounts,
  sign_tx,
} from "@/lib/wasm";

interface TestResult {
  name: string;
  status: "pass" | "fail" | "running";
  detail?: string;
  error?: string;
}

const TEST_MNEMONIC =
  "inject kidney empty canal shadow pact comfort wife crush horse wife sketch";
const TEST_PASSWORD = "password_for_test";

export default function Home() {
  const [results, setResults] = useState<TestResult[]>([]);
  const [running, setRunning] = useState(false);

  const push = (r: TestResult) =>
    setResults((prev) => {
      const idx = prev.findIndex((x) => x.name === r.name);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = r;
        return next;
      }
      return [...prev, r];
    });

  const runTests = useCallback(async () => {
    setResults([]);
    setRunning(true);

    try {
      // Init WASM
      push({ name: "Init WASM", status: "running" });
      await initWasm();
      push({ name: "Init WASM", status: "pass", detail: "Module loaded" });

      // 1. Create keystore (import mnemonic)
      push({ name: "Create Keystore (import)", status: "running" });
      const createRes = JSON.parse(
        create_keystore(
          JSON.stringify({
            password: TEST_PASSWORD,
            mnemonic: TEST_MNEMONIC,
            name: "test-wallet",
          })
        )
      );
      if (!createRes.id || createRes.source !== "MNEMONIC") {
        throw new Error(`Unexpected: ${JSON.stringify(createRes)}`);
      }
      push({
        name: "Create Keystore (import)",
        status: "pass",
        detail: `ID: ${createRes.id} | Source: ${createRes.source}`,
      });

      // 2. Create keystore (new mnemonic)
      push({ name: "Create Keystore (new)", status: "running" });
      const newRes = JSON.parse(
        create_keystore(
          JSON.stringify({ password: TEST_PASSWORD, name: "generated-wallet" })
        )
      );
      if (!newRes.id || newRes.source !== "NEW_MNEMONIC") {
        throw new Error(`Unexpected: ${JSON.stringify(newRes)}`);
      }
      push({
        name: "Create Keystore (new)",
        status: "pass",
        detail: `ID: ${newRes.id} | Source: ${newRes.source}`,
      });

      // 3. Derive ETH account
      push({ name: "Derive ETH Account", status: "running" });
      const acct = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson: createRes.keystoreJson,
            password: TEST_PASSWORD,
            derivationPath: "m/44'/60'/0'/0/0",
            chainId: "1",
            network: "MAINNET",
          })
        )
      );
      if (!acct.address?.startsWith("0x")) {
        throw new Error(`Bad address: ${acct.address}`);
      }
      push({
        name: "Derive ETH Account",
        status: "pass",
        detail: `Address: ${acct.address}`,
      });

      // 4. Sign legacy tx
      push({ name: "Sign Legacy TX (EIP-155)", status: "running" });
      const legacyTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson: createRes.keystoreJson,
            password: TEST_PASSWORD,
            derivationPath: "m/44'/60'/0'/0/0",
            input: {
              nonce: "0",
              gasPrice: "20000000000",
              gasLimit: "21000",
              to: "0x3535353535353535353535353535353535353535",
              value: "1000000000000000000",
              chainId: "1",
            },
          })
        )
      );
      if (!legacyTx.signature || !legacyTx.txHash) {
        throw new Error("Missing signature/txHash");
      }
      push({
        name: "Sign Legacy TX (EIP-155)",
        status: "pass",
        detail: `Hash: ${legacyTx.txHash}`,
      });

      // 5. Sign EIP-1559 tx
      push({ name: "Sign EIP-1559 TX", status: "running" });
      const eip1559Tx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson: createRes.keystoreJson,
            password: TEST_PASSWORD,
            derivationPath: "m/44'/60'/0'/0/0",
            input: {
              nonce: "1",
              gasLimit: "21000",
              to: "0x3535353535353535353535353535353535353535",
              value: "1000000000000000000",
              chainId: "1",
              txType: "02",
              maxFeePerGas: "30000000000",
              maxPriorityFeePerGas: "1000000000",
              accessList: [],
            },
          })
        )
      );
      if (!eip1559Tx.signature || !eip1559Tx.txHash) {
        throw new Error("Missing signature/txHash");
      }
      push({
        name: "Sign EIP-1559 TX",
        status: "pass",
        detail: `Hash: ${eip1559Tx.txHash}`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      push({
        name: results.find((r) => r.status === "running")?.name ?? "Unknown",
        status: "fail",
        error: msg,
      });
    } finally {
      setRunning(false);
    }
  }, []);

  const passed = results.filter((r) => r.status === "pass").length;
  const failed = results.filter((r) => r.status === "fail").length;

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 p-8 font-[family-name:var(--font-geist-sans)]">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-2xl font-bold mb-2 text-zinc-900 dark:text-zinc-100">
          tcx-wasm Integration Tests
        </h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
          Browser-side WASM integration tests for keystore, account derivation &
          ETH signing.
        </p>

        <button
          onClick={runTests}
          disabled={running}
          className="mb-8 px-5 py-2.5 rounded-lg bg-zinc-900 text-white text-sm font-medium hover:bg-zinc-700 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300 transition-colors"
        >
          {running ? "Running..." : "Run Tests"}
        </button>

        {results.length > 0 && (
          <>
            <div className="mb-4 text-sm text-zinc-600 dark:text-zinc-400">
              {passed + failed} / {results.length} completed
              {failed > 0 && (
                <span className="text-red-600 dark:text-red-400 ml-2">
                  ({failed} failed)
                </span>
              )}
              {failed === 0 && passed === results.length && (
                <span className="text-green-600 dark:text-green-400 ml-2">
                  All passed
                </span>
              )}
            </div>

            <ul className="space-y-3">
              {results.map((r) => (
                <li
                  key={r.name}
                  className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-4"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-base">
                      {r.status === "pass" && "✅"}
                      {r.status === "fail" && "❌"}
                      {r.status === "running" && "⏳"}
                    </span>
                    <span className="font-medium text-sm text-zinc-900 dark:text-zinc-100">
                      {r.name}
                    </span>
                  </div>
                  {r.detail && (
                    <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 font-mono break-all pl-7">
                      {r.detail}
                    </p>
                  )}
                  {r.error && (
                    <p className="mt-1 text-xs text-red-600 dark:text-red-400 font-mono break-all pl-7">
                      {r.error}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
