"use client";

import { useCallback, useState } from "react";
import {
  initWasm,
  create_keystore,
  derive_accounts,
  sign_tx,
  cache_keystore,
  clear_cached_keystore,
} from "@/lib/wasm";

interface TestResult {
  name: string;
  status: "pass" | "fail" | "running";
  detail?: string;
  error?: string;
}

const TEST_MNEMONIC =
  "inject kidney empty canal shadow pact comfort wife crush horse wife sketch";
const TEST_PRF_KEY =
  "0000000000000000000000000000000000000000000000000000000000000001";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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
      const keystoreJson = create_keystore(
        JSON.stringify({
          prfKey: TEST_PRF_KEY,
          userId: "test-user",
          credentialId: "test-credential",
          rpId: "localhost",
          mnemonic: TEST_MNEMONIC,
          network: "MAINNET",
        })
      );
      const importedKs = JSON.parse(keystoreJson);
      if (!importedKs.encryptedMnemonic || !importedKs.mnemonicIv) {
        throw new Error(`Unexpected: ${keystoreJson}`);
      }
      if (
        !importedKs.identity?.identifier ||
        !importedKs.identity?.ipfsId ||
        !importedKs.identity?.encKey ||
        !importedKs.identity?.encAuthKey
      ) {
        throw new Error(`Missing identity fields: ${keystoreJson}`);
      }
      push({
        name: "Create Keystore (import)",
        status: "pass",
        detail: JSON.stringify(importedKs, null, 2),
      });

      // 2. Create keystore (new — entropy from Web Crypto, testnet)
      push({ name: "Create Keystore (new via entropy)", status: "running" });
      const entropy = crypto.getRandomValues(new Uint8Array(16));
      const newKeystoreJson = create_keystore(
        JSON.stringify({
          prfKey: TEST_PRF_KEY,
          userId: "test-user-2",
          credentialId: "test-credential-2",
          rpId: "localhost",
          entropy: toHex(entropy),
          network: "TESTNET",
        })
      );
      const newKs = JSON.parse(newKeystoreJson);
      if (!newKs.encryptedMnemonic || !newKs.mnemonicIv) {
        throw new Error(`Unexpected: ${newKeystoreJson}`);
      }
      if (!newKs.identity?.identifier || !newKs.identity?.ipfsId) {
        throw new Error(`Missing identity: ${newKeystoreJson}`);
      }
      push({
        name: "Create Keystore (new via entropy)",
        status: "pass",
        detail: `Identifier: ${newKs.identity.identifier} | Network: TESTNET`,
      });

      // 3. Derive ETH + TRON accounts in one call
      push({ name: "Derive Accounts (ETH + TRON)", status: "running" });
      const accounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
            derivations: [
              {
                chain: "ETHEREUM",
                derivationPath: "m/44'/60'/0'/0/0",
                chainId: "1",
                network: "MAINNET",
              },
              {
                chain: "TRON",
                derivationPath: "m/44'/195'/0'/0/0",
                network: "MAINNET",
              },
            ],
          })
        )
      );
      const acct = accounts[0];
      const tronAcct = accounts[1];
      if (!acct.address?.startsWith("0x")) {
        throw new Error(`Bad ETH address: ${acct.address}`);
      }
      if (!tronAcct.address?.startsWith("T")) {
        throw new Error(`Bad TRON address: ${tronAcct.address}`);
      }
      push({
        name: "Derive Accounts (ETH + TRON)",
        status: "pass",
        detail: `ETH: ${acct.address}\nTRON: ${tronAcct.address}`,
      });

      // 5. Sign legacy tx
      push({ name: "Sign Legacy TX (EIP-155)", status: "running" });
      const legacyTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
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

      // 6. Sign EIP-1559 tx
      push({ name: "Sign EIP-1559 TX", status: "running" });
      const eip1559Tx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
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

      // 7. Sign TRON tx
      push({ name: "Sign TRON TX", status: "running" });
      const tronTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
            chain: "TRON",
            input: {
              rawData:
                "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470a0bfbfa7c92d",
            },
          })
        )
      );
      if (!tronTx.signatures || tronTx.signatures.length === 0) {
        throw new Error("Missing TRON signatures");
      }
      push({
        name: "Sign TRON TX",
        status: "pass",
        detail: `Signature: ${tronTx.signatures[0].slice(0, 32)}...`,
      });

      // 8. Cache keystore & derive without explicit keystoreJson
      push({ name: "Cache Keystore + Derive", status: "running" });
      cache_keystore(keystoreJson);
      const cachedAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            prfKey: TEST_PRF_KEY,
            derivations: [
              {
                chain: "ETHEREUM",
                derivationPath: "m/44'/60'/0'/0/0",
                chainId: "1",
                network: "MAINNET",
              },
            ],
          })
        )
      );
      if (cachedAccounts[0].address !== acct.address) {
        throw new Error(
          `Cached derive mismatch: ${cachedAccounts[0].address} !== ${acct.address}`
        );
      }
      clear_cached_keystore();
      push({
        name: "Cache Keystore + Derive",
        status: "pass",
        detail: `Address matches: ${cachedAccounts[0].address}`,
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
          ETH / TRON signing.
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
                    <pre className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 font-mono break-all whitespace-pre-wrap pl-7">
                      {r.detail}
                    </pre>
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
