"use client";

import { useCallback, useState } from "react";
import {
  initWasm,
  create_keystore,
  export_mnemonic,
  derive_accounts,
  sign_tx,
  sign_txs,
  sign_message,
  sign_psbt,
  sign_psbts,
  cache_keystore,
  clear_cached_keystore,
  derive_message_key_pair,
  sign_message_event,
  encrypt_message,
  decrypt_message,
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
const TEST_PASSWORD = "correct horse battery staple";
const TEST_SERVER_PUBKEY =
  "d39eadac9f88ea1a77b034e8586191ed5435f44b01dea8f214f45fd7bd0b8e0f";

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

      // 3. Create keystore (random — no mnemonic or entropy)
      push({ name: "Create Keystore (random)", status: "running" });
      const randomKeystoreJson = create_keystore(
        JSON.stringify({
          prfKey: TEST_PRF_KEY,
          userId: "test-user-3",
          credentialId: "test-credential-3",
          rpId: "localhost",
          network: "MAINNET",
        })
      );
      const randomKs = JSON.parse(randomKeystoreJson);
      if (!randomKs.encryptedMnemonic || !randomKs.mnemonicIv) {
        throw new Error(`Unexpected: ${randomKeystoreJson}`);
      }
      if (!randomKs.identity?.identifier || !randomKs.identity?.ipfsId) {
        throw new Error(`Missing identity: ${randomKeystoreJson}`);
      }
      if (randomKs.encryptedMnemonic === importedKs.encryptedMnemonic) {
        throw new Error("Random keystore should differ from imported one");
      }
      push({
        name: "Create Keystore (random)",
        status: "pass",
        detail: `Identifier: ${randomKs.identity.identifier}`,
      });

      // 4. Create password keystore
      push({ name: "Create Password Keystore", status: "running" });
      const passwordKeystoreStart = performance.now();
      const passwordKeystoreJson = create_keystore(
        JSON.stringify({
          password: TEST_PASSWORD,
          mnemonic: TEST_MNEMONIC,
          network: "MAINNET",
        })
      );
      const passwordKeystoreElapsedMs = performance.now() - passwordKeystoreStart;
      const passwordKs = JSON.parse(passwordKeystoreJson);
      if (passwordKs.version !== 12000) {
        throw new Error(`Unexpected password keystore version: ${passwordKs.version}`);
      }
      if (
        passwordKs.crypto?.kdf !== "pbkdf2" ||
        passwordKs.crypto?.kdfparams?.c !== 65535
      ) {
        throw new Error(`Unexpected password crypto: ${passwordKeystoreJson}`);
      }
      push({
        name: "Create Password Keystore",
        status: "pass",
        detail: `Elapsed: ${passwordKeystoreElapsedMs.toFixed(1)} ms (KDF: ${passwordKs.crypto.kdf}, rounds: ${passwordKs.crypto.kdfparams.c})\n${JSON.stringify(passwordKs, null, 2)}`,
      });

      // 5. Export mnemonic
      push({ name: "Export Mnemonic", status: "running" });
      const exported = JSON.parse(
        export_mnemonic(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
          })
        )
      );
      if (exported.mnemonic !== TEST_MNEMONIC) {
        throw new Error(
          `Mnemonic mismatch: ${exported.mnemonic} !== ${TEST_MNEMONIC}`
        );
      }
      push({
        name: "Export Mnemonic",
        status: "pass",
        detail: `Mnemonic: ${exported.mnemonic}`,
      });

      // 6. Export mnemonic with legacy prfKey field
      push({ name: "Export Mnemonic (legacy prfKey)", status: "running" });
      const legacyExported = JSON.parse(
        export_mnemonic(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
          })
        )
      );
      if (legacyExported.mnemonic !== TEST_MNEMONIC) {
        throw new Error(
          `Legacy mnemonic mismatch: ${legacyExported.mnemonic} !== ${TEST_MNEMONIC}`
        );
      }
      push({
        name: "Export Mnemonic (legacy prfKey)",
        status: "pass",
        detail: "Legacy prfKey alias accepted",
      });

      // 7. Export password mnemonic and reject wrong password
      push({ name: "Password Export + Wrong Password", status: "running" });
      const passwordExported = JSON.parse(
        export_mnemonic(
          JSON.stringify({
            keystoreJson: passwordKeystoreJson,
            key: TEST_PASSWORD,
          })
        )
      );
      if (passwordExported.mnemonic !== TEST_MNEMONIC) {
        throw new Error(
          `Password mnemonic mismatch: ${passwordExported.mnemonic} !== ${TEST_MNEMONIC}`
        );
      }
      let wrongPasswordRejected = false;
      try {
        export_mnemonic(
          JSON.stringify({
            keystoreJson: passwordKeystoreJson,
            key: "wrong password",
          })
        );
      } catch {
        wrongPasswordRejected = true;
      }
      if (!wrongPasswordRejected) {
        throw new Error("Wrong password should be rejected");
      }
      push({
        name: "Password Export + Wrong Password",
        status: "pass",
        detail: "Password export succeeded; wrong password rejected",
      });

      // 8. Derive ETH + TRON accounts in one call
      push({ name: "Derive Accounts (ETH + TRON)", status: "running" });
      const accounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
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

      // 9. Derive password accounts
      push({ name: "Password Derive Accounts", status: "running" });
      const passwordAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson: passwordKeystoreJson,
            key: TEST_PASSWORD,
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
      if (passwordAccounts[0].address !== acct.address) {
        throw new Error(
          `Password ETH mismatch: ${passwordAccounts[0].address} !== ${acct.address}`
        );
      }
      if (passwordAccounts[1].address !== tronAcct.address) {
        throw new Error(
          `Password TRON mismatch: ${passwordAccounts[1].address} !== ${tronAcct.address}`
        );
      }
      push({
        name: "Password Derive Accounts",
        status: "pass",
        detail: `ETH: ${passwordAccounts[0].address}\nTRON: ${passwordAccounts[1].address}`,
      });

      // 10. Sign legacy tx
      push({ name: "Sign Legacy TX (EIP-155)", status: "running" });
      const legacyTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
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

      // 11. Sign legacy tx with password keystore
      push({ name: "Password Sign Legacy TX", status: "running" });
      const passwordLegacyTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson: passwordKeystoreJson,
            key: TEST_PASSWORD,
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
      if (
        passwordLegacyTx.signature !== legacyTx.signature ||
        passwordLegacyTx.txHash !== legacyTx.txHash
      ) {
        throw new Error("Password signature should match passkey signature");
      }
      push({
        name: "Password Sign Legacy TX",
        status: "pass",
        detail: `Hash: ${passwordLegacyTx.txHash}`,
      });

      // 6. Sign EIP-1559 tx
      push({ name: "Sign EIP-1559 TX", status: "running" });
      const eip1559Tx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
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
            key: TEST_PRF_KEY,
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

      // 8. Batch sign (ETH + TRON)
      push({ name: "Sign Batch TXs (ETH + TRON)", status: "running" });
      const batchResults = JSON.parse(
        sign_txs(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            txs: [
              {
                chain: "ETHEREUM",
                derivationPath: "m/44'/60'/0'/0/0",
                input: {
                  nonce: "2",
                  gasPrice: "20000000000",
                  gasLimit: "21000",
                  to: "0x3535353535353535353535353535353535353535",
                  value: "1000000000000000000",
                  chainId: "1",
                },
              },
              {
                chain: "TRON",
                input: {
                  rawData:
                    "0a0208312208b02efdc02638b61e40f083c3a7c92d5a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541a1e81654258bf14f63feb2e8d1380075d45b0dac1215410b3e84ec677b3e63c99affcadb91a6b4e086798f186470a0bfbfa7c92d",
                },
              },
            ],
          })
        )
      );
      if (!Array.isArray(batchResults) || batchResults.length !== 2) {
        throw new Error(`Expected 2 results, got ${JSON.stringify(batchResults)}`);
      }
      if (!batchResults[0].signature || !batchResults[0].txHash) {
        throw new Error("Missing ETH signature/txHash in batch result");
      }
      if (!batchResults[1].signatures || batchResults[1].signatures.length === 0) {
        throw new Error("Missing TRON signatures in batch result");
      }
      push({
        name: "Sign Batch TXs (ETH + TRON)",
        status: "pass",
        detail: `ETH Hash: ${batchResults[0].txHash}\nTRON Sig: ${batchResults[1].signatures[0].slice(0, 32)}...`,
      });

      // 9. Sign ETH message (PersonalSign)
      push({ name: "Sign ETH Message (PersonalSign)", status: "running" });
      const ethMsg = JSON.parse(
        sign_message(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "ETHEREUM",
            derivationPath: "m/44'/60'/0'/0/0",
            input: {
              message: "Hello from tcx-wasm!",
              signatureType: "PersonalSign",
            },
          })
        )
      );
      if (!ethMsg.signature?.startsWith("0x")) {
        throw new Error(`Bad ETH message signature: ${ethMsg.signature}`);
      }
      push({
        name: "Sign ETH Message (PersonalSign)",
        status: "pass",
        detail: `Signature: ${ethMsg.signature}`,
      });

      // 9. Sign TRON message
      push({ name: "Sign TRON Message", status: "running" });
      const tronMsg = JSON.parse(
        sign_message(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "TRON",
            input: {
              value: "Hello from tcx-wasm!",
              header: "TRON",
              version: 2,
            },
          })
        )
      );
      if (!tronMsg.signature?.startsWith("0x")) {
        throw new Error(`Bad TRON message signature: ${tronMsg.signature}`);
      }
      push({
        name: "Sign TRON Message",
        status: "pass",
        detail: `Signature: ${tronMsg.signature}`,
      });

      // ─── BTC ───
      // Derive all 4 BTC address types in a single call.
      push({ name: "Derive BTC Accounts (4 types)", status: "running" });
      const btcAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            derivations: [
              {
                chain: "BITCOIN",
                derivationPath: "m/44'/0'/0'/0/0",
                network: "MAINNET",
                segWit: "NONE",
              },
              {
                chain: "BITCOIN",
                derivationPath: "m/49'/0'/0'/0/0",
                network: "MAINNET",
                segWit: "P2WPKH",
              },
              {
                chain: "BITCOIN",
                derivationPath: "m/84'/0'/0'/0/0",
                network: "MAINNET",
                segWit: "VERSION_0",
              },
              {
                chain: "BITCOIN",
                derivationPath: "m/86'/0'/0'/0/0",
                network: "MAINNET",
                segWit: "VERSION_1",
              },
            ],
          })
        )
      );
      const [btcLegacy, btcNested, btcNative, btcTaproot] = btcAccounts;
      if (!btcLegacy.address?.startsWith("1")) {
        throw new Error(`Bad P2PKH address: ${btcLegacy.address}`);
      }
      if (!btcNested.address?.startsWith("3")) {
        throw new Error(`Bad P2SH-P2WPKH address: ${btcNested.address}`);
      }
      if (!btcNative.address?.startsWith("bc1q")) {
        throw new Error(`Bad native segwit address: ${btcNative.address}`);
      }
      if (!btcTaproot.address?.startsWith("bc1p")) {
        throw new Error(`Bad taproot address: ${btcTaproot.address}`);
      }
      push({
        name: "Derive BTC Accounts (4 types)",
        status: "pass",
        detail: [
          `P2PKH:     ${btcLegacy.address}`,
          `P2SH-WPKH: ${btcNested.address}`,
          `Native:    ${btcNative.address}`,
          `Taproot:   ${btcTaproot.address}`,
        ].join("\n"),
      });

      // Sign a BTC testnet transaction (P2WPKH native segwit).
      push({ name: "Sign BTC TX (P2WPKH TESTNET)", status: "running" });
      const btcTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "BITCOIN",
            network: "TESTNET",
            segWit: "VERSION_0",
            derivationPath: "m/84'/1'/0'/0/0",
            input: {
              inputs: [
                {
                  txHash:
                    "cebc5c2b4f5533428ad0cca94e9bfefa6410a270ed1d7116e2ee8592494c66bd",
                  vout: 1,
                  amount: 100000,
                  address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95",
                  derivedPath: "m/84'/1'/0'/0/0",
                },
              ],
              to: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4",
              amount: 50000,
              fee: 20000,
              changeAddressIndex: 53,
            },
          })
        )
      );
      if (!btcTx.rawTx || !btcTx.txHash) {
        throw new Error(`Bad BTC tx result: ${JSON.stringify(btcTx)}`);
      }
      push({
        name: "Sign BTC TX (P2WPKH TESTNET)",
        status: "pass",
        detail: `txHash: ${btcTx.txHash}\nrawTx:  ${btcTx.rawTx.slice(0, 64)}...`,
      });

      // Sign a BIP-322 message using Native SegWit.
      push({ name: "Sign BTC Message (BIP-322)", status: "running" });
      const btcMsg = JSON.parse(
        sign_message(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "BITCOIN",
            network: "MAINNET",
            segWit: "VERSION_0",
            derivationPath: "m/84'/0'/0'",
            input: { message: "hello world" },
          })
        )
      );
      if (!btcMsg.signature) {
        throw new Error(`Missing BTC message signature: ${JSON.stringify(btcMsg)}`);
      }
      push({
        name: "Sign BTC Message (BIP-322)",
        status: "pass",
        detail: `Signature: ${btcMsg.signature.slice(0, 64)}...`,
      });

      // Sign a Taproot PSBT on testnet and auto-finalize it.
      push({ name: "Sign PSBT (Taproot TESTNET)", status: "running" });
      const psbtHex =
        "70736274ff0100db0200000001fa4c8d58b9b6c56ed0b03f78115246c99eb70f99b837d7b4162911d1016cda340200000000fdffffff0350c30000000000002251202114eda66db694d87ff15ddd5d3c4e77306b6e6dd5720cbd90cd96e81016c2b30000000000000000496a47626274340066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229ec20acf33c17e5a6c92cced9f1d530cccab7aa3e53400456202f02fac95e9c481fa00d47b1700000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233d80f03000001012be3bf1d00000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23301172066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e00000000";
      const psbtResult = JSON.parse(
        sign_psbt(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "BITCOIN",
            network: "TESTNET",
            derivationPath: "m/86'/1'/0'",
            input: { psbt: psbtHex, autoFinalize: true },
          })
        )
      );
      if (!psbtResult.psbt || psbtResult.psbt === psbtHex) {
        throw new Error(`PSBT not signed: ${JSON.stringify(psbtResult)}`);
      }
      push({
        name: "Sign PSBT (Taproot TESTNET)",
        status: "pass",
        detail: `Signed PSBT: ${psbtResult.psbt.slice(0, 96)}...`,
      });

      // Batch-sign the same PSBT via sign_psbts.
      push({ name: "Sign PSBTs (batch)", status: "running" });
      const psbtsResult = JSON.parse(
        sign_psbts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "BITCOIN",
            network: "TESTNET",
            derivationPath: "m/86'/1'/0'",
            input: { psbts: [psbtHex], autoFinalize: true },
          })
        )
      );
      if (
        !Array.isArray(psbtsResult.psbts) ||
        psbtsResult.psbts.length !== 1 ||
        psbtsResult.psbts[0] === psbtHex
      ) {
        throw new Error(`Bad batch PSBT result: ${JSON.stringify(psbtsResult)}`);
      }
      push({
        name: "Sign PSBTs (batch)",
        status: "pass",
        detail: `Returned ${psbtsResult.psbts.length} signed PSBT(s)`,
      });

      // ─── BCH / LTC / DOGE / COSMOS / EOS ───
      // Derive accounts for the additional secp256k1 chains in one call.
      push({ name: "Derive Accounts (multi-chain)", status: "running" });
      const multiDerivations = [
        { chain: "BITCOINCASH", derivationPath: "m/44'/145'/0'/0/0", network: "MAINNET", segWit: "NONE" },
        { chain: "LITECOIN", derivationPath: "m/44'/2'/0'/0/0", network: "MAINNET", segWit: "NONE" },
        { chain: "DOGECOIN", derivationPath: "m/44'/3'/0'/0/0", network: "MAINNET", segWit: "NONE" },
        { chain: "COSMOS", derivationPath: "m/44'/118'/0'/0/0", chainId: "cosmoshub-4", network: "MAINNET" },
        { chain: "EOS", derivationPath: "m/44'/194'/0'/0/0", network: "MAINNET" },
      ];
      const multiAccounts: any[] = [];
      for (const d of multiDerivations) {
        try {
          const one = JSON.parse(
            derive_accounts(
              JSON.stringify({
                keystoreJson,
                key: TEST_PRF_KEY,
                derivations: [d],
              })
            )
          );
          multiAccounts.push(one[0]);
        } catch (e) {
          throw new Error(`Derive failed for ${d.chain}: ${String(e)}`);
        }
      }
      const [bchAcct, ltcAcct, dogeAcct, cosmosAcct, eosAcct] = multiAccounts;
      if (
        !bchAcct.address?.startsWith("bitcoincash:") &&
        !bchAcct.address?.startsWith("q")
      ) {
        throw new Error(`Bad BCH address: ${bchAcct.address}`);
      }
      if (!ltcAcct.address?.startsWith("L")) {
        throw new Error(`Bad LTC address: ${ltcAcct.address}`);
      }
      if (!dogeAcct.address?.startsWith("D")) {
        throw new Error(`Bad DOGE address: ${dogeAcct.address}`);
      }
      if (!cosmosAcct.address?.startsWith("cosmos1")) {
        throw new Error(`Bad COSMOS address: ${cosmosAcct.address}`);
      }
      if (!eosAcct.address?.startsWith("EOS")) {
        throw new Error(`Bad EOS address: ${eosAcct.address}`);
      }
      push({
        name: "Derive Accounts (multi-chain)",
        status: "pass",
        detail: [
          `BCH:    ${bchAcct.address}`,
          `LTC:    ${ltcAcct.address}`,
          `DOGE:   ${dogeAcct.address}`,
          `COSMOS: ${cosmosAcct.address}`,
          `EOS:    ${eosAcct.address}`,
        ].join("\n"),
      });

      // Sign a Cosmos transaction (sha256 → secp256k1 ECDSA, base64-encoded).
      push({ name: "Sign COSMOS TX", status: "running" });
      const cosmosTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "COSMOS",
            derivationPath: "m/44'/118'/0'/0/0",
            input: {
              rawData:
                "0a91010a8e010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126e0a2d636f736d6f733175616d6e346b74706d657332656664663671666837386d356365646b66637467617436657661122d636f736d6f73316a30636c726371727a636135326c6167707a3237687774713734776c327265353438346177681a0e0a057561746f6d1205313030303012680a510a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a210232c1ef21d73c19531b0aa4e863cf397c2b982b2f958f60cdb62969824c096d6512040a02080118930312130a0d0a057561746f6d12043230303410b1f2041a0b636f736d6f736875622d34208cb201",
            },
          })
        )
      );
      if (!cosmosTx.signature) {
        throw new Error(`Missing COSMOS signature: ${JSON.stringify(cosmosTx)}`);
      }
      push({
        name: "Sign COSMOS TX",
        status: "pass",
        detail: `Signature (base64): ${cosmosTx.signature}`,
      });

      // Sign EOS transactions (canonical secp256k1 with K1 base58 encoding).
      push({ name: "Sign EOS TX", status: "running" });
      const eosTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "EOS",
            derivationPath: "m/44'/194'/0'/0/0",
            input: {
              chainId:
                "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
              txHexs: [
                "2b03b26547b625edc1c6000000000100a6823403ea3055000000572d3ccdcd0130069b34b2a9a48b00000000a8ed32322130069b34b2a9a48b10425e79aa47b374640000000000000004454f53000000000000",
              ],
            },
          })
        )
      );
      if (
        !eosTx.sigData ||
        eosTx.sigData.length !== 1 ||
        !eosTx.sigData[0].signature?.startsWith("SIG_K1_")
      ) {
        throw new Error(`Bad EOS tx result: ${JSON.stringify(eosTx)}`);
      }
      push({
        name: "Sign EOS TX",
        status: "pass",
        detail: `${eosTx.sigData[0].signature}\nhash: ${eosTx.sigData[0].hash}`,
      });

      // Sign an EOS message (sha256 over data, then canonical secp256k1).
      push({ name: "Sign EOS Message", status: "running" });
      const eosMsg = JSON.parse(
        sign_message(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "EOS",
            derivationPath: "m/44'/194'/0'/0/0",
            input: { data: "Hello from tcx-wasm EOS!" },
          })
        )
      );
      if (!eosMsg.signature?.startsWith("SIG_K1_")) {
        throw new Error(`Bad EOS msg signature: ${eosMsg.signature}`);
      }
      push({
        name: "Sign EOS Message",
        status: "pass",
        detail: `Signature: ${eosMsg.signature}`,
      });

      // ─── TEZOS / TON (Ed25519 chains) ───
      // V5R1 wallet code, used by TON to derive the wallet contract address.
      const TON_V5R1_CODE =
        "te6ccgECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNA=";

      // Derive Tezos (tz1...) and TON (mainnet base64-url, V5R1) accounts.
      push({ name: "Derive TEZOS + TON Accounts", status: "running" });
      const ed25519Accounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            derivations: [
              { chain: "TEZOS", derivationPath: "m/44'/1729'/0'/0'", network: "MAINNET" },
              {
                chain: "TON",
                derivationPath: "m/44'/607'/0'",
                network: "MAINNET",
                contractCode: TON_V5R1_CODE,
              },
            ],
          })
        )
      );
      const [tezosAcct, tonAcct] = ed25519Accounts;
      if (!tezosAcct.address?.startsWith("tz1")) {
        throw new Error(`Bad TEZOS address: ${tezosAcct.address}`);
      }
      if (!tonAcct.address || tonAcct.address.length === 0) {
        throw new Error(`Bad TON address: ${tonAcct.address}`);
      }
      push({
        name: "Derive TEZOS + TON Accounts",
        status: "pass",
        detail: `TEZOS: ${tezosAcct.address}\nTON:   ${tonAcct.address}`,
      });

      // Sign a TEZOS transaction (Ed25519 over Blake2b watermark|raw_data).
      push({ name: "Sign TEZOS TX", status: "running" });
      const tezosTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "TEZOS",
            derivationPath: "m/44'/1729'/0'/0'",
            input: {
              rawData:
                "1234798e6f1d4ee9bf65bdf6803a4ec59b7d83373b39e8e4e7d5b8f56a8002ee6c00aff7f8a3a301a8b1ee5e2bcd0ec7c4d61c4d6f6502b903bcd105d10764000001976e6c0a0c8d8d8a8e89d8c0e0e62b8c5d6c6e7c7e6f6e1c4c8c4f7e6c4c8e7e6c4c5c6e7c7c8c9c0c1c2c3c4c5c6c70",
            },
          })
        )
      );
      if (!tezosTx.signature || !tezosTx.edsig?.startsWith("edsig")) {
        throw new Error(`Bad TEZOS tx result: ${JSON.stringify(tezosTx)}`);
      }
      push({
        name: "Sign TEZOS TX",
        status: "pass",
        detail: `edsig:  ${tezosTx.edsig}\nsbytes: ${tezosTx.sbytes.slice(0, 64)}...`,
      });

      // ─── POLKADOT / KUSAMA (sr25519, sp-core ss58) ───
      push({ name: "Derive POLKADOT + KUSAMA Accounts", status: "running" });
      const substrateAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            derivations: [
              { chain: "POLKADOT", derivationPath: "//imToken//polkadot/0", network: "MAINNET" },
              { chain: "KUSAMA", derivationPath: "//imToken//kusama/0", network: "MAINNET" },
            ],
          })
        )
      );
      const [polkadotAcct, kusamaAcct] = substrateAccounts;
      if (!polkadotAcct.address || polkadotAcct.address.length === 0) {
        throw new Error(`Bad POLKADOT address: ${polkadotAcct.address}`);
      }
      if (!kusamaAcct.address || kusamaAcct.address.length === 0) {
        throw new Error(`Bad KUSAMA address: ${kusamaAcct.address}`);
      }
      push({
        name: "Derive POLKADOT + KUSAMA Accounts",
        status: "pass",
        detail: `POLKADOT: ${polkadotAcct.address}\nKUSAMA:   ${kusamaAcct.address}`,
      });

      // ─── NERVOS / CKB ───
      // Derive a CKB account.
      push({ name: "Derive NERVOS Account", status: "running" });
      const ckbAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            derivations: [
              {
                chain: "NERVOS",
                derivationPath: "m/44'/309'/0'/0/0",
                network: "MAINNET",
              },
            ],
          })
        )
      );
      const [ckbAcct] = ckbAccounts;
      if (!ckbAcct.address?.startsWith("ckb")) {
        throw new Error(`Bad NERVOS address: ${ckbAcct.address}`);
      }
      push({
        name: "Derive NERVOS Account",
        status: "pass",
        detail: `NERVOS: ${ckbAcct.address}`,
      });

      // Sign a TON transaction (Ed25519 over the raw 32-byte hash).
      push({ name: "Sign TON TX", status: "running" });
      const tonTx = JSON.parse(
        sign_tx(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            chain: "TON",
            derivationPath: "m/44'/607'/0'",
            input: {
              hash: "0xd356774c21d6a6e2c651a5255f3f876fa973f1cfb7dce941c14ecabc2b1511d0",
            },
          })
        )
      );
      if (!tonTx.signature?.startsWith("0x") || tonTx.signature.length !== 130) {
        throw new Error(`Bad TON signature: ${tonTx.signature}`);
      }
      push({
        name: "Sign TON TX",
        status: "pass",
        detail: `Signature: ${tonTx.signature}`,
      });

      // 10. Cache keystore & derive without explicit keystoreJson
      push({ name: "Cache Keystore + Derive", status: "running" });
      cache_keystore(keystoreJson);
      const cachedAccounts = JSON.parse(
        derive_accounts(
          JSON.stringify({
            key: TEST_PRF_KEY,
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

      // ─── Message API ───
      // derive_message_key_pair: Derives a NIP-44 key pair from the keystore
      // mnemonic at path m/44'/1237'/0'/0/0 (Nostr BIP-44). Returns the
      // x-only public key and caches the secret key in WASM memory for
      // subsequent encrypt_message / decrypt_message calls.
      push({ name: "derive_message_key_pair", status: "running" });
      const messageKeyPair = JSON.parse(
        derive_message_key_pair(
          JSON.stringify({
            keystoreJson,
            key: TEST_PRF_KEY,
            // derivationPath: "m/44'/1237'/0'/0/0", // optional, this is the default
          })
        )
      );
      if (!messageKeyPair.pubkey || messageKeyPair.pubkey.length !== 64) {
        throw new Error(`Bad message pubkey: ${messageKeyPair.pubkey}`);
      }
      push({
        name: "derive_message_key_pair",
        status: "pass",
        detail: `Pubkey (x-only, 32 bytes hex): ${messageKeyPair.pubkey}`,
      });

      // encrypt_message: Encrypts plaintext using NIP-44 v2 with the cached
      // secret key and a caller-supplied server public key. Must call
      // derive_message_key_pair first to populate the cached key.
      // Input:  { serverPubkey: string, plaintext: string }
      // Output: { encryptedContent: string } (base64 NIP-44 payload)
      push({ name: "encrypt_message", status: "running" });
      const plaintext = "Hello from tcx-wasm message test!";
      const encrypted = JSON.parse(
        encrypt_message(JSON.stringify({ serverPubkey: TEST_SERVER_PUBKEY, plaintext }))
      );
      if (!encrypted.encryptedContent) {
        throw new Error("Missing encryptedContent");
      }
      push({
        name: "encrypt_message",
        status: "pass",
        detail: `Input:  "${plaintext}"\nOutput: ${encrypted.encryptedContent.slice(0, 48)}...`,
      });

      // decrypt_message: Decrypts a NIP-44 v2 payload back to plaintext.
      // Uses the same cached secret key + caller-supplied server public key.
      // Input:  { serverPubkey: string, encryptedContent: string }
      // Output: { plaintext: string }
      push({ name: "decrypt_message", status: "running" });
      const decrypted = JSON.parse(
        decrypt_message(
          JSON.stringify({ serverPubkey: TEST_SERVER_PUBKEY, encryptedContent: encrypted.encryptedContent })
        )
      );
      if (decrypted.plaintext !== plaintext) {
        throw new Error(
          `Decrypt mismatch: ${decrypted.plaintext} !== ${plaintext}`
        );
      }
      push({
        name: "decrypt_message",
        status: "pass",
        detail: `Input:  ${encrypted.encryptedContent.slice(0, 48)}...\nOutput: "${decrypted.plaintext}"`,
      });

      // sign_message_event: Signs a Nostr event (NIP-01) with Schnorr/BIP-340.
      // Uses the cached secret key from derive_message_key_pair.
      // Input:  { event: { createdAt, kind, tags, content }, recipientPubkey? }
      // Output: Full signed event { id, pubkey, createdAt, kind, tags, content, sig }
      push({ name: "sign_message_event", status: "running" });
      const now = Math.floor(Date.now() / 1000);
      const signedEvent = JSON.parse(
        sign_message_event(
          JSON.stringify({
            event: {
              createdAt: now,
              kind: 1,
              tags: [],
              content: encrypted.encryptedContent,
            },
          })
        )
      );
      if (
        !signedEvent.id ||
        !signedEvent.sig ||
        signedEvent.id.length !== 64 ||
        signedEvent.sig.length !== 128
      ) {
        throw new Error(`Bad signed event: ${JSON.stringify(signedEvent)}`);
      }
      if (signedEvent.pubkey !== messageKeyPair.pubkey) {
        throw new Error("Signed event pubkey mismatch");
      }
      push({
        name: "sign_message_event",
        status: "pass",
        detail: JSON.stringify(signedEvent, null, 2),
      });

      // sign_message_event (seal+wrap): NIP-59 Gift Wrapping.
      // When recipientPubkey is provided, returns a kind:1059 gift-wrapped event.
      push({ name: "sign_message_event (seal+wrap)", status: "running" });
      const wrappedEvent = JSON.parse(
        sign_message_event(
          JSON.stringify({
            recipientPubkey: TEST_SERVER_PUBKEY,
            event: {
              createdAt: now,
              kind: 1,
              tags: [],
              content: "secret message via gift wrap",
            },
          })
        )
      );
      if (wrappedEvent.kind !== 1059) {
        throw new Error(`Expected kind 1059, got ${wrappedEvent.kind}`);
      }
      if (
        !wrappedEvent.id ||
        !wrappedEvent.sig ||
        wrappedEvent.id.length !== 64 ||
        wrappedEvent.sig.length !== 128
      ) {
        throw new Error(`Bad wrapped event: ${JSON.stringify(wrappedEvent)}`);
      }
      if (wrappedEvent.pubkey === messageKeyPair.pubkey) {
        throw new Error("Wrapped event pubkey should differ from sender (ephemeral key)");
      }
      const pTag = wrappedEvent.tags.find((t: string[]) => t[0] === "p");
      if (!pTag || pTag[1] !== TEST_SERVER_PUBKEY) {
        throw new Error("Wrapped event missing correct p-tag for recipient");
      }
      push({
        name: "sign_message_event (seal+wrap)",
        status: "pass",
        detail: JSON.stringify(wrappedEvent, null, 2),
      });

      // sign_message_event + decrypt: Verify the signed event's encrypted
      // content can be decrypted back, demonstrating the full roundtrip:
      // plaintext -> encrypt -> sign event -> decrypt content.
      push({ name: "sign + encrypt/decrypt roundtrip", status: "running" });
      const eventDecrypted = JSON.parse(
        decrypt_message(
          JSON.stringify({ serverPubkey: TEST_SERVER_PUBKEY, encryptedContent: signedEvent.content })
        )
      );
      if (eventDecrypted.plaintext !== plaintext) {
        throw new Error(
          `Event content decrypt mismatch: ${eventDecrypted.plaintext} !== ${plaintext}`
        );
      }
      push({
        name: "sign + encrypt/decrypt roundtrip",
        status: "pass",
        detail: `Encrypted content in event decrypted back to: "${eventDecrypted.plaintext}"`,
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
          Browser-side WASM integration tests for keystore, account derivation,
          ETH / TRON / BTC transaction, message & PSBT signing, and Message API
          (derive_message_key_pair, encrypt_message, decrypt_message,
          sign_message_event).
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
