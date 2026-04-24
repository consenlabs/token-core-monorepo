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

      // 4. Export mnemonic
      push({ name: "Export Mnemonic", status: "running" });
      const exported = JSON.parse(
        export_mnemonic(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
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

      // 5. Derive ETH + TRON accounts in one call
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

      // 8. Batch sign (ETH + TRON)
      push({ name: "Sign Batch TXs (ETH + TRON)", status: "running" });
      const batchResults = JSON.parse(
        sign_txs(
          JSON.stringify({
            keystoreJson,
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
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
            prfKey: TEST_PRF_KEY,
            chain: "BITCOIN",
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
            prfKey: TEST_PRF_KEY,
            chain: "BITCOIN",
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

      // 10. Cache keystore & derive without explicit keystoreJson
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
            prfKey: TEST_PRF_KEY,
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
