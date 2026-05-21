import { describe, expect, it } from "vitest";

import type { StoredTokenCoreWallet } from "../../lib/types";
import {
  parseManagedWalletFile,
  serializeManagedWalletFile,
} from "../../lib/wallet-file";

describe("wallet-file helpers", () => {
  const wallet: StoredTokenCoreWallet = {
    id: "wallet-1",
    name: "demo-wallet",
    address: "0x1234567890123456789012345678901234567890",
    keystoreJson:
      '{"userId":"demo-wallet","credentialId":"demo-wallet-sepolia","rpId":"localhost","encryptedMnemonic":"abc","mnemonicIv":"def","createdAt":1,"identity":{"encAuthKey":{"encStr":"1","nonce":"2"},"encKey":"3","identifier":"4","ipfsId":"5"}}',
    publicKey: "02abcdef",
    derivationPath: "m/44'/60'/0'/0/0",
    chainId: 11155111,
    createdAt: "2026-04-09T00:00:00.000Z",
  };

  it("serializes and parses managed wallet files", () => {
    const serialized = serializeManagedWalletFile(wallet);
    const parsed = parseManagedWalletFile(serialized);

    expect(parsed).toEqual(wallet);
  });

  it("keeps keystore json inside managed wallet file", () => {
    const serialized = serializeManagedWalletFile(wallet);
    const imported = parseManagedWalletFile(serialized);

    expect(imported.keystoreJson).toBe(wallet.keystoreJson);
    expect(imported.name).toBe(wallet.name);
  });

  it("rejects old raw keystore json format", () => {
    expect(() => parseManagedWalletFile(wallet.keystoreJson)).toThrow(
      "錢包檔格式不正確。",
    );
  });
});
