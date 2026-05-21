import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";

const _require = createRequire(import.meta.url);
const cliVersion = (_require("../package.json") as { version: string })
  .version;

import {
  buildBlockingBroadcastPolicyWarning,
  buildBlockingSignPolicyWarning,
  buildDraftFromParsed,
  renderBroadcastTimeoutMessage,
} from "./cli/helpers";
import { loadCliDotEnv } from "./cli/load-env";
import {
  renderAnalysisText,
  renderBroadcastResultText,
  renderPolicyWarningText,
  renderSignedResultText,
  renderWalletListText,
  renderWalletText,
} from "./cli/render";
import {
  broadcastSignedTransactionNode,
  createTokenCoreWalletNode,
  importTokenCoreWalletNode,
  initTokenCoreNodeWasm,
  signDraftTransactionNode,
} from "./cli/tokencore-node";
import {
  listManagedWallets,
  readManagedWalletFile,
  resolveManagedWallet,
  saveManagedWallet,
} from "./cli/wallet-store";
import { buildFallbackAiSummary, generateAiSummary } from "./lib/ai";
import { buildAnalysisResult } from "./lib/analysis";
import {
  getChainConfig,
  getChainKeyById,
  parseDemoChainKey,
  resolveTargetChainKey,
} from "./lib/chains";
import {
  NATIVE_TRANSFER_VERIFICATION,
  decodeParsedInput,
  inferChainKey,
  parseRawTransactionInput,
  resolveContractVerification,
} from "./lib/decode";
import { evaluatePolicies, parsePolicyDocument } from "./lib/policy";
import { simulateTransaction } from "./lib/simulate";
import type { AnalysisResult, DemoChainKey } from "./lib/types";

interface ParsedArgs {
  positionals: string[];
  options: Record<string, string>;
  flags: Set<string>;
}

const requiredPolicyErrorMessage =
  "analyze、sign、broadcast 皆必須提供 --policy（可為 JSON 檔案路徑或 inline JSON 字串，以 { 開頭自動判斷）。";
const supportedChainList = "eth-sepolia、base-sepolia";

function printHelp() {
  console.log(`TokenCore CLI v${cliVersion}

用法：
  npm run cli -- wallet create --chain eth-sepolia|base-sepolia --name <name> [--password <password>]
  npm run cli -- wallet import --chain eth-sepolia|base-sepolia --wallet <path> [--name <name>] [--password <password>]
  npm run cli -- wallet list
  npm run cli -- analyze  --chain eth-sepolia|base-sepolia --input '<tx-json|signed-rawtx>' --policy '<json-file|inline-json>' [--no-ai]
  npm run cli -- sign     --chain eth-sepolia|base-sepolia --input '<tx-json>' --wallet <wallet-name|path> --policy '<json-file|inline-json>' [--password <password>]
  npm run cli -- broadcast --chain eth-sepolia|base-sepolia --input '<tx-json|signed-rawtx>' --policy '<json-file|inline-json>' [--wallet <wallet-name|path>] [--password <password>] [--wait-timeout <ms>]

必填參數（analyze / sign / broadcast）：
  --chain eth-sepolia|base-sepolia        目標鏈
  --input '<tx-json|signed-rawtx>'        交易草稿 JSON 或已簽 raw transaction（與 --input-file 擇一）
  --policy '<json-file|inline-json>'      policy 檔案路徑 或 inline JSON 字串（以 { 開頭自動視為 JSON）

可選參數：
  --input-file <path>                     從檔案讀取 --input 內容
  --wallet <wallet-name|path>             錢包識別碼或路徑（sign / broadcast 未簽名 tx 時必填）
  --password <password>
  --rp-id <value>
  --derivation-path <value>
  --wait-timeout <ms>                     broadcast 等待 receipt 的逾時毫秒數（預設 180000）
  --no-ai                                 analyze 時跳過 AI 摘要，直接使用本地規則摘要（加速分析）
  -h, --help                              顯示本說明

密碼讀取優先順序：
  1. --password
  2. TOKENCORE_CLI_PASSWORD
  3. 互動式隱藏輸入`);
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options: Record<string, string> = {};
  const flags = new Set<string>();

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === "-h") {
      flags.add("help");
      continue;
    }
    if (!current.startsWith("--")) {
      positionals.push(current);
      continue;
    }

    const key = current.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      flags.add(key);
      continue;
    }

    options[key] = next;
    index += 1;
  }

  return { positionals, options, flags };
}

type ChainRequiredCommand =
  | "analyze"
  | "sign"
  | "broadcast"
  | "wallet create"
  | "wallet import";

function buildMissingChainErrorMessage(command: ChainRequiredCommand) {
  const examples: Record<ChainRequiredCommand, string> = {
    analyze:
      "npm run cli -- analyze --chain eth-sepolia --input-file ./tx.json --policy ./src/policies/default-risk-policy.json",
    sign: "npm run cli -- sign --chain eth-sepolia --input-file ./tx.json --wallet <wallet-id-or-path> --policy ./src/policies/default-risk-policy.json",
    broadcast:
      "npm run cli -- broadcast --chain eth-sepolia --input '0x02f8...' --policy ./src/policies/default-risk-policy.json",
    "wallet create":
      "npm run cli -- wallet create --chain eth-sepolia --name my-wallet",
    "wallet import":
      "npm run cli -- wallet import --chain eth-sepolia --wallet ./my-wallet.wallet.json",
  };

  return [
    `缺少必要參數 --chain。合法值：${supportedChainList}。`,
    "範例：",
    ...Object.entries(examples).map(([cmd, ex]) => `- ${cmd}: ${ex}`),
    `目前命令：${command}`,
  ].join("\n");
}

function requireChainOption(
  args: ParsedArgs,
  command: ChainRequiredCommand,
): DemoChainKey {
  const inputValue = args.options.chain?.trim();
  const chainKey = parseDemoChainKey(inputValue);
  if (!chainKey) throw new Error(buildMissingChainErrorMessage(command));
  return chainKey;
}

function requireOption(args: ParsedArgs, key: string) {
  const value = args.options[key];
  if (!value) throw new Error(`缺少必要參數 --${key}`);
  return value;
}

function ensurePolicyOptionProvided(args: ParsedArgs) {
  if (!args.options.policy?.trim()) {
    throw new Error(requiredPolicyErrorMessage);
  }
}

class MaskedWritable extends Writable {
  muted = false;

  override _write(
    chunk: string | Uint8Array,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ) {
    if (!this.muted) {
      process.stdout.write(chunk, encoding);
    }
    callback();
  }
}

async function promptHiddenPassword(promptText: string) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("未提供 --password，且目前終端機不支援互動式隱藏輸入。");
  }

  const output = new MaskedWritable();
  const rl = createInterface({
    input: process.stdin,
    output,
    terminal: true,
  });

  try {
    output.write(promptText);
    output.muted = true;
    const password = await rl.question("");
    output.muted = false;
    process.stdout.write("\n");

    if (!password.trim()) {
      throw new Error("密碼不可空白。");
    }

    return password;
  } finally {
    output.muted = false;
    rl.close();
  }
}

async function readPasswordArg(args: ParsedArgs, promptText: string) {
  const directPassword = args.options.password;
  if (directPassword) return directPassword;
  const envPassword = process.env.TOKENCORE_CLI_PASSWORD;
  if (envPassword) return envPassword;
  return promptHiddenPassword(promptText);
}

async function readInputArg(args: ParsedArgs) {
  const directInput = args.options.input;
  if (directInput) return directInput;

  const inputFile = args.options["input-file"];
  if (inputFile) {
    return readFile(path.resolve(inputFile), "utf8");
  }

  throw new Error("請提供 --input 或 --input-file。");
}

async function readPolicyArg(args: ParsedArgs) {
  const raw = args.options.policy?.trim();
  if (!raw) throw new Error(requiredPolicyErrorMessage);

  // Auto-detect: inline JSON starts with '{'; otherwise treat as a file path.
  if (raw.startsWith("{")) {
    return parsePolicyDocument(raw);
  }

  const content = await readFile(path.resolve(raw), "utf8");
  return parsePolicyDocument(content);
}

async function buildAnalysisWithPolicy(
  args: ParsedArgs,
  rawInput: string,
  preferredChainKey?: DemoChainKey,
): Promise<AnalysisResult> {
  const policyDocument = await readPolicyArg(args);
  const parsed = await parseRawTransactionInput(rawInput);
  const chainKey =
    preferredChainKey ?? (parsed.chainId ? inferChainKey(parsed) : "sepolia");

  if (preferredChainKey && parsed.chainId) {
    const parsedChainKey = getChainKeyById(parsed.chainId);
    if (parsedChainKey && parsedChainKey !== preferredChainKey) {
      console.warn(
        `⚠️  注意：--chain 指定了 ${getChainConfig(preferredChainKey).label}，` +
          `但 input.chainId ${parsed.chainId} 對應 ${getChainConfig(parsedChainKey).label}。` +
          `分析將以 --chain 為準。`,
      );
    }
  }

  const isNativeTransfer = !parsed.data || parsed.data === "0x";
  const verification = isNativeTransfer
    ? NATIVE_TRANSFER_VERIFICATION
    : await resolveContractVerification(chainKey, parsed.to);
  const action = await decodeParsedInput(chainKey, parsed, verification);
  const simulation = await simulateTransaction(chainKey, parsed, action);
  const policyViolations = evaluatePolicies({
    document: policyDocument,
    chainKey,
    parsed,
    action,
    verification,
    simulation,
  }).violations;

  return buildAnalysisResult({
    chainKey,
    chainLabel: getChainConfig(chainKey).label,
    action,
    verification,
    simulation,
    policyViolations,
  });
}

function assertChainCompatibility(
  resolvedChainKey: DemoChainKey,
  parsedChainId: number | undefined,
  operation: "sign" | "broadcast",
) {
  if (!parsedChainId) return;
  const parsedChainKey = getChainKeyById(parsedChainId);
  if (parsedChainKey && parsedChainKey !== resolvedChainKey) {
    throw new Error(
      `--chain 指定了 ${getChainConfig(resolvedChainKey).label}，` +
        `但 input.chainId ${parsedChainId} 對應 ${getChainConfig(parsedChainKey).label}。` +
        `${operation === "sign" ? "簽名" : "廣播"}已停止，請確認 --chain 與交易的 chainId 一致。`,
    );
  }
}

async function handleAnalyze(args: ParsedArgs) {
  const chainKey = requireChainOption(args, "analyze");
  ensurePolicyOptionProvided(args);
  const rawInput = await readInputArg(args);
  const analysis = await buildAnalysisWithPolicy(args, rawInput, chainKey);

  if (args.flags.has("no-ai")) {
    analysis.aiSummary = buildFallbackAiSummary(analysis);
  } else {
    try {
      const aiResult = await generateAiSummary(analysis);
      if (aiResult) {
        analysis.aiSummary = aiResult.text;
        analysis.aiProvider = aiResult.provider;
      } else {
        analysis.aiSummary = buildFallbackAiSummary(analysis);
      }
    } catch {
      analysis.aiSummary = buildFallbackAiSummary(analysis);
    }
  }

  console.log(renderAnalysisText(analysis));
}

async function handleWalletCreate(args: ParsedArgs) {
  const chainKey = requireChainOption(args, "wallet create");
  await initTokenCoreNodeWasm();
  const name = args.options.name?.trim() || `wallet-${Date.now()}`;
  const password = await readPasswordArg(args, "請輸入建立錢包密碼：");
  const rpId = args.options["rp-id"];

  const result = await createTokenCoreWalletNode({
    name,
    password,
    chainKey,
    rpId,
  });
  const filePath = await saveManagedWallet(result.wallet);

  console.log(renderWalletText(result.wallet, filePath));
}

async function handleWalletImport(args: ParsedArgs) {
  const chainKey = requireChainOption(args, "wallet import");
  await initTokenCoreNodeWasm();
  const walletFilePath = requireOption(args, "wallet");
  const providedName = args.options.name?.trim();
  const password = await readPasswordArg(args, "請輸入錢包密碼：");
  const derivationPath = args.options["derivation-path"];
  const importedWallet = await readManagedWalletFile(walletFilePath);
  const wallet = await importTokenCoreWalletNode({
    name:
      providedName ||
      importedWallet.name ||
      path.basename(walletFilePath).replace(/\.wallet\.json$/i, "") ||
      "imported-wallet",
    password,
    chainKey,
    keystoreJson: importedWallet.keystoreJson,
    derivationPath: derivationPath || importedWallet.derivationPath,
  });
  const filePath = await saveManagedWallet(wallet);

  console.log(renderWalletText(wallet, filePath));
}

async function handleWalletList() {
  const wallets = await listManagedWallets();
  console.log(renderWalletListText(wallets));
}

async function handleSign(args: ParsedArgs) {
  ensurePolicyOptionProvided(args);
  await initTokenCoreNodeWasm();
  const rawInput = await readInputArg(args);
  const parsed = await parseRawTransactionInput(rawInput);
  if (parsed.type === "signedRaw") {
    throw new Error("這筆輸入已經是 signed raw transaction，不需要再次簽名。");
  }

  const explicitChainKey = requireChainOption(args, "sign");
  assertChainCompatibility(explicitChainKey, parsed.chainId, "sign");

  const walletSelector = requireOption(args, "wallet");
  const { wallet } = await resolveManagedWallet(walletSelector);
  const chainKey = resolveTargetChainKey({
    explicitChainKey,
    parsedChainId: parsed.chainId,
    walletChainId: wallet.chainId,
  });
  let policyWarning = "";
  try {
    const analysis = await buildAnalysisWithPolicy(args, rawInput, chainKey);
    policyWarning = renderPolicyWarningText({
      operation: "sign",
      analysis,
    });
    if (analysis.policyViolations.length > 0) {
      console.log(
        [
          buildBlockingSignPolicyWarning(policyWarning),
          "",
          "偵測到 policy 不符合項目，已停止簽名。",
        ].join("\n"),
      );
      return;
    }
  } catch (error) {
    policyWarning = renderPolicyWarningText({
      operation: "sign",
      errorMessage:
        error instanceof Error
          ? error.message
          : "未知錯誤，無法完成 policy 預檢。",
    });
  }

  const password = await readPasswordArg(args, "請輸入簽名密碼：");
  const result = await signDraftTransactionNode(
    wallet,
    password,
    buildDraftFromParsed(chainKey, parsed, wallet.address),
    chainKey,
  );

  console.log(
    [
      policyWarning,
      "",
      renderSignedResultText({
        rawTransaction: result.rawTransaction,
        txHash: result.txHash,
      }),
    ]
      .filter(Boolean)
      .join("\n"),
  );
}

async function handleBroadcast(args: ParsedArgs) {
  ensurePolicyOptionProvided(args);
  const rawInput = await readInputArg(args);
  const parsed = await parseRawTransactionInput(rawInput);
  const explicitChainKey = requireChainOption(args, "broadcast");
  assertChainCompatibility(explicitChainKey, parsed.chainId, "broadcast");
  const waitTimeoutMs = args.options["wait-timeout"]
    ? Number(args.options["wait-timeout"])
    : undefined;

  if (parsed.type === "signedRaw") {
    const chainKey = explicitChainKey ?? inferChainKey(parsed);
    let policyWarning = "";
    try {
      const analysis = await buildAnalysisWithPolicy(args, rawInput, chainKey);
      policyWarning = renderPolicyWarningText({
        operation: "broadcast",
        analysis,
      });
      if (analysis.policyViolations.length > 0) {
        console.log(
          [
            buildBlockingBroadcastPolicyWarning(policyWarning),
            "",
            "偵測到 policy 不符合項目，已停止廣播。",
          ].join("\n"),
        );
        return;
      }
    } catch (error) {
      policyWarning = renderPolicyWarningText({
        operation: "broadcast",
        errorMessage:
          error instanceof Error
            ? error.message
            : "未知錯誤，無法完成 policy 預檢。",
      });
    }
    try {
      const result = await broadcastSignedTransactionNode(
        chainKey,
        parsed.raw as `0x${string}`,
        waitTimeoutMs,
      );
      console.log(
        [
          policyWarning,
          "",
          renderBroadcastResultText({
            chainKey,
            hash: result.hash,
            receipt: result.receipt,
          }),
        ]
          .filter(Boolean)
          .join("\n"),
      );
    } catch (error) {
      throw new Error(
        renderBroadcastTimeoutMessage(chainKey, error, policyWarning),
      );
    }
    return;
  }

  const walletSelector = requireOption(args, "wallet");
  const password = await readPasswordArg(args, "請輸入簽名密碼：");
  await initTokenCoreNodeWasm();
  const { wallet } = await resolveManagedWallet(walletSelector);
  const chainKey = resolveTargetChainKey({
    explicitChainKey,
    parsedChainId: parsed.chainId,
    walletChainId: wallet.chainId,
  });
  let policyWarning = "";
  try {
    const analysis = await buildAnalysisWithPolicy(args, rawInput, chainKey);
    policyWarning = renderPolicyWarningText({
      operation: "broadcast",
      analysis,
    });
    if (analysis.policyViolations.length > 0) {
      console.log(
        [
          buildBlockingBroadcastPolicyWarning(policyWarning),
          "",
          "偵測到 policy 不符合項目，已停止廣播。",
        ].join("\n"),
      );
      return;
    }
  } catch (error) {
    policyWarning = renderPolicyWarningText({
      operation: "broadcast",
      errorMessage:
        error instanceof Error
          ? error.message
          : "未知錯誤，無法完成 policy 預檢。",
    });
  }
  const signed = await signDraftTransactionNode(
    wallet,
    password,
    buildDraftFromParsed(chainKey, parsed, wallet.address),
    chainKey,
  );
  try {
    const result = await broadcastSignedTransactionNode(
      chainKey,
      signed.rawTransaction,
      waitTimeoutMs,
    );

    console.log(
      [
        policyWarning,
        "",
        renderSignedResultText({
          rawTransaction: signed.rawTransaction,
          txHash: signed.txHash,
        }),
        "",
        renderBroadcastResultText({
          chainKey,
          hash: result.hash,
          receipt: result.receipt,
        }),
      ].join("\n"),
    );
  } catch (error) {
    throw new Error(
      renderBroadcastTimeoutMessage(chainKey, error, policyWarning),
    );
  }
}

async function main() {
  await loadCliDotEnv();

  const args = parseArgs(process.argv.slice(2));
  const [command, subcommand] = args.positionals;

  if (!command || args.flags.has("help")) {
    printHelp();
    return;
  }

  if (command === "wallet") {
    if (subcommand === "create") {
      await handleWalletCreate(args);
      return;
    }
    if (subcommand === "import") {
      await handleWalletImport(args);
      return;
    }
    if (subcommand === "list") {
      await handleWalletList();
      return;
    }
    throw new Error("wallet 子命令僅支援 create、import、list。");
  }

  if (command === "analyze") {
    await handleAnalyze(args);
    return;
  }

  if (command === "sign") {
    await handleSign(args);
    return;
  }

  if (command === "broadcast") {
    await handleBroadcast(args);
    return;
  }

  throw new Error(`未知命令：${command}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "CLI 執行失敗。");
  process.exitCode = 1;
});
