import { formatUnits, parseUnits, type Address } from "viem";

import type {
  ContractVerificationStatus,
  DecodedAction,
  DemoChainKey,
  ParsedInput,
  PolicyDocument,
  PolicyRule,
  PolicyViolation,
  SimulationSummary,
} from "./types";

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isAddressRecord(
  value: unknown,
): value is Partial<Record<DemoChainKey, Address>> {
  if (!isObject(value)) return false;
  return Object.entries(value).every(
    ([key, currentValue]) =>
      (key === "sepolia" || key === "baseSepolia") &&
      typeof currentValue === "string" &&
      currentValue.startsWith("0x"),
  );
}

type RawPolicy = Record<string, unknown> & {
  id: string;
  name: string;
  type: string;
};

function ensurePolicyBase(policy: unknown): RawPolicy {
  if (!isObject(policy)) {
    throw new Error("每一條 policy 都必須是 JSON 物件。");
  }
  if (typeof policy.id !== "string" || typeof policy.name !== "string") {
    throw new Error("每一條 policy 都必須包含字串型別的 id 與 name。");
  }
  if (typeof policy.type !== "string") {
    throw new Error(`policy ${policy.id} 缺少 type。`);
  }

  return policy as RawPolicy;
}

function parsePolicyRule(policy: unknown): PolicyRule {
  const current = ensurePolicyBase(policy);

  switch (current.type) {
    case "requireVerifiedContract":
    case "requireSimulationSuccess":
    case "forbidUnknownFunction":
    case "forbidUnlimitedApproval":
    case "requireSwapMinimumOutput":
      return {
        id: current.id,
        name: current.name,
        description:
          typeof current.description === "string"
            ? current.description
            : undefined,
        enabled: typeof current.enabled === "boolean" ? current.enabled : true,
        type: current.type,
        level:
          current.level === "low" ||
          current.level === "medium" ||
          current.level === "high"
            ? current.level
            : "high",
      };
    case "maxAssetOut":
      if (
        (current.assetKind !== "native" && current.assetKind !== "erc20") ||
        typeof current.symbol !== "string" ||
        typeof current.decimals !== "number" ||
        typeof current.max !== "string"
      ) {
        throw new Error(`policy ${current.id} 的 maxAssetOut 格式不正確。`);
      }
      if (
        current.assetKind === "erc20" &&
        current.tokenAddressByChain !== undefined &&
        !isAddressRecord(current.tokenAddressByChain)
      ) {
        throw new Error(
          `policy ${current.id} 的 tokenAddressByChain 格式不正確。`,
        );
      }
      return {
        id: current.id,
        name: current.name,
        description:
          typeof current.description === "string"
            ? current.description
            : undefined,
        enabled: typeof current.enabled === "boolean" ? current.enabled : true,
        type: "maxAssetOut",
        level:
          current.level === "low" ||
          current.level === "medium" ||
          current.level === "high"
            ? current.level
            : "high",
        assetKind: current.assetKind,
        symbol: current.symbol,
        decimals: current.decimals,
        max: current.max,
        tokenAddressByChain: isAddressRecord(current.tokenAddressByChain)
          ? current.tokenAddressByChain
          : undefined,
      };
    default:
      throw new Error(`不支援的 policy type：${String(current.type)}`);
  }
}

export function parsePolicyDocument(raw: string): PolicyDocument {
  const parsed = JSON.parse(raw) as unknown;
  if (!isObject(parsed)) {
    throw new Error("Policy JSON 必須是物件。");
  }
  if (typeof parsed.name !== "string" || !Array.isArray(parsed.policies)) {
    throw new Error("Policy JSON 必須包含 name 與 policies 陣列。");
  }

  return {
    version: typeof parsed.version === "number" ? parsed.version : 1,
    name: parsed.name,
    description:
      typeof parsed.description === "string" ? parsed.description : undefined,
    policies: parsed.policies.map((policy) => parsePolicyRule(policy)),
  };
}

export function stringifyPolicyDocument(document: PolicyDocument) {
  return JSON.stringify(document, null, 2);
}

function parseUnsignedInteger(value: string | undefined) {
  if (!value || !/^\d+$/.test(value.trim())) return 0n;
  return BigInt(value.trim());
}

function parseStructFromArgs(action: DecodedAction) {
  const firstArg = action.argsSummary[0]?.value;
  if (!firstArg) return null;

  try {
    const parsed = JSON.parse(firstArg) as Record<string, unknown>;
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function getOutgoingRawAmount(
  policy: Extract<PolicyRule, { type: "maxAssetOut" }>,
  chainKey: DemoChainKey,
  parsed: ParsedInput,
  action: DecodedAction,
) {
  if (policy.assetKind === "native") {
    return parsed.value ?? 0n;
  }

  const expectedToken = policy.tokenAddressByChain?.[chainKey]?.toLowerCase();
  if (!expectedToken || action.functionName !== "transfer" || !parsed.to) {
    return 0n;
  }

  if (parsed.to.toLowerCase() !== expectedToken) {
    return 0n;
  }

  return parseUnsignedInteger(action.argsSummary[1]?.value);
}

function formatAssetAmount(
  rawAmount: bigint,
  decimals: number,
  symbol: string,
) {
  return `${formatUnits(rawAmount, decimals)} ${symbol}`;
}

function buildViolation(
  policy: PolicyRule,
  description: string,
): PolicyViolation {
  return {
    policyId: policy.id,
    policyName: policy.name,
    level: policy.level ?? "high",
    description,
  };
}

const HALF_MAX_UINT256 = 2n ** 255n;

export function evaluatePolicies(params: {
  document: PolicyDocument;
  chainKey: DemoChainKey;
  parsed: ParsedInput;
  action: DecodedAction;
  verification: ContractVerificationStatus;
  simulation: SimulationSummary;
}) {
  const violations: PolicyViolation[] = [];

  for (const policy of params.document.policies) {
    if (policy.enabled === false) continue;

    switch (policy.type) {
      case "requireVerifiedContract":
        if (
          params.action.kind !== "nativeTransfer" &&
          !params.verification.verified
        ) {
          violations.push(
            buildViolation(
              policy,
              "直接互動的目標合約目前查不到已驗證原始碼。",
            ),
          );
        }
        break;
      case "maxAssetOut": {
        const outgoingRawAmount = getOutgoingRawAmount(
          policy,
          params.chainKey,
          params.parsed,
          params.action,
        );
        const maxRawAmount = parseUnits(policy.max, policy.decimals);
        if (outgoingRawAmount > maxRawAmount) {
          violations.push(
            buildViolation(
              policy,
              `偵測到預計轉出 ${formatAssetAmount(outgoingRawAmount, policy.decimals, policy.symbol)}，超過 policy 上限 ${policy.max} ${policy.symbol}。`,
            ),
          );
        }
        break;
      }
      case "requireSimulationSuccess":
        if (!params.simulation.success) {
          violations.push(
            buildViolation(
              policy,
              `模擬未通過：${params.simulation.errorMessage ?? "未知錯誤"}`,
            ),
          );
        }
        break;
      case "forbidUnknownFunction":
        if (
          params.action.kind !== "nativeTransfer" &&
          (params.action.title.includes("未知") ||
            params.action.functionName === undefined)
        ) {
          violations.push(
            buildViolation(
              policy,
              "這筆交易的 selector / 函式用途尚未被完整辨識，不符合白名單可讀性要求。",
            ),
          );
        }
        break;
      case "forbidUnlimitedApproval": {
        const amount = parseUnsignedInteger(
          params.action.argsSummary[1]?.value,
        );
        if (
          params.action.functionName === "approve" &&
          amount >= HALF_MAX_UINT256
        ) {
          violations.push(
            buildViolation(
              policy,
              "偵測到近乎無限授權 approve，日後可能被持續扣款。",
            ),
          );
        }
        break;
      }
      case "requireSwapMinimumOutput": {
        const exactInputStruct = parseStructFromArgs(params.action);
        const minOut = parseUnsignedInteger(
          typeof exactInputStruct?.amountOutMinimum === "string"
            ? exactInputStruct.amountOutMinimum
            : undefined,
        );
        if (
          (params.action.functionName?.includes("swap") ||
            params.action.functionName === "exactInputSingle") &&
          minOut === 0n
        ) {
          violations.push(
            buildViolation(
              policy,
              "swap 的 amountOutMinimum 為 0，代表幾乎沒有滑點保護。",
            ),
          );
        }
        break;
      }
    }
  }

  return { violations };
}
