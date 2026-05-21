import type { Address, Hex } from "viem";

export type DemoChainKey = "sepolia" | "baseSepolia";

export type TemplateKind =
  | "nativeTransfer"
  | "erc20Transfer"
  | "erc20Approve"
  | "wethDeposit"
  | "wethWithdraw"
  | "uniswapV2SwapExactETHForTokens"
  | "customCall";

export interface StoredTokenCoreWallet {
  id: string;
  name: string;
  address: Address;
  keystoreJson: string;
  publicKey: string;
  derivationPath: string;
  chainId: number;
  createdAt: string;
}

export interface TemplateFormValues {
  chainKey: DemoChainKey;
  kind: TemplateKind;
  from?: Address;
  to?: Address;
  tokenAddress?: Address;
  tokenDecimals?: string;
  recipient?: Address;
  spender?: Address;
  routerAddress?: Address;
  targetAddress?: Address;
  tokenOut?: Address;
  tokenOutDecimals?: string;
  amount?: string;
  amountIn?: string;
  amountOutMin?: string;
  feeBps?: string;
  value?: string;
  data?: Hex;
}

export interface PreparedTx {
  chainKey: DemoChainKey;
  chainId: number;
  templateKind: TemplateKind;
  title: string;
  description: string;
  to?: Address;
  data?: Hex;
  value?: bigint;
  from?: Address;
  request: TxRequestDraft;
  rawInput: string;
}

export interface TxRequestDraft {
  chainId: number;
  to?: Address;
  data?: Hex;
  value?: bigint;
  gas?: bigint;
  nonce?: number;
  account?: Address;
}

export interface ContractVerificationStatus {
  verified: boolean;
  source: "etherscan" | "sourcify" | "local" | "unknown";
  contractName?: string;
  abi?: readonly unknown[];
  message: string;
}

export interface RiskItem {
  level: "low" | "medium" | "high";
  title: string;
  description: string;
}

export type PolicyRule =
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "requireVerifiedContract";
      level?: RiskItem["level"];
    }
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "maxAssetOut";
      level?: RiskItem["level"];
      assetKind: "native" | "erc20";
      symbol: string;
      decimals: number;
      max: string;
      tokenAddressByChain?: Partial<Record<DemoChainKey, Address>>;
    }
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "requireSimulationSuccess";
      level?: RiskItem["level"];
    }
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "forbidUnknownFunction";
      level?: RiskItem["level"];
    }
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "forbidUnlimitedApproval";
      level?: RiskItem["level"];
    }
  | {
      id: string;
      name: string;
      description?: string;
      enabled?: boolean;
      type: "requireSwapMinimumOutput";
      level?: RiskItem["level"];
    };

export interface PolicyDocument {
  version: number;
  name: string;
  description?: string;
  policies: PolicyRule[];
}

export interface PolicyViolation {
  policyId: string;
  policyName: string;
  level: RiskItem["level"];
  description: string;
}

export interface TokenChange {
  address: Address;
  tokenSymbol: string;
  tokenAddress?: Address;
  direction: "in" | "out" | "approve" | "unknown";
  amount?: string;
  note: string;
}

export interface SimulationSummary {
  success: boolean;
  source: "tenderly" | "rpc" | "heuristic";
  summary: string;
  gasEstimate?: string;
  preparedGas?: string;
  preparedMaxFeePerGas?: string;
  preparedMaxPriorityFeePerGas?: string;
  resultPreview?: string;
  errorMessage?: string;
  simulationUrl?: string;
  publicSimulationUrl?: string;
  publicSimulationMessage?: string;
  tokenChanges: TokenChange[];
  raw?: unknown;
}

export interface ExecutionPreview {
  gas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export interface DecodedAction {
  kind: "nativeTransfer" | "contractCall" | "unknown";
  functionName?: string;
  functionSignature?: string;
  title: string;
  summary: string;
  argsSummary: Array<{ label: string; value: string }>;
  targetAddress?: Address;
  selector?: Hex;
  value?: bigint;
}

export interface AnalysisResult {
  chainKey: DemoChainKey;
  chainLabel: string;
  action: DecodedAction;
  verification: ContractVerificationStatus;
  risks: RiskItem[];
  policyViolations: PolicyViolation[];
  simulation: SimulationSummary;
  zhTwSummary: string;
  aiSummary?: string;
  /** Provider that generated aiSummary; undefined = local rule-based fallback */
  aiProvider?: import("./ai").AiProvider;
}

export interface ParsedInput {
  type: "json" | "signedRaw";
  chainId?: number;
  from?: Address;
  to?: Address;
  data?: Hex;
  value?: bigint;
  nonce?: number;
  gas?: bigint;
  raw: string;
}

export interface TokenPreset {
  symbol: string;
  address: Address;
  decimals: number;
}
