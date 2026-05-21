// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// Mock browser-only / WASM / network modules before importing App
vi.mock("../../lib/tokencore", () => ({
  initTokenCoreWasm: vi.fn().mockResolvedValue(undefined),
  createTokenCoreWallet: vi.fn(),
  importTokenCoreWallet: vi.fn(),
  signDraftTransaction: vi.fn(),
  broadcastSignedTransaction: vi.fn(),
}));

vi.mock("../../lib/ai", () => ({
  generateAiSummary: vi.fn(),
  buildFallbackAiSummary: vi.fn().mockReturnValue("AI summary unavailable"),
}));

vi.mock("../../lib/simulate", () => ({
  simulateTransaction: vi.fn().mockResolvedValue({
    success: false,
    source: "heuristic",
    summary: "mock",
    tokenChanges: [],
  }),
  estimateExecutionPreview: vi.fn(),
}));

vi.mock("../../lib/uniswap", () => ({
  quoteEthToTokenSwap: vi.fn(),
}));

import App from "../../ui/App";

describe("App smoke test", () => {
  it("renders hero section without crashing", () => {
    render(<App />);
    expect(screen.getByText("看懂一筆 EVM 交易")).toBeInTheDocument();
  });

  it("shows chain selector or hero copy", () => {
    render(<App />);
    const elements = screen.getAllByText(/TokenCore CLI UI Tools/i);
    expect(elements.length).toBeGreaterThan(0);
  });
});
