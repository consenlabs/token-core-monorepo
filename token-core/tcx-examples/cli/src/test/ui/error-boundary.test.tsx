// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "../../ui/components/ErrorBoundary";

function ThrowOnMount({ message }: { message: string }): ReactNode {
  throw new Error(message);
}

function NormalChild() {
  return <div data-testid="ok">正常子元件</div>;
}

describe("ErrorBoundary", () => {
  it("renders children when no error occurs", () => {
    render(
      <ErrorBoundary>
        <NormalChild />
      </ErrorBoundary>,
    );
    expect(screen.getByTestId("ok")).toBeInTheDocument();
  });

  it("renders error UI when child throws", () => {
    // suppress console.error from React during this test
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowOnMount message="test-error-message" />
      </ErrorBoundary>,
    );

    expect(screen.getByText("畫面發生錯誤")).toBeInTheDocument();
    expect(screen.getByText("test-error-message")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "重新整理頁面" }),
    ).toBeInTheDocument();

    spy.mockRestore();
  });

  it("calls window.location.reload when refresh button is clicked", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const reloadSpy = vi.fn();
    vi.stubGlobal("location", { reload: reloadSpy });

    const user = userEvent.setup();
    render(
      <ErrorBoundary>
        <ThrowOnMount message="reload-test" />
      </ErrorBoundary>,
    );

    await user.click(screen.getByRole("button", { name: "重新整理頁面" }));
    expect(reloadSpy).toHaveBeenCalledOnce();

    vi.unstubAllGlobals();
    spy.mockRestore();
  });
});
