import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage?: string;
}

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = {
    hasError: false,
    errorMessage: undefined,
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error.message || "未知錯誤",
    };
  }

  override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("React UI 發生未捕捉錯誤：", error, errorInfo);
  }

  private readonly handleReload = () => {
    window.location.reload();
  };

  override render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <main style={{ padding: "32px", maxWidth: "760px", margin: "0 auto" }}>
        <h1>畫面發生錯誤</h1>
        <p>React UI 遇到未預期例外，建議重新整理後再試一次。</p>
        <p>
          <strong>錯誤訊息：</strong>
          {this.state.errorMessage}
        </p>
        <button onClick={this.handleReload}>重新整理頁面</button>
      </main>
    );
  }
}
