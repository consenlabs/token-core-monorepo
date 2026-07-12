const DEFAULT_TSM_BASE_URL = "/imkey";

export class FetchTsmClient {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl ?? DEFAULT_TSM_BASE_URL;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetchImpl) throw new Error("imkey_fetch_not_available");
  }

  async post(action, bodyJson) {
    const response = await this.fetchImpl(`${this.baseUrl}${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: bodyJson,
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(
        `imkey_tsm_http_error_${response.status}${detail ? `: ${detail}` : ""}`
      );
    }
    return response.text();
  }
}
