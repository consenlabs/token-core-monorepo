const DEFAULT_TSM_BASE_URL = "/imkey";

function normalizeBaseUrl(baseUrl) {
  const normalized = baseUrl.trim().replace(/\/+$/, "");
  if (!normalized) throw new Error("imkey_invalid_tsm_url");
  return normalized;
}

export class FetchTsmClient {
  constructor(options = {}) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl ?? DEFAULT_TSM_BASE_URL);
    this.configuredExplicitly = options.baseUrl !== undefined;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetchImpl) throw new Error("imkey_fetch_not_available");
  }

  configure(baseUrl) {
    const normalized = normalizeBaseUrl(baseUrl);
    if (this.configuredExplicitly && normalized !== this.baseUrl) {
      throw new Error("imkey_tsm_url_already_configured");
    }
    this.baseUrl = normalized;
    this.configuredExplicitly = true;
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
