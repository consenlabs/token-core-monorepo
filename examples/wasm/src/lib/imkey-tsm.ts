export interface TsmClient {
  post(action: string, bodyJson: string): Promise<string>;
}

export interface FetchTsmClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

const DEFAULT_TSM_BASE_URL = "https://imkey.online:1000/imkey";

export class FetchTsmClient implements TsmClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: FetchTsmClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? DEFAULT_TSM_BASE_URL;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async post(action: string, bodyJson: string): Promise<string> {
    const response = await this.fetchImpl(`${this.baseUrl}${action}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: bodyJson,
    });
    if (!response.ok) {
      throw new Error(`imkey_tsm_http_error_${response.status}`);
    }
    return response.text();
  }
}
