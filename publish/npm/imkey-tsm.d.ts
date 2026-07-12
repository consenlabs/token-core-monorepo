export interface TsmClient {
  post(action: string, bodyJson: string): Promise<string>;
}

export interface FetchTsmClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class FetchTsmClient implements TsmClient {
  constructor(options?: FetchTsmClientOptions);
  post(action: string, bodyJson: string): Promise<string>;
}
