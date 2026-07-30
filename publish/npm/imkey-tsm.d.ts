export interface TsmClient {
  configure?(baseUrl: string): void | Promise<void>;
  post(action: string, bodyJson: string): Promise<string>;
}

export interface FetchTsmClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class FetchTsmClient implements TsmClient {
  constructor(options?: FetchTsmClientOptions);
  configure(baseUrl: string): void;
  post(action: string, bodyJson: string): Promise<string>;
}
