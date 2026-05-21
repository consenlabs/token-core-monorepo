export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withTimeout<T>(
  factory: () => Promise<T>,
  timeoutMs: number,
  timeoutMessage: string,
): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(timeoutMessage));
    }, timeoutMs);
  });

  try {
    return await Promise.race([factory(), timeoutPromise]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

function normalizeError(error: unknown) {
  return error instanceof Error
    ? error
    : new Error(String(error ?? "未知錯誤"));
}

export async function retry<T>(
  runner: () => Promise<T>,
  options?: {
    retries?: number;
    delayMs?: number;
    shouldRetry?: (error: Error) => boolean;
  },
): Promise<T> {
  const retries = options?.retries ?? 1;
  const delayMs = options?.delayMs ?? 300;
  const shouldRetry = options?.shouldRetry ?? (() => true);

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await runner();
    } catch (error) {
      const normalized = normalizeError(error);
      lastError = normalized;
      if (attempt >= retries || !shouldRetry(normalized)) break;
      await sleep(delayMs * (attempt + 1));
    }
  }

  throw lastError ?? new Error("重試失敗。");
}
