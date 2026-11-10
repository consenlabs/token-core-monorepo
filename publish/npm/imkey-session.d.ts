export function runDeviceSession<T>(
  transport: object,
  runtime: object,
  operation: () => Promise<T>
): Promise<T>;
