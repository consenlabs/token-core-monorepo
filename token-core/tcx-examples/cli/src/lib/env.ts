type RuntimeEnvMap = Record<string, string | undefined>;

function getImportMetaEnv(): RuntimeEnvMap | undefined {
  return (import.meta as ImportMeta & { env?: RuntimeEnvMap }).env;
}

function getProcessEnv(): RuntimeEnvMap | undefined {
  return (
    globalThis as typeof globalThis & {
      process?: { env?: RuntimeEnvMap };
    }
  ).process?.env;
}

export function getRuntimeEnv(name: string) {
  const processValue = getProcessEnv()?.[name]?.trim();
  if (processValue) return processValue;

  const viteValue = getImportMetaEnv()?.[name]?.trim();
  if (viteValue) return viteValue;

  return undefined;
}
