import { readFile } from "node:fs/promises";
import path from "node:path";

function stripQuotes(value: string) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

export async function loadCliDotEnv(cwd = process.cwd()) {
  const envPath = path.join(cwd, ".env");

  try {
    const contents = await readFile(envPath, "utf8");
    for (const rawLine of contents.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;

      const separatorIndex = line.indexOf("=");
      if (separatorIndex <= 0) continue;

      const key = line.slice(0, separatorIndex).trim();
      const value = stripQuotes(line.slice(separatorIndex + 1).trim());

      if (!process.env[key]) {
        process.env[key] = value;
      }
    }
  } catch {
    // The CLI allows users to export env vars themselves, so a missing .env file is silently ignored.
  }
}
