import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const nextConfig: NextConfig = {
  turbopack: {
    root: repositoryRoot,
  },
  async rewrites() {
    return [
      {
        source: "/imkey/:path*",
        destination: "https://imkeyserver.com:10444/imkey/:path*",
      },
    ];
  },
};

export default nextConfig;
