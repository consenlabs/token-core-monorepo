import type { NextConfig } from "next";

const nextConfig: NextConfig = {
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
