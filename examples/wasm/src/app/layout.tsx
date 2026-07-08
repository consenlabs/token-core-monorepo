import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "tcx-wasm Integration Tests",
  description: "Browser-based integration tests for the tcx-wasm crate",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
