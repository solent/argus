import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Suspense } from "react";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Argus — C++ Vulnerability Intelligence",
  description:
    "Static C++ vulnerability analysis powered by AI — CVE impact scoring, data-flow slicing, and multi-model consensus.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {/* Suspense pour tout ce qui utilise useSearchParams ou CSR-only */}
        <Suspense
          fallback={
            <div
              className="min-h-screen flex items-center justify-center text-slate-400"
              style={{ background: "#070c18" }}
            >
              Loading Argus…
            </div>
          }
        >
          {children}
        </Suspense>
      </body>
    </html>
  );
}
