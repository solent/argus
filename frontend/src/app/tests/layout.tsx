import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
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
  title: "Argus — Model Evaluation",
  description: "Multi-model consensus evaluation dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
      <Suspense fallback={<div>Loading...</div>}>{children}</Suspense>
    </div>
  );
}
