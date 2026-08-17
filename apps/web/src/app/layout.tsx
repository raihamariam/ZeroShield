import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { AppShell } from "@/components/layout/AppShell";
import { authApi } from "@/lib/api";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "ZeroShield",
    template: "%s · ZeroShield",
  },
  description: "Continuous mitigation assurance for validated CVE remediations.",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Best-effort, never throws (the /login page itself has no session, and
  // proxy.ts already handles the redirect gate for every other route) -
  // this is only used for display (username/role badge, logout button),
  // not as a security check. See components/layout/UserMenu.tsx.
  const currentUser = await authApi.me().catch(() => null);

  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <AppShell currentUser={currentUser}>{children}</AppShell>
      </body>
    </html>
  );
}
