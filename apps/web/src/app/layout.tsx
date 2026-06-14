import type { Metadata } from "next";
import "@voldzi/stratos-ui/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecurityPreflight",
  description: "Česko-anglický bezpečnostní preflight dashboard"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="cs">
      <body>{children}</body>
    </html>
  );
}
