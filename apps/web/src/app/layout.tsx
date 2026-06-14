import type { Metadata } from "next";
import "@voldzi/stratos-ui/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecurityPreflight",
  description: "Local security preflight dashboard"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
