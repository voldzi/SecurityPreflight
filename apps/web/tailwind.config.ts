import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#1f2933",
        paper: "#f7f8fa",
        line: "#d8dde6",
        muted: "#6b7280",
        ok: "#137a4a",
        warn: "#a36200",
        fail: "#b42318"
      }
    }
  },
  plugins: []
};

export default config;
