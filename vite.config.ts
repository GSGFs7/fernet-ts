import { playwright } from "@vitest/browser-playwright";
import dts from "vite-plugin-dts";
import { defineConfig } from "vitest/config";

export default defineConfig({
  build: {
    lib: {
      entry: "./lib/fernet.ts",
      name: "Fernet",
      fileName: "fernet",
      formats: ["es", "umd"],
    },
    rolldownOptions: {
      platform: "neutral",
    },
    minify: "terser", // obfuscation
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    browser: {
      // run real browser test?
      // try: pnpm run test:browser
      enabled: false,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "firefox" }, { browser: "chromium" }],
    },
  },
  plugins: [
    dts({
      insertTypesEntry: true,
      rollupTypes: true,
      tsconfigPath: "./tsconfig.json",
    }),
  ],
});
