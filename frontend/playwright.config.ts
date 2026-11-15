import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 30000,
  reporter: "list",
  use: {
    baseURL: process.env.SF_BASE_URL || "http://127.0.0.1:8000",
    browserName: "chromium",
    viewport: { width: 1440, height: 1000 },
    screenshot: "only-on-failure",
  },
});
