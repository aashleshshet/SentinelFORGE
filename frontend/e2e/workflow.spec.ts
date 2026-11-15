import { test, expect } from "@playwright/test";
import { readFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
const root = resolve(import.meta.dirname, "../..");
function credential(role: string) {
  if (process.env.SF_E2E_TOKEN && role === "admin")
    return process.env.SF_E2E_TOKEN;
  const line = readFileSync(resolve(root, ".env"), "utf8")
    .split("\n")
    .find((l) => l.startsWith("SF_IDENTITIES="))!;
  return JSON.parse(
    line.slice("SF_IDENTITIES=".length).replace(/^'|'$/g, ""),
  ).find((p: { role: string }) => p.role === role).token;
}
async function login(page: import("@playwright/test").Page, role = "admin") {
  await page.goto("/");
  await page.getByLabel("Access token", { exact: true }).fill(credential(role));
  await page.getByRole("button", { name: "Open workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Active detection rules", { exact: true }),
  ).toBeVisible();
}

test("replay → alert → investigation → note → evidence → simulation", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page);
  await page.getByRole("button", { name: "Replay demo", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Demo replay:");
  await expect(
    page.getByText("Signals to investigate", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Investigations", exact: true })
    .click();
  await page
    .getByRole("button", { name: /SSH password guessing/ })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Investigation timeline" }),
  ).toBeVisible();
  await page
    .getByLabel("Status", { exact: true })
    .selectOption("investigating");
  await expect(page.getByRole("status")).toContainText("Case status updated");
  await page.getByRole("button", { name: "Assign to me", exact: true }).click();
  const note =
    "Browser-verified investigation: inspect parent process and preserve source telemetry. <script>not executable</script>";
  await page.getByLabel("Investigation note", { exact: true }).fill(note);
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(page.locator(".note p").last()).toHaveText(note);
  await page.getByLabel("Validate the signal", { exact: true }).check();
  await page
    .getByRole("button", { name: "Preserve evidence", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText(
    "Evidence snapshot preserved",
  );
  const downloadPromise = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export", exact: true })
    .last()
    .click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/sentinelforge-case-.*\.json/);
  const report = JSON.parse(readFileSync((await download.path())!, "utf8"));
  expect(report.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(report.snapshot.events.length).toBeGreaterThan(0);
  await page
    .getByLabel("Reason for simulation", { exact: true })
    .fill("Validate isolation approval workflow in the local lab.");
  await page
    .getByRole("button", { name: "Request simulation", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Simulation requested");
  await expect(
    page.getByRole("button", { name: "Approve simulation" }),
  ).toHaveCount(0);
  expect(errors).toEqual([]);
  const stats = await request.get("/api/stats", {
    headers: { Authorization: "Bearer " + credential("admin") },
  });
  expect((await stats.json()).alerts).toBe(7);
});

test("filters, empty state, telemetry details, rules, and viewer restrictions", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("button", { name: "Alert queue", exact: true }).click();
  await page.getByLabel("Search alerts").fill("no-such-detection");
  await expect(page.getByText("No alerts match these filters.")).toBeVisible();
  await page.getByLabel("Search alerts").fill("");
  await page.getByLabel("Filter severity").selectOption("critical");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByRole("button", { name: "Telemetry", exact: true }).click();
  await page.getByLabel("Filter telemetry source").selectOption("wazuh");
  await expect(page.locator(".event-list details")).toHaveCount(1);
  await page.locator(".event-list summary").click();
  await expect(page.locator(".event-list pre")).toContainText("wazuh-manager");
  await page
    .getByRole("button", { name: "Detection rules", exact: true })
    .click();
  await expect(page.locator(".rule-card")).toHaveCount(7);
  await page.locator(".rule-card summary").first().click();
  await expect(page.locator(".rule-body").first()).toContainText(
    "False positives:",
  );
  await page
    .getByRole("button", { name: "Sign out", exact: true })
    .filter({ visible: true })
    .click();
  await page
    .getByLabel("Access token", { exact: true })
    .fill(credential("viewer"));
  await page.getByRole("button", { name: "Open workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Replay demo", exact: true }),
  ).toHaveCount(0);
});

test("responsive screenshots have no horizontal overflow", async ({ page }) => {
  await login(page);
  mkdirSync(resolve(root, "docs/screenshots"), { recursive: true });
  for (const [name, width, height] of [
    ["desktop", 1440, 1000],
    ["tablet", 768, 1024],
    ["mobile", 390, 844],
  ] as const) {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => document.fonts.ready);
    await expect(page.locator("h1")).toHaveText("Overview");
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    );
    expect(overflow, `${name} must not scroll horizontally`).toBe(false);
    await page.screenshot({
      path: resolve(root, `docs/screenshots/${name}.png`),
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page
    .getByRole("button", { name: "Investigations", exact: true })
    .click();
  await page
    .getByRole("button", { name: /SSH password guessing/ })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Investigation timeline" }),
  ).toBeVisible();
  await page.screenshot({
    path: resolve(root, "docs/screenshots/investigation.png"),
    fullPage: true,
  });
});

test("public guide preserves an authenticated in-memory session", async ({
  page,
  request,
}) => {
  await page.goto("/how-it-works");
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "Understand SentinelForge.",
  );
  expect((await request.get("/api/stats")).status()).toBe(401);
  await page
    .getByRole("button", { name: "Open workspace", exact: true })
    .click();
  await expect(page.getByLabel("Access token", { exact: true })).toBeVisible();
  await login(page);
  await page
    .locator(".topbar")
    .getByRole("link", { name: "How It Works" })
    .click();
  await page
    .getByRole("button", { name: "Open workspace", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Replay demo", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });
  expect(page.url()).not.toContain(credential("admin"));
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByLabel("Access token", { exact: true })).toBeVisible();
});

test("JSON import validates input and preserves deduplication", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("button", { name: "Telemetry", exact: true }).click();
  await page.getByLabel("Upload JSON telemetry").setInputFiles({
    name: "invalid.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"events":"invalid"}'),
  });
  await expect(page.getByRole("alert")).toContainText("invalid fields");
  await page
    .getByLabel("Upload JSON telemetry")
    .setInputFiles(resolve(root, "data/demo.json"));
  await expect(page.getByRole("status")).toContainText(
    "Import: 0 accepted, 18 duplicates, 0 rejected",
  );
  await expect(page.locator(".event-list details")).toHaveCount(18);
});
