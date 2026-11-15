import { expect, test } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

test.skip(!process.env.SF_PUBLIC_DEMO, "Requires the public-demo server");

test("public visitor explores real evidence without signing in", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("note")).toContainText("Synthetic demo");
  await expect(page.getByLabel("Access token", { exact: true })).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Sign out", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Replay demo", exact: true }),
  ).toHaveCount(0);
  await expect(page.locator(".metrics")).toContainText("18");
  const captures = resolve(
    import.meta.dirname,
    "../../work/vercel-screenshots",
  );
  mkdirSync(captures, { recursive: true });
  await page.screenshot({
    path: resolve(captures, "desktop.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Alert queue", exact: true }).click();
  await page.getByLabel("Filter severity").selectOption("critical");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page
    .getByRole("button", { name: "UID-zero account creation", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Investigation timeline" }),
  ).toBeVisible();
  await expect(page.getByLabel("Status", { exact: true })).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Add note", exact: true }),
  ).toHaveCount(0);
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export", exact: true }).click();
  const report = JSON.parse(
    readFileSync((await (await downloaded).path())!, "utf8"),
  );
  expect(report.snapshot.events.length).toBeGreaterThan(0);
  expect(report.sha256).toMatch(/^[a-f0-9]{64}$/);
  await page.getByRole("button", { name: "Telemetry", exact: true }).click();
  await page.getByLabel("Filter telemetry source").selectOption("wazuh");
  await expect(page.locator(".event-list details")).toHaveCount(1);
  await page
    .getByRole("button", { name: "Detection rules", exact: true })
    .click();
  await expect(page.locator(".rule-card")).toHaveCount(7);
  const denied = await request.post("/api/demo");
  expect(denied.status()).toBe(403);
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator("tbody tr")).toHaveCount(4);
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({
    path: resolve(captures, "mobile.png"),
    fullPage: true,
  });
  expect(errors).toEqual([]);
});
