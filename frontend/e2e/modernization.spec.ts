import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

test.skip(!process.env.SF_PUBLIC_DEMO, "Requires isolated public demo");
const captures = resolve(import.meta.dirname, "../../work/modernization");
const title = "Understand SentinelForge. Master Your Security Workflow.";

test("guide routes, keyboard steps, architecture, FAQ and real destinations", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("response", (response) => {
    if (response.status() >= 400)
      errors.push(`${response.status()} ${response.url()}`);
  });
  const direct = await request.get("/how-it-works");
  expect(direct.status()).toBe(200);
  expect(await direct.text()).toContain("How It Works · SentinelForge");
  await page.goto("/how-it-works");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
  await expect(page).toHaveTitle("How It Works · SentinelForge");
  await page.getByRole("tab").first().focus();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("tab").nth(1)).toBeFocused();
  await expect(page.getByRole("tabpanel")).toContainText(
    "Check the environment",
  );
  await page.keyboard.press("End");
  await expect(page.getByRole("tabpanel")).toContainText("Practice a response");
  await page
    .getByRole("button", { name: "Local workspace", exact: true })
    .click();
  await expect(page.getByRole("tabpanel")).toContainText(
    "A different administrator",
  );
  await page.getByText("Helpful to know", { exact: true }).click();
  await expect(page.getByRole("tabpanel")).toContainText(
    "requester cannot approve",
  );
  for (let i = 0; i < 8; i++) {
    await page.getByRole("tab").nth(i).click();
    await expect(page.getByRole("tabpanel")).toContainText("What to expect");
  }
  const architecture = page.locator(".architecture-nodes button");
  for (let i = 0; i < 5; i++) {
    if ((await architecture.nth(i).getAttribute("aria-expanded")) !== "true")
      await architecture.nth(i).click();
    await expect(page.locator(`#architecture-${i}`)).toBeVisible();
  }
  await page.locator(".faq-list summary").first().focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".faq-list details").first()).toHaveAttribute(
    "open",
    "",
  );
  await expect(page.locator(".faq-list details").first()).toContainText(
    "fixed synthetic dataset",
  );
  await page
    .getByRole("button", { name: "Open SentinelForge", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/demo visitor/i)).toHaveCount(0);
  await page
    .locator(".topbar")
    .getByRole("link", { name: "How It Works" })
    .click();
  await page
    .getByRole("button", { name: "Explore telemetry", exact: true })
    .click();
  await expect(page).toHaveURL(/\?view=telemetry/);
  await expect(
    page.getByRole("heading", { name: "Telemetry", exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Telemetry", exact: true }),
  ).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
  expect(errors).toEqual([]);
});

test("responsive reflow, mobile dialog focus, reduced motion and opaque fallback", async ({
  page,
}) => {
  mkdirSync(captures, { recursive: true });
  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    for (const route of ["/", "/how-it-works"]) {
      await page.goto(route);
      await page.locator(route === "/" ? ".metrics" : ".guide-hero").waitFor();
      await page.evaluate(() => document.fonts.ready);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBeTruthy();
      await page.screenshot({
        animations: "disabled",
        path: resolve(
          captures,
          `${route === "/" ? "dashboard" : "guide"}-${width}.png`,
        ),
        fullPage: true,
      });
    }
  }
  await page.goto("/");
  const menu = page.getByRole("button", {
    name: "Open navigation",
    exact: true,
  });
  await menu.click();
  const dialog = page.getByRole("dialog", { name: "Your workspace" });
  await expect(dialog).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Close navigation" }),
  ).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(
    dialog.getByRole("link", { name: "How It Works" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Close navigation" }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(menu).toBeFocused();
  await menu.click();
  await dialog
    .getByRole("button", { name: "Detection rules", exact: true })
    .click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator(".rule-card")).toHaveCount(7);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/how-it-works");
  await page.getByRole("tabpanel").waitFor();
  expect(
    await page
      .getByRole("tabpanel")
      .evaluate((el) => getComputedStyle(el).animationName),
  ).toBe("none");
  // Disable the enhancement to verify the material's solid fallback stays legible.
  await page.addStyleTag({
    content:
      ".glass-material { backdrop-filter:none!important; -webkit-backdrop-filter:none!important; background:#101a2c!important; }",
  });
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await page.screenshot({
    animations: "disabled",
    path: resolve(captures, "guide-opaque-reduced-motion.png"),
    fullPage: true,
  });
  await page.emulateMedia({ forcedColors: "active" });
  await expect(
    page.getByRole("button", { name: "Explore the workspace" }),
  ).toBeVisible();
  await page.screenshot({
    animations: "disabled",
    path: resolve(captures, "guide-forced-colors.png"),
    fullPage: true,
  });
  await page.emulateMedia({ forcedColors: "none" });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect(page.locator(".app-shell")).toHaveClass(/sidebar-collapsed/);
  await page.getByRole("button", { name: "Expand sidebar" }).click();
  await expect(page.locator(".app-shell")).not.toHaveClass(/sidebar-collapsed/);
  await page.evaluate(() => {
    document.documentElement.style.zoom = "2";
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
});

test("WCAG automated checks cover dashboard views, investigation, guide and dialog", async ({
  page,
}) => {
  test.setTimeout(60000);
  for (const route of [
    "/",
    "/?view=alerts",
    "/?view=cases",
    "/?view=telemetry",
    "/?view=rules",
    "/how-it-works",
  ]) {
    await page.goto(route);
    await page
      .locator(
        route.includes("how-it-works") ? ".guide-hero" : ".workspace-footer",
      )
      .waitFor();
    await page.evaluate(() =>
      Promise.all(
        document.getAnimations().map((animation) => animation.finished),
      ),
    );
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(result.violations, route).toEqual([]);
  }
  await page.goto("/?view=alerts");
  await page
    .getByRole("button", { name: "UID-zero account creation", exact: true })
    .click();
  await page.getByRole("heading", { name: "Investigation timeline" }).waitFor();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
});

test("records browser lab metrics without inventing field scores", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const metrics = { lcp: 0, cls: 0 };
    Object.assign(window, { sfLabMetrics: metrics });
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) metrics.lcp = e.startTime;
    }).observe({ type: "largest-contentful-paint", buffered: true });
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const e = entry as PerformanceEntry & {
          hadRecentInput: boolean;
          value: number;
        };
        if (!e.hadRecentInput) metrics.cls += e.value;
      }
    }).observe({ type: "layout-shift", buffered: true });
  });
  const runs = [];
  for (const route of ["/", "/how-it-works"]) {
    await page.goto(route);
    await page.locator(route === "/" ? ".metrics" : ".guide-hero").waitFor();
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(400);
    const metrics = await page.evaluate(() => ({
      ...(window as unknown as { sfLabMetrics: { lcp: number; cls: number } })
        .sfLabMetrics,
      navigation: performance.getEntriesByType("navigation")[0].toJSON(),
    }));
    runs.push({ route, ...metrics });
  }
  mkdirSync(captures, { recursive: true });
  writeFileSync(
    resolve(captures, "lab-metrics.json"),
    JSON.stringify(
      {
        context: `Chromium browser lab; target ${process.env.SF_BASE_URL || "http://127.0.0.1:8000"}; unthrottled, two route samples, not field data or a Lighthouse score`,
        runs,
      },
      null,
      2,
    ),
  );
  for (const run of runs)
    expect(run.cls, `${run.route} layout shift`).toBeLessThan(0.1);
});

test("guide chrome is stable while its lazy assets are delayed", async ({
  page,
}) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/assets/HowItWorks-*.js", async (route) => {
    await gate;
    await route.continue();
  });
  try {
    await page.goto("/how-it-works", { waitUntil: "domcontentloaded" });
    const header = page.locator(".guide-navbar");
    await expect(header).toBeVisible();
    await expect(page.getByText("Opening the field guide…")).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    const before = await header.boundingBox();
    release();
    await page.locator(".guide-hero").waitFor();
    const after = await header.boundingBox();
    expect(after?.height).toBe(before?.height);
    expect(after?.y).toBe(before?.y);
  } finally {
    release();
  }
});
