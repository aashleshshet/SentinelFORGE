import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");
const publicDemo = Boolean(process.env.SF_PUBLIC_DEMO);
const captures = resolve(root, "work/ux-hardening");

function credential() {
  if (process.env.SF_E2E_TOKEN) return process.env.SF_E2E_TOKEN;
  const line = readFileSync(resolve(root, ".env"), "utf8")
    .split("\n")
    .find((value) => value.startsWith("SF_IDENTITIES="))!;
  return JSON.parse(
    line.slice("SF_IDENTITIES=".length).replace(/^'|'$/g, ""),
  ).find((identity: { role: string }) => identity.role === "admin")
    .token as string;
}

async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Access token", { exact: true }).fill(credential());
  await page
    .getByRole("button", { name: "Open workspace", exact: true })
    .click();
  await expect(page.locator(".metrics")).toBeVisible();
}

function deferred() {
  let resolvePromise!: () => void;
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

test.describe("public product and workspace experience", () => {
  test.skip(!publicDemo, "Requires isolated public demo");

  test("What It Is has exact routes, usable mobile navigation and accessible detailed content", async ({
    page,
    request,
  }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    for (const route of ["/what-it-is", "/what-it-is/"]) {
      const response = await request.get(route);
      expect(response.status()).toBe(200);
      expect(await response.text()).toContain("What It Is · SentinelForge");
    }
    mkdirSync(captures, { recursive: true });
    for (const width of [1440, 768, 390, 320]) {
      await page.setViewportSize({ width, height: width < 500 ? 844 : 1000 });
      await page.goto("/what-it-is");
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(
        "What is SentinelForge?",
      );
      await expect(page).toHaveTitle("What It Is · SentinelForge");
      await page.evaluate(() => document.fonts.ready);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBe(true);
      const navigation = page.getByRole("navigation", {
        name: "Main navigation",
        exact: true,
      });
      await expect(
        navigation.getByRole("link", { name: "What It Is", exact: true }),
      ).toHaveAttribute("aria-current", "page");
      await expect(
        navigation.getByRole("link", { name: "How It Works", exact: true }),
      ).toBeVisible();
      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations).toEqual([]);
      await page.screenshot({
        path: resolve(captures, `what-it-is-${width}.png`),
        fullPage: true,
        animations: "disabled",
      });
    }
    await page.getByLabel("Compare workspace mode").selectOption("local");
    await expect(page.locator("#about-mode-details")).toContainText(
      "Loopback only",
    );
    await page
      .getByLabel("Compare workspace mode")
      .selectOption("authenticated");
    await expect(page.locator("#about-mode-details")).toContainText(
      "different admin approves",
    );
    await page
      .locator(".about-source-list summary")
      .filter({ hasText: "Windows Sysmon" })
      .click();
    await expect(
      page.locator(".about-source-list details[open]"),
    ).toContainText("Native EVTX/XML ingestion is not included");
    const guideLink = page
      .getByRole("navigation", { name: "Main navigation", exact: true })
      .getByRole("link", { name: "How It Works", exact: true });
    await guideLink.focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/how-it-works$/);
    await page.goBack();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "What is SentinelForge?",
    );
    await page
      .getByRole("button", { name: "Explore workspace", exact: true })
      .click();
    await expect(page.locator(".metrics")).toBeVisible();
    await page
      .getByRole("button", { name: "Open navigation", exact: true })
      .click();
    const dialog = page.getByRole("dialog", { name: "Your workspace" });
    await dialog.getByRole("link", { name: "What It Is", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "What is SentinelForge?",
    );
    expect(errors).toEqual([]);
  });

  test("selecting the active view during a refresh does not strand the request", async ({
    page,
  }) => {
    await page.goto("/?view=alerts");
    await expect(page.locator("tbody tr")).toHaveCount(7);
    const started = deferred();
    const release = deferred();
    await page.route("**/api/alerts?**", async (route) => {
      started.resolve();
      await release.promise;
      await route.continue();
    });
    try {
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await started.promise;
      await page
        .getByRole("button", { name: "Alert queue", exact: true })
        .click();
      release.resolve();
      await expect(
        page.getByRole("button", { name: "Refresh", exact: true }),
      ).toBeEnabled();
      await expect(page.locator("tbody tr")).toHaveCount(7);
    } finally {
      release.resolve();
    }
  });

  test("a missing document chunk leaves a working return to the workspace", async ({
    page,
  }) => {
    await page.route("**/assets/WhatItIs-*.js", (route) => route.abort());
    await page.goto("/what-it-is");
    await expect(
      page.getByRole("heading", { name: "This page could not load." }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Return to workspace", exact: true })
      .click();
    await expect(page.locator(".metrics")).toBeVisible();
  });

  test("filter changes hide outdated rows while loading and reset returns the full queue", async ({
    page,
  }) => {
    await page.goto("/?view=alerts");
    await expect(page.locator("tbody tr")).toHaveCount(7);
    const started = deferred();
    const release = deferred();
    await page.route("**/api/alerts?**", async (route) => {
      if (
        new URL(route.request().url()).searchParams.get("q") !==
        "no-matching-signal"
      ) {
        await route.continue();
        return;
      }
      started.resolve();
      await release.promise;
      await route.fulfill({ json: { total: 0, items: [] } });
    });
    try {
      await page
        .getByLabel("Search alerts", { exact: true })
        .fill("no-matching-signal");
      await started.promise;
      await expect(page.locator("tbody tr")).toHaveCount(0);
      await expect(
        page.getByText("No alerts match these filters.", { exact: true }),
      ).toHaveCount(0);
      await expect(
        page.getByLabel("Search alerts", { exact: true }),
      ).toBeFocused();
      release.resolve();
      await expect(
        page.getByText("No alerts match these filters.", { exact: true }),
      ).toBeVisible();
      await page
        .getByRole("button", { name: "Clear filters", exact: true })
        .click();
      await expect(
        page.getByLabel("Search alerts", { exact: true }),
      ).toHaveValue("");
      await expect(page.locator("tbody tr")).toHaveCount(7);
    } finally {
      release.resolve();
    }
  });
});

test.describe("authenticated interaction recovery", () => {
  test.skip(publicDemo, "Requires isolated authenticated server");

  test("product navigation retains the in-memory session", async ({ page }) => {
    await login(page);
    await page
      .locator(".topbar")
      .getByRole("link", { name: "What It Is", exact: true })
      .click();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "What is SentinelForge?",
    );
    await page
      .getByRole("link", { name: "Follow the walkthrough", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Open workspace", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Replay demo", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(() => [localStorage.length, sessionStorage.length]),
    ).toEqual([0, 0]);
    expect(page.url()).not.toContain(credential());
  });

  test("a rejected import stays actionable after refresh without marking the API offline", async ({
    page,
  }) => {
    await login(page);
    await page.getByRole("button", { name: "Telemetry", exact: true }).click();
    await expect(page.getByLabel("Upload JSON telemetry")).toBeAttached();
    await page.getByLabel("Upload JSON telemetry").setInputFiles({
      name: "invalid.json",
      mimeType: "application/json",
      buffer: Buffer.from('{"events":"invalid"}'),
    });
    await expect(page.getByRole("alert")).toContainText("invalid fields");
    await expect(page.locator(".connection")).toHaveText("API connected");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "Refresh", exact: true }),
    ).toBeEnabled();
    await expect(page.getByRole("alert")).toContainText("invalid fields");
    await expect(page.locator(".connection")).toHaveText("API connected");
    await expect(page.getByRole("alert")).not.toContainText(
      "Displayed data may be stale",
    );
  });

  test("an import failure during initial loading still recovers telemetry", async ({
    page,
  }) => {
    await login(page);
    const started = deferred();
    const release = deferred();
    let reads = 0;
    await page.route("**/api/events?**", async (route) => {
      reads += 1;
      if (reads === 1) {
        started.resolve();
        await release.promise;
      }
      await route.continue();
    });
    try {
      await page
        .getByRole("button", { name: "Telemetry", exact: true })
        .click();
      await started.promise;
      await page.getByLabel("Upload JSON telemetry").setInputFiles({
        name: "broken.json",
        mimeType: "application/json",
        buffer: Buffer.from("invalid json"),
      });
      await expect(page.getByRole("alert")).toContainText("not valid JSON");
      await expect(page.getByLabel("Telemetry results")).toHaveAttribute(
        "aria-busy",
        "false",
      );
      await expect(
        page.getByText("Loading telemetry…", { exact: true }),
      ).toHaveCount(0);
      await expect(
        page.getByRole("button", { name: "Refresh", exact: true }),
      ).toBeEnabled();
    } finally {
      release.resolve();
    }
  });

  test("a delayed save cannot replace a newly selected investigation or erase its draft", async ({
    page,
    request,
  }) => {
    const headers = { Authorization: `Bearer ${credential()}` };
    expect((await request.post("/api/demo", { headers })).ok()).toBe(true);
    const cases = (await (await request.get("/api/cases", { headers })).json())
      .items as { id: string; title: string }[];
    expect(cases.length).toBeGreaterThanOrEqual(2);
    const [first, second] = cases;
    await login(page);
    await page
      .getByRole("button", { name: "Investigations", exact: true })
      .click();
    await page.getByRole("button", { name: first.title, exact: true }).click();
    await expect(page.locator(".case-banner h2")).toHaveText(first.title);
    await expect(page.locator("#main-content")).toBeFocused();
    const started = deferred();
    const release = deferred();
    await page.route(`**/api/cases/${first.id}/notes`, async (route) => {
      started.resolve();
      await release.promise;
      await route.fulfill({ json: { id: "delayed-note" } });
    });
    try {
      await page
        .getByLabel("Investigation note", { exact: true })
        .fill("Pending note for the first case.");
      await page.getByRole("button", { name: "Add note", exact: true }).click();
      await started.promise;
      await page
        .getByRole("button", { name: "Investigations", exact: true })
        .click();
      await page
        .getByRole("button", { name: second.title, exact: true })
        .click();
      await expect(page.locator(".case-banner h2")).toHaveText(second.title);
      const draft = page.getByLabel("Investigation note", { exact: true });
      if (await draft.isEnabled())
        await draft.fill("Draft for the second case must survive.");
      const pendingDraft = await draft.inputValue();
      release.resolve();
      await expect(
        page.getByRole("button", { name: "Refresh", exact: true }),
      ).toBeEnabled();
      await expect(page.locator(".case-banner h2")).toHaveText(second.title);
      await expect(draft).toHaveValue(pendingDraft);
      await expect(page.locator(".page-heading p")).toContainText(
        second.id.slice(0, 8),
      );
    } finally {
      release.resolve();
    }
  });
});
