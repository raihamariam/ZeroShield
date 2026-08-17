import { expect, test } from "@playwright/test";

test("an unknown route shows the themed 404 page, not a framework crash screen", async ({ page }) => {
  const response = await page.goto("/this-route-does-not-exist");
  expect(response?.status()).toBe(404);
  await expect(page.getByText("Page not found")).toBeVisible();
  await page.getByRole("link", { name: "Back to Mission Control" }).click();
  await expect(page).toHaveURL("/");
});

test("an unknown/unreachable CVE degrades gracefully, never a framework crash", async ({ page }) => {
  const response = await page.goto("/vulnerabilities/CVE-0000-00000");
  // Without a live backend this renders an "API unreachable" ErrorState (200); against a
  // live backend a genuinely unknown CVE 404s. Either is "handled" - what must never happen
  // is Next.js's own unhandled-exception crash overlay.
  expect(response?.status()).not.toBe(500);
  await expect(page.getByText(/Application error/i)).toHaveCount(0);
});
