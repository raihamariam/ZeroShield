import { expect, injectFakeSessionCookie, test } from "../fixtures";

/**
 * This smoke tier intentionally runs against no backend (see playwright.config.ts) - it's
 * the automated version of the manual check performed throughout Phase 4 development:
 * every data-driven page must degrade to an inline ErrorState per section, never crash the
 * page or block navigation, when the ZeroShield API is unreachable.
 */
test.beforeEach(async ({ page }) => {
  await injectFakeSessionCookie(page);
});

const DATA_DRIVEN_ROUTES = [
  "/",
  "/vulnerabilities",
  "/priority-queue",
  "/experiments",
  "/runs",
  "/domain-packs",
  "/evidence-vault",
  "/approvals",
  "/integrations",
  "/health",
];

for (const route of DATA_DRIVEN_ROUTES) {
  test(`${route} shows an inline "unreachable" state instead of crashing`, async ({ page }) => {
    await page.goto(route);
    await expect(page.getByText("ZeroShield API is unreachable").first()).toBeVisible();
    await expect(page.getByText(/Application error/i)).toHaveCount(0);
  });
}

test("Mission Control's panels fail independently - one down section doesn't blank the page", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Mission Control" })).toBeVisible();
  const unreachableCount = await page.getByText("ZeroShield API is unreachable").count();
  // Six stat tiles + five list panels all hit the (unreachable) API independently.
  expect(unreachableCount).toBeGreaterThanOrEqual(5);
});
