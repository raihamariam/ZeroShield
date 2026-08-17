import { expect, injectFakeSessionCookie, test } from "../fixtures";

test.beforeEach(async ({ page }) => {
  await injectFakeSessionCookie(page);
});

const NAV_ROUTES: { label: string; href: string }[] = [
  { label: "Mission Control", href: "/" },
  { label: "Vulnerabilities", href: "/vulnerabilities" },
  { label: "Priority Queue", href: "/priority-queue" },
  { label: "Experiment Studio", href: "/experiment-studio" },
  { label: "Experiments", href: "/experiments" },
  { label: "Runs", href: "/runs" },
  { label: "Domain Packs", href: "/domain-packs" },
  { label: "Evidence Vault", href: "/evidence-vault" },
  { label: "Approvals", href: "/approvals" },
  { label: "Audit Trail", href: "/audit-trail" },
  { label: "Integrations", href: "/integrations" },
  { label: "Health", href: "/health" },
  { label: "Legacy Dashboard", href: "/legacy-dashboard" },
];

test.describe("every nav item resolves to a real page", () => {
  for (const route of NAV_ROUTES) {
    test(`${route.label} (${route.href})`, async ({ page }) => {
      const response = await page.goto(route.href);
      expect(response?.status()).toBe(200);
      // A real page, not the framework's default 404 boundary.
      await expect(page.getByText("Page not found")).toHaveCount(0);
    });
  }
});

test("sidebar links match the routes each page actually serves", async ({ page }) => {
  await page.goto("/");
  for (const route of NAV_ROUTES.filter((r) => r.href !== "/")) {
    const link = page.getByRole("link", { name: route.label, exact: true });
    await expect(link).toHaveAttribute("href", route.href);
  }
});

test("skip-to-content link is the first focusable element", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
});
