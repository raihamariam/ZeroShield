import type { Page } from "@playwright/test";
export { expect, test } from "@playwright/test";

/**
 * V2 Phase 6 added session-cookie auth (src/proxy.ts): any route other than
 * /login|/api|/_next/static|/_next/image|/favicon.ico now redirects an
 * unauthenticated request to /login. Two different fixes for the two E2E
 * tiers (see playwright.config.ts):
 *
 * - smoke/ (no backend) - proxy.ts only checks *presence* of the session
 *   cookie, never validity (real validation happens server-side, per
 *   request, via zeroshield.api.dependencies.get_current_user) - so
 *   injectFakeSessionCookie() below is enough to get smoke specs back past
 *   the proxy and exercising the same "backend unreachable" degradation
 *   paths they always have. It grants no real access to anything, since
 *   there is no backend in this tier to grant access to.
 * - workflows/ (live backend, RUN_E2E_LIVE=1) - the backend genuinely
 *   validates the session, so these specs must log in for real via the UI
 *   - see loginAsAdmin/loginAs below.
 */
const FAKE_SESSION_COOKIE_NAME = "zeroshield_session";

export async function injectFakeSessionCookie(page: Page): Promise<void> {
  await page.context().addCookies([
    {
      name: FAKE_SESSION_COOKIE_NAME,
      value: "e2e-smoke-tier-fake-session-not-a-real-credential",
      domain: "localhost",
      path: "/",
    },
  ]);
}

/** E2E_ADMIN_USERNAME/E2E_ADMIN_PASSWORD must name a real ADMIN account,
 * bootstrapped once via `zeroshield create-admin` against the live stack -
 * see e2e/README.md. Every workflows/ scenario that needs other roles
 * (RESEARCHER/REVIEWER/VIEWER) creates them itself via bootstrapUser() below,
 * so only this one credential needs to be seeded ahead of time. */
export function adminCredentials(): { username: string; password: string } {
  const username = process.env.E2E_ADMIN_USERNAME;
  const password = process.env.E2E_ADMIN_PASSWORD;
  if (!username || !password) {
    throw new Error(
      "E2E_ADMIN_USERNAME/E2E_ADMIN_PASSWORD must be set for workflows/ specs - " +
        "bootstrap one with `zeroshield create-admin --username <u> --password <p>` " +
        "against the live docker-compose stack first. See e2e/README.md."
    );
  }
  return { username, password };
}

export async function login(page: Page, username: string, password: string): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"));
}

export async function loginAsAdmin(page: Page): Promise<void> {
  const { username, password } = adminCredentials();
  await login(page, username, password);
}

/** Must be called while `page` is an authenticated ADMIN session (/users is
 * ADMIN-only). Returns the generated credentials so the caller can log the
 * new user in themselves (in the same or a fresh browser context). Username
 * is suffixed with the current timestamp so repeated suite runs against the
 * same long-lived stack never collide on a leftover username from a prior
 * run. */
export async function bootstrapUser(
  page: Page,
  role: "researcher" | "reviewer" | "viewer",
  label: string
): Promise<{ username: string; password: string }> {
  const username = `e2e-${label}-${Date.now()}`;
  const password = `E2e-${label}-bootstrap-pw-1`;

  await page.goto("/users");
  await page.getByRole("button", { name: "Create user" }).click();
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByLabel("Role").selectOption(role);
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.getByText(username).first().waitFor();

  return { username, password };
}
