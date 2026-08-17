import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/** V2 Phase 6: gates the whole app behind a session. Only checks for the
 * session cookie's PRESENCE (cheap, no network call) - an expired/invalid
 * session still reaches the page, whose own server-side data fetch then
 * gets a real 401 from the backend (see RootLayout, which treats that the
 * same as "not logged in" for display purposes). This is a UX redirect, not
 * the security boundary - the backend's own get_current_user dependency is
 * the actual enforcement point for every route (see docs/V2_SECURITY.md);
 * this proxy only saves a logged-out user from staring at a page full of
 * ErrorState "not authenticated" cards instead of a login form.
 */
const SESSION_COOKIE_NAME = "zeroshield_session";

export function proxy(request: NextRequest) {
  if (request.cookies.has(SESSION_COOKIE_NAME)) {
    return NextResponse.next();
  }
  const loginUrl = new URL("/login", request.url);
  loginUrl.searchParams.set("next", request.nextUrl.pathname);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: [
    /*
     * Every path except:
     * - /login (the page this proxy redirects to - avoid a redirect loop)
     * - /api (proxied straight to FastAPI, which enforces auth itself and
     *   returns a real 401/403 JSON body a client component can handle)
     * - Next.js internals and static assets
     */
    "/((?!login|api|_next/static|_next/image|favicon.ico).*)",
  ],
};
