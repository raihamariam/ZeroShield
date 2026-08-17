import type { Metadata } from "next";
import { UserManagementPanel } from "@/components/features/UserManagementPanel";
import { ErrorState } from "@/components/ui";
import { authApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Users" };

export default async function UsersPage() {
  let users;
  let currentUsername = "";
  try {
    const [listResult, meResult] = await Promise.all([authApi.listUsers(), authApi.me()]);
    users = listResult.users;
    currentUsername = meResult.username;
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return (
        <div className="flex flex-col gap-6">
          <div>
            <h1 className="text-xl font-semibold text-foreground">Users</h1>
            <p className="mt-1 text-sm text-text-muted">System</p>
          </div>
          <ErrorState error={error} />
        </div>
      );
    }
    return <ErrorState error={error} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Users</h1>
        <p className="mt-1 text-sm text-text-muted">
          ADMIN only. Roles are enforced on the backend for every route - changing a role here takes effect
          immediately, on their next request.
        </p>
      </div>
      <UserManagementPanel users={users} currentUsername={currentUsername} />
    </div>
  );
}
