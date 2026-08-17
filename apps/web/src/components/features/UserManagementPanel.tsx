"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { authApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { Role, UserResponse } from "@/lib/api/types";
import { formatDateTime, titleCase } from "@/lib/utils/format";

const ROLES: Role[] = ["viewer", "researcher", "reviewer", "admin"];

/** ADMIN-only (V2 Phase 6, Step 2: "ADMIN: users, integration configuration
 * and system settings"). Every mutation here goes straight to the real
 * /users routes, which enforce ADMIN themselves - this panel only exists
 * for a caller who already passed that check to reach the page at all. */
export function UserManagementPanel({ users, currentUsername }: { users: UserResponse[]; currentUsername: string }) {
  const router = useRouter();
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ username: "", password: "", role: "researcher" as Role });
  const [error, setError] = useState<string | null>(null);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);

  async function handleCreate() {
    setError(null);
    try {
      await authApi.createUser(form);
      setForm({ username: "", password: "", role: "researcher" });
      setCreating(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create user.");
    }
  }

  async function handleRoleChange(userId: string, role: Role) {
    setBusyUserId(userId);
    setError(null);
    try {
      await authApi.updateUserRole(userId, { role });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to change role.");
    } finally {
      setBusyUserId(null);
    }
  }

  async function handleActiveToggle(userId: string, active: boolean) {
    setBusyUserId(userId);
    setError(null);
    try {
      await authApi.updateUserActive(userId, { active });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update user.");
    } finally {
      setBusyUserId(null);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {creating ? (
        <div className="grid grid-cols-1 gap-3 rounded-xl border border-border bg-surface p-4 sm:grid-cols-4">
          <FormField id="new-username" label="Username">
            <Input id="new-username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </FormField>
          <FormField id="new-password" label="Password" hint="At least 12 characters.">
            <Input
              id="new-password"
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
          </FormField>
          <FormField id="new-role" label="Role">
            <Select id="new-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {titleCase(r)}
                </option>
              ))}
            </Select>
          </FormField>
          <div className="flex items-end gap-2">
            <Button variant="primary" onClick={handleCreate} disabled={!form.username.trim() || form.password.length < 12}>
              Create
            </Button>
            <Button variant="ghost" onClick={() => setCreating(false)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="primary" onClick={() => setCreating(true)}>
          Create user
        </Button>
      )}

      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}

      <TableContainer>
        <Table>
          <THead>
            <TR>
              <TH>Username</TH>
              <TH>Role</TH>
              <TH>Status</TH>
              <TH>Created</TH>
              <TH></TH>
            </TR>
          </THead>
          <TBody>
            {users.map((u) => (
              <TR key={u.user_id}>
                <TD>
                  {u.username}
                  {u.username === currentUsername ? <span className="ml-2 text-xs text-text-muted">(you)</span> : null}
                </TD>
                <TD>
                  <Select
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.user_id, e.target.value as Role)}
                    disabled={busyUserId === u.user_id}
                    className="w-36"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {titleCase(r)}
                      </option>
                    ))}
                  </Select>
                </TD>
                <TD>{u.active ? <Badge variant="success">Active</Badge> : <Badge variant="neutral">Inactive</Badge>}</TD>
                <TD title={formatDateTime(u.created_at)}>{formatDateTime(u.created_at)}</TD>
                <TD>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busyUserId === u.user_id || u.username === currentUsername}
                    onClick={() => handleActiveToggle(u.user_id, !u.active)}
                  >
                    {u.active ? "Deactivate" : "Reactivate"}
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </TableContainer>
    </div>
  );
}
