"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Select } from "@/components/ui/Field";
import { assetsApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";

const EMPTY = {
  asset_id: "", name: "", vendor: "", product: "", version: "",
  environment: "production", exposure: "internal", criticality: "medium",
};

export function CreateAssetForm() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(EMPTY);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function set<K extends keyof typeof EMPTY>(key: K, value: string) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  async function submit() {
    setSubmitting(true);
    setError(null);
    try {
      await assetsApi.createAsset({ ...form, version: form.version || null });
      setForm(EMPTY);
      setOpen(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to register asset.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) {
    return (
      <Button variant="primary" onClick={() => setOpen(true)}>
        Register asset
      </Button>
    );
  }

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-surface p-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <FormField id="asset_id" label="Asset ID" required>
          <Input id="asset_id" value={form.asset_id} onChange={(e) => set("asset_id", e.target.value)} placeholder="ASSET-VPN-01" />
        </FormField>
        <FormField id="name" label="Name" required>
          <Input id="name" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Edge VPN gateway" />
        </FormField>
        <FormField id="vendor" label="Vendor" required>
          <Input id="vendor" value={form.vendor} onChange={(e) => set("vendor", e.target.value)} placeholder="fortinet" />
        </FormField>
        <FormField id="product" label="Product" required>
          <Input id="product" value={form.product} onChange={(e) => set("product", e.target.value)} placeholder="fortios" />
        </FormField>
        <FormField id="version" label="Version" hint="Optional">
          <Input id="version" value={form.version} onChange={(e) => set("version", e.target.value)} placeholder="7.2.1" />
        </FormField>
        <FormField id="environment" label="Environment" required>
          <Select id="environment" value={form.environment} onChange={(e) => set("environment", e.target.value)}>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
          </Select>
        </FormField>
        <FormField id="exposure" label="Exposure" required>
          <Select id="exposure" value={form.exposure} onChange={(e) => set("exposure", e.target.value)}>
            <option value="internet_facing">Internet-facing</option>
            <option value="internal">Internal</option>
            <option value="isolated">Isolated</option>
          </Select>
        </FormField>
        <FormField id="criticality" label="Criticality" required>
          <Select id="criticality" value={form.criticality} onChange={(e) => set("criticality", e.target.value)}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </FormField>
      </div>
      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}
      <div className="flex gap-2">
        <Button
          variant="primary"
          onClick={submit}
          disabled={submitting || !form.asset_id.trim() || !form.name.trim() || !form.vendor.trim() || !form.product.trim()}
        >
          {submitting ? "Registering…" : "Register"}
        </Button>
        <Button variant="ghost" onClick={() => setOpen(false)} disabled={submitting}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
