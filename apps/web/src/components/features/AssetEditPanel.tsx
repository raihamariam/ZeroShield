"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { FormField, Select } from "@/components/ui/Field";
import { assetsApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { AssetResponse } from "@/lib/api/types";

export function AssetEditPanel({ asset }: { asset: AssetResponse }) {
  const router = useRouter();
  const [environment, setEnvironment] = useState(asset.environment);
  const [exposure, setExposure] = useState(asset.exposure);
  const [criticality, setCriticality] = useState(asset.criticality);
  const [active, setActive] = useState(asset.active);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSubmitting(true);
    setError(null);
    try {
      await assetsApi.updateAsset(asset.asset_id, { environment, exposure, criticality, active });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Update failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <FormField id="environment" label="Environment">
          <Select id="environment" value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
          </Select>
        </FormField>
        <FormField id="exposure" label="Exposure">
          <Select id="exposure" value={exposure} onChange={(e) => setExposure(e.target.value)}>
            <option value="internet_facing">Internet-facing</option>
            <option value="internal">Internal</option>
            <option value="isolated">Isolated</option>
          </Select>
        </FormField>
        <FormField id="criticality" label="Criticality">
          <Select id="criticality" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </FormField>
      </div>
      <label className="flex items-center gap-2 text-sm text-foreground">
        <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
        Active
      </label>
      {error ? <p className="text-sm font-medium text-danger">{error}</p> : null}
      <div>
        <Button variant="primary" size="sm" onClick={save} disabled={submitting}>
          {submitting ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </div>
  );
}
