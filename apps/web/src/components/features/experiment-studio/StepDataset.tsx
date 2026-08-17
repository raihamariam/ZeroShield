"use client";

import { useState } from "react";
import { Badge } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Textarea } from "@/components/ui/Field";
import { studioApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import type { GenerateDatasetResponse } from "@/lib/api/types";
import { GENERATOR_CONFIGS } from "@/lib/generatorConfigs";
import type { StepProps } from "./types";

export function stepDatasetErrors(state: { seed: number; datasetJsonMode: boolean; datasetJsonText: string }): string[] {
  const errors: string[] = [];
  if (!Number.isFinite(state.seed)) errors.push("Seed must be a number.");
  if (state.datasetJsonMode) {
    try {
      JSON.parse(state.datasetJsonText || "{}");
    } catch {
      errors.push("Dataset config JSON is not valid JSON.");
    }
  }
  return errors;
}

export function StepDataset({ state, update }: StepProps) {
  const [preview, setPreview] = useState<GenerateDatasetResponse | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);

  const pack = state.domainPacks.find((p) => p.pack_id === state.domainPackId);
  const spec = pack ? GENERATOR_CONFIGS[pack.dataset_generator_id] : undefined;

  function resolveConfig(): Record<string, unknown> {
    if (state.datasetJsonMode) {
      try {
        return JSON.parse(state.datasetJsonText || "{}");
      } catch {
        return {};
      }
    }
    return state.datasetConfig;
  }

  async function handlePreview() {
    if (!pack) return;
    setPreviewing(true);
    setPreviewError(null);
    setPreview(null);
    try {
      const result = await studioApi.generateDataset({
        domain_pack_id: pack.pack_id,
        seed: state.seed,
        config: resolveConfig(),
      });
      setPreview(result);
    } catch (err) {
      setPreviewError(err instanceof ApiError ? err.message : "Preview failed.");
    } finally {
      setPreviewing(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <FormField id="seed" label="Seed" hint="Same domain pack + seed + config always reproduces the same dataset." className="max-w-xs">
        <Input id="seed" type="number" value={state.seed} onChange={(e) => update({ seed: Number.parseInt(e.target.value, 10) || 0 })} />
      </FormField>

      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-foreground">Dataset configuration</h2>
        {spec ? (
          <button
            type="button"
            onClick={() =>
              update({
                datasetJsonMode: !state.datasetJsonMode,
                datasetJsonText: state.datasetJsonMode ? state.datasetJsonText : JSON.stringify(state.datasetConfig, null, 2),
              })
            }
            className="text-xs font-medium text-accent hover:underline"
          >
            {state.datasetJsonMode ? "Use structured fields" : "Advanced: edit as JSON"}
          </button>
        ) : null}
      </div>

      {!spec ? (
        <div>
          <p className="text-sm text-text-muted">
            No structured field spec is known for generator <span className="font-mono">{pack?.dataset_generator_id}</span> - configure it
            as JSON.
          </p>
          <Textarea
            rows={8}
            value={state.datasetJsonText}
            onChange={(e) => update({ datasetJsonText: e.target.value })}
            className="mt-2 font-mono text-xs"
          />
        </div>
      ) : state.datasetJsonMode ? (
        <Textarea
          rows={10}
          value={state.datasetJsonText}
          onChange={(e) => update({ datasetJsonText: e.target.value })}
          className="font-mono text-xs"
        />
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {spec.map((field) => (
            <FormField key={field.key} id={`ds-${field.key}`} label={field.label} hint={field.hint}>
              <Input
                id={`ds-${field.key}`}
                type="number"
                min={field.min}
                max={field.max}
                value={state.datasetConfig[field.key] ?? field.default}
                onChange={(e) =>
                  update({
                    datasetConfig: { ...state.datasetConfig, [field.key]: Number.parseInt(e.target.value, 10) || 0 },
                  })
                }
              />
            </FormField>
          ))}
        </div>
      )}

      <div>
        <Button type="button" variant="secondary" onClick={handlePreview} disabled={previewing || !pack}>
          {previewing ? "Generating preview…" : "Preview dataset"}
        </Button>
        {previewError ? <p className="mt-2 text-sm font-medium text-danger">{previewError}</p> : null}
        {preview ? (
          <div className="mt-3 rounded-lg border border-border p-3 text-sm">
            <p className="text-foreground">
              {preview.case_count} cases · sha256 <span className="font-mono text-xs">{preview.sha256.slice(0, 16)}…</span>
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {Object.entries(preview.cases_by_category).map(([cat, count]) => (
                <Badge key={cat} variant="neutral">
                  {cat}: {count}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
