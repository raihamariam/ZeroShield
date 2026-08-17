"use client";

import { useEffect } from "react";
import { Badge } from "@/components/ui";
import { studioApi } from "@/lib/api";
import { defaultConfigFor } from "@/lib/generatorConfigs";
import type { StepProps } from "./types";

export function stepDomainTemplateErrors(state: { domainPackId: string; templateId: string; templateVersion: string }): string[] {
  const errors: string[] = [];
  if (!state.domainPackId) errors.push("Choose a domain pack.");
  if (!state.templateId) errors.push("Choose a validation template.");
  return errors;
}

export function StepDomainTemplate({ state, update }: StepProps) {
  useEffect(() => {
    if (!state.templateId) return;
    const pack = state.domainPacks.find((p) => p.pack_id === state.domainPackId);
    if (pack) {
      update({ datasetConfig: defaultConfigFor(pack.dataset_generator_id) });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.templateId]);

  useEffect(() => {
    if (!state.domainPackId) return;
    let cancelled = false;
    studioApi.listDomainPackTemplates(state.domainPackId).then((res) => {
      if (!cancelled) {
        update({ templates: res.templates });
      }
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.domainPackId]);

  const packsForDomain = state.domainPacks.filter((p) => p.domain === state.domain);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-base font-semibold text-foreground">Domain pack</h2>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {packsForDomain.map((pack) => (
            <button
              key={pack.pack_id}
              type="button"
              onClick={() => update({ domainPackId: pack.pack_id, templateId: "", templateVersion: "", templates: [] })}
              className={`rounded-xl border p-4 text-left ${
                state.domainPackId === pack.pack_id ? "border-accent ring-1 ring-accent" : "border-border hover:bg-surface-muted"
              }`}
            >
              <p className="font-medium text-foreground">{pack.name}</p>
              <p className="mt-1 text-xs text-text-muted">
                {pack.pack_id} · v{pack.version}
              </p>
              <div className="mt-2 flex flex-wrap gap-1">
                {pack.allowed_strategy_ids.map((s) => (
                  <Badge key={s} variant="info">
                    {s}
                  </Badge>
                ))}
              </div>
            </button>
          ))}
        </div>
      </div>

      {state.domainPackId ? (
        <div>
          <h2 className="text-base font-semibold text-foreground">Validation template</h2>
          <div className="mt-3 flex flex-col gap-3">
            {state.templates.map((t) => (
              <button
                key={`${t.template_id}@${t.version}`}
                type="button"
                onClick={() => update({ templateId: t.template_id, templateVersion: t.version })}
                className={`rounded-xl border p-4 text-left ${
                  state.templateId === t.template_id ? "border-accent ring-1 ring-accent" : "border-border hover:bg-surface-muted"
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="font-medium text-foreground">
                    {t.name} <span className="font-mono text-xs text-text-muted">v{t.version}</span>
                  </p>
                  <Badge variant="neutral">{t.safety_level}</Badge>
                </div>
                <p className="mt-1 text-xs text-text-muted">Required fields: {t.required_input_fields.join(", ")}</p>
                <p className="mt-1 text-xs text-text-muted">
                  Baseline <span className="font-mono">{t.allowed_baseline_strategies.join(", ")}</span> · Mitigation{" "}
                  <span className="font-mono">{t.allowed_mitigation_strategies.join(", ")}</span>
                </p>
              </button>
            ))}
            {state.templates.length === 0 ? <p className="text-sm text-text-muted">Loading templates…</p> : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
