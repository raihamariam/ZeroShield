"use client";

import { Badge } from "@/components/ui";
import { titleCase } from "@/lib/utils/format";
import type { StepProps } from "./types";

export function stepMetricsErrors(state: { metricsSelected: string[] }): string[] {
  return state.metricsSelected.length === 0 ? ["Select at least one metric to collect."] : [];
}

export function StepStrategyMetrics({ state, update }: StepProps) {
  const template = state.templates.find((t) => t.template_id === state.templateId);
  if (!template) return <p className="text-sm text-text-muted">Choose a template first.</p>;

  const baseline = template.allowed_baseline_strategies[0];
  const mitigation = template.allowed_mitigation_strategies[0];

  function toggle(metric: string) {
    const selected = state.metricsSelected.includes(metric)
      ? state.metricsSelected.filter((m) => m !== metric)
      : [...state.metricsSelected, metric];
    update({ metricsSelected: selected });
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-base font-semibold text-foreground">Baseline & mitigation strategies</h2>
        <p className="mt-1 text-sm text-text-muted">
          Prescribed by the template - ZeroShield doesn&apos;t let you pair arbitrary strategies, only the ones a
          template has been validated with.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-border p-3">
            <p className="text-xs font-medium tracking-wide text-text-muted uppercase">Baseline (deliberately weak)</p>
            <p className="mt-1 font-mono text-sm text-foreground">{baseline}</p>
          </div>
          <div className="rounded-lg border border-border p-3">
            <p className="text-xs font-medium tracking-wide text-text-muted uppercase">Mitigation (candidate)</p>
            <p className="mt-1 font-mono text-sm text-foreground">{mitigation}</p>
          </div>
        </div>
      </div>

      <div>
        <h2 className="text-base font-semibold text-foreground">Metrics to collect</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          {template.metrics_to_collect.map((metric) => {
            const selected = state.metricsSelected.includes(metric);
            return (
              <button
                key={metric}
                type="button"
                onClick={() => toggle(metric)}
                aria-pressed={selected}
                className="rounded-full"
              >
                <Badge variant={selected ? "accent" : "neutral"}>{titleCase(metric)}</Badge>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
