"use client";

import { useEffect } from "react";
import { FormField, Input, Select, Textarea } from "@/components/ui/Field";
import { EXPERIMENT_ID_PATTERN, suggestNextExperimentId } from "@/lib/experimentStudio";
import type { StepProps } from "./types";

export function stepIdentityErrors(state: { experimentId: string; title: string; description: string; domain: string | null }): string[] {
  const errors: string[] = [];
  if (!EXPERIMENT_ID_PATTERN.test(state.experimentId)) {
    errors.push("Experiment ID must look like ZC-VPN-EXP-004 or ZC-TELECOM-EXP-004.");
  } else if (state.domain && !state.experimentId.includes(`-${state.domain}-`)) {
    errors.push(`Experiment ID must match the chosen domain (${state.domain}).`);
  }
  if (!state.title.trim()) errors.push("Title is required.");
  if (!state.description.trim()) errors.push("Description is required.");
  return errors;
}

export function StepIdentity({ state, update }: StepProps) {
  useEffect(() => {
    if (!state.domain || state.experimentMode !== "new" || state.experimentId) return;
    update({ experimentId: suggestNextExperimentId(state.domain, state.existingExperimentIds) });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.domain, state.existingExperimentIds]);

  const existingForDomain = state.existingExperimentIds.filter((id) => state.domain && id.includes(`-${state.domain}-`));

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-base font-semibold text-foreground">Experiment</h2>
        <div className="mt-3 flex gap-3">
          <button
            type="button"
            onClick={() =>
              update({
                experimentMode: "new",
                experimentId: state.domain ? suggestNextExperimentId(state.domain, state.existingExperimentIds) : "",
              })
            }
            className={`rounded-lg border px-4 py-2 text-sm font-medium ${
              state.experimentMode === "new" ? "border-accent bg-accent text-accent-foreground" : "border-border hover:bg-surface-muted"
            }`}
          >
            New experiment
          </button>
          <button
            type="button"
            onClick={() => update({ experimentMode: "existing", experimentId: existingForDomain[0] ?? "" })}
            disabled={existingForDomain.length === 0}
            className={`rounded-lg border px-4 py-2 text-sm font-medium disabled:opacity-40 ${
              state.experimentMode === "existing" ? "border-accent bg-accent text-accent-foreground" : "border-border hover:bg-surface-muted"
            }`}
          >
            New version of an existing experiment
          </button>
        </div>

        <div className="mt-3 max-w-sm">
          {state.experimentMode === "new" ? (
            <FormField id="experiment-id" label="Experiment ID" hint="Suggested from existing IDs in this domain - editable.">
              <Input
                id="experiment-id"
                value={state.experimentId}
                onChange={(e) => update({ experimentId: e.target.value.toUpperCase() })}
                className="font-mono"
              />
            </FormField>
          ) : (
            <FormField id="experiment-id-existing" label="Existing experiment">
              <Select id="experiment-id-existing" value={state.experimentId} onChange={(e) => update({ experimentId: e.target.value })}>
                {existingForDomain.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </Select>
            </FormField>
          )}
        </div>
      </div>

      <FormField id="title" label="Title" required>
        <Input id="title" value={state.title} onChange={(e) => update({ title: e.target.value })} />
      </FormField>
      <FormField id="description" label="Description" required>
        <Textarea id="description" rows={4} value={state.description} onChange={(e) => update({ description: e.target.value })} />
      </FormField>
    </div>
  );
}
