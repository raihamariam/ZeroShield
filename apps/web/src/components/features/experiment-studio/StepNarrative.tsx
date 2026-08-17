"use client";

import { FormField, Input, Select, Textarea } from "@/components/ui/Field";
import { ROOT_CAUSE_CATEGORIES } from "@/lib/experimentStudio";
import type { StepProps } from "./types";

export function stepNarrativeErrors(state: {
  failurePattern: string;
  rootCause: string;
  vendorMitigation: string;
  mitigationGap: string;
  researchQuestion: string;
  hypothesis: string;
}): string[] {
  const errors: string[] = [];
  if (!state.failurePattern) errors.push("Failure pattern is required.");
  if (!state.rootCause) errors.push("Root cause is required.");
  if (!state.vendorMitigation.trim()) errors.push("Vendor mitigation is required.");
  if (!state.mitigationGap.trim()) errors.push("Mitigation gap is required.");
  if (!state.researchQuestion.trim()) errors.push("Research question is required.");
  if (!state.hypothesis.trim()) errors.push("Hypothesis is required.");
  return errors;
}

export function StepNarrative({ state, update }: StepProps) {
  const template = state.templates.find((t) => t.template_id === state.templateId);

  return (
    <div className="flex flex-col gap-4">
      <FormField id="failure-pattern" label="Failure pattern" required>
        <Select id="failure-pattern" value={state.failurePattern} onChange={(e) => update({ failurePattern: e.target.value })}>
          <option value="">Select…</option>
          {(template?.supported_failure_patterns ?? []).map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
      </FormField>
      <FormField id="root-cause" label="Root cause" required>
        <Select id="root-cause" value={state.rootCause} onChange={(e) => update({ rootCause: e.target.value })}>
          <option value="">Select…</option>
          {ROOT_CAUSE_CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </Select>
      </FormField>
      <FormField id="vendor-mitigation" label="Vendor mitigation" required hint="Overall, experiment-level summary (each CVE also has its own).">
        <Input id="vendor-mitigation" value={state.vendorMitigation} onChange={(e) => update({ vendorMitigation: e.target.value })} />
      </FormField>
      <FormField id="mitigation-gap" label="Mitigation gap" required>
        <Input id="mitigation-gap" value={state.mitigationGap} onChange={(e) => update({ mitigationGap: e.target.value })} />
      </FormField>
      <FormField id="research-question" label="Research question" required>
        <Textarea id="research-question" rows={2} value={state.researchQuestion} onChange={(e) => update({ researchQuestion: e.target.value })} />
      </FormField>
      <FormField id="hypothesis" label="Hypothesis" required>
        <Textarea id="hypothesis" rows={2} value={state.hypothesis} onChange={(e) => update({ hypothesis: e.target.value })} />
      </FormField>
    </div>
  );
}
