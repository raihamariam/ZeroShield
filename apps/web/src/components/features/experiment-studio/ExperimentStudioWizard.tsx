"use client";

import { useEffect, useState } from "react";
import { Card, CardBody } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { experimentsApi, intelligenceApi, studioApi } from "@/lib/api";
import { emptyCveRow } from "@/lib/experimentStudio";
import { StepVulnerability, stepVulnerabilityErrors } from "./StepVulnerability";
import { StepDomainTemplate, stepDomainTemplateErrors } from "./StepDomainTemplate";
import { StepIdentity, stepIdentityErrors } from "./StepIdentity";
import { StepDataset, stepDatasetErrors } from "./StepDataset";
import { StepStrategyMetrics, stepMetricsErrors } from "./StepStrategyMetrics";
import { StepNarrative, stepNarrativeErrors } from "./StepNarrative";
import { StepReview } from "./StepReview";
import type { WizardState } from "./types";

const STEPS = ["Vulnerability", "Domain & template", "Identity", "Dataset", "Strategy & metrics", "Narrative", "Review & submit"] as const;

function initialState(initial: { domainPack?: string; template?: string; cve?: string }): WizardState {
  return {
    domain: null,
    cves: initial.cve ? [emptyCveRow(crypto.randomUUID())] : [],
    domainPacks: [],
    domainPackId: initial.domainPack ?? "",
    templates: [],
    templateId: initial.template ?? "",
    templateVersion: "",
    experimentMode: "new",
    experimentId: "",
    existingExperimentIds: [],
    title: "",
    description: "",
    seed: Math.floor(Math.random() * 1_000_000),
    datasetConfig: {},
    datasetJsonMode: false,
    datasetJsonText: "{}",
    metricsSelected: [],
    failurePattern: "",
    rootCause: "",
    vendorMitigation: "",
    mitigationGap: "",
    researchQuestion: "",
    hypothesis: "",
  };
}

export function ExperimentStudioWizard({ initialCveId, initialDomainPack, initialTemplate }: { initialCveId?: string; initialDomainPack?: string; initialTemplate?: string }) {
  const [step, setStep] = useState(0);
  const [state, setState] = useState<WizardState>(() =>
    initialState({ domainPack: initialDomainPack, template: initialTemplate, cve: initialCveId })
  );

  function update(patch: Partial<WizardState>) {
    setState((prev) => ({ ...prev, ...patch }));
  }

  useEffect(() => {
    studioApi.listDomainPacks().then((res) => update({ domainPacks: res.domain_packs }));
    Promise.all([experimentsApi.listExperiments(), studioApi.listExperimentVersions({})])
      .then(([experiments, versions]) => {
        const ids = new Set<string>([...experiments.experiments.map((e) => e.experiment_id), ...versions.versions.map((v) => v.experiment_id)]);
        update({ existingExperimentIds: [...ids] });
      })
      .catch(() => {});
    if (initialCveId) {
      intelligenceApi
        .getVulnerability(initialCveId)
        .then((vuln) => {
          setState((prev) => ({
            ...prev,
            domain: (vuln.domain_guess as "VPN" | "TELECOM" | null) ?? prev.domain,
            cves: prev.cves.map((row, i) =>
              i === 0
                ? {
                    ...row,
                    cve_id: initialCveId,
                    cvss_score: vuln.cvss_score !== null ? String(vuln.cvss_score) : "",
                    cisa_kev: vuln.kev_listed,
                    epss_score: vuln.epss_score !== null ? String(vuln.epss_score) : "",
                    source_urls: vuln.references.join("\n"),
                  }
                : row
            ),
          }));
        })
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stepErrors: string[][] = [
    stepVulnerabilityErrors(state),
    stepDomainTemplateErrors(state),
    stepIdentityErrors(state),
    stepDatasetErrors(state),
    stepMetricsErrors(state),
    stepNarrativeErrors(state),
    [],
  ];
  const canAdvance = stepErrors[step].length === 0;

  return (
    <div className="flex flex-col gap-6">
      <ol className="flex flex-wrap gap-2 text-xs">
        {STEPS.map((label, i) => (
          <li key={label}>
            <button
              type="button"
              onClick={() => i < step && setStep(i)}
              disabled={i > step}
              className={`rounded-full border px-3 py-1 font-medium ${
                i === step
                  ? "border-accent bg-accent text-accent-foreground"
                  : i < step
                    ? "border-border text-foreground hover:bg-surface-muted"
                    : "border-border text-text-muted opacity-50"
              }`}
            >
              {i + 1}. {label}
            </button>
          </li>
        ))}
      </ol>

      <Card>
        <CardBody>
          {step === 0 ? <StepVulnerability state={state} update={update} /> : null}
          {step === 1 ? <StepDomainTemplate state={state} update={update} /> : null}
          {step === 2 ? <StepIdentity state={state} update={update} /> : null}
          {step === 3 ? <StepDataset state={state} update={update} /> : null}
          {step === 4 ? <StepStrategyMetrics state={state} update={update} /> : null}
          {step === 5 ? <StepNarrative state={state} update={update} /> : null}
          {step === 6 ? <StepReview state={state} update={update} /> : null}
        </CardBody>
      </Card>

      {step < STEPS.length - 1 ? (
        <div className="flex items-center justify-between">
          <Button variant="ghost" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
            Back
          </Button>
          <div className="text-right">
            {!canAdvance && stepErrors[step].length > 0 ? (
              <ul className="mb-2 text-xs text-danger">
                {stepErrors[step].slice(0, 3).map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            ) : null}
            <Button variant="primary" onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))} disabled={!canAdvance}>
              Next
            </Button>
          </div>
        </div>
      ) : (
        <div>
          <Button variant="ghost" onClick={() => setStep((s) => Math.max(0, s - 1))}>
            Back
          </Button>
        </div>
      )}
    </div>
  );
}
