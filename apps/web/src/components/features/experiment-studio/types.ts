import type { CveRowState } from "@/lib/experimentStudio";
import type { DomainPackResponse, ValidationTemplateResponse } from "@/lib/api/types";

export type ExperimentMode = "new" | "existing";

export interface WizardState {
  domain: "VPN" | "TELECOM" | null;
  cves: CveRowState[];

  domainPacks: DomainPackResponse[];
  domainPackId: string;
  templates: ValidationTemplateResponse[];
  templateId: string;
  templateVersion: string;

  experimentMode: ExperimentMode;
  experimentId: string;
  existingExperimentIds: string[];
  title: string;
  description: string;

  seed: number;
  datasetConfig: Record<string, number>;
  datasetJsonMode: boolean;
  datasetJsonText: string;

  metricsSelected: string[];

  failurePattern: string;
  rootCause: string;
  vendorMitigation: string;
  mitigationGap: string;
  researchQuestion: string;
  hypothesis: string;
  createdBy: string;
}

export interface StepProps {
  state: WizardState;
  update: (patch: Partial<WizardState>) => void;
}
