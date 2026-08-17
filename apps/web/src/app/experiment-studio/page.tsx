import type { Metadata } from "next";
import { ExperimentStudioWizard } from "@/components/features/experiment-studio/ExperimentStudioWizard";

export const metadata: Metadata = { title: "Experiment Studio" };

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ExperimentStudioPage(props: PageProps<"/experiment-studio">) {
  const raw = await props.searchParams;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Experiment Studio</h1>
        <p className="mt-1 text-sm text-text-muted">
          Build a validated experiment version from a CVE, a domain pack, and a validation template - no hand-authored
          JSON required. It&apos;s saved as a draft first; nothing runs until it&apos;s approved.
        </p>
      </div>
      <ExperimentStudioWizard
        initialCveId={firstValue(raw.cve)}
        initialDomainPack={firstValue(raw.domain_pack)}
        initialTemplate={firstValue(raw.template)}
      />
    </div>
  );
}
