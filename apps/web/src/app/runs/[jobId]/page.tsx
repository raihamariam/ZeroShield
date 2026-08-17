import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ErrorState } from "@/components/ui";
import { LiveRunView } from "@/components/features/LiveRunView";
import { ApiError } from "@/lib/api/client";
import { jobsApi } from "@/lib/api";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/runs/[jobId]">): Promise<Metadata> {
  const { jobId } = await props.params;
  return { title: jobId };
}

export default async function RunDetailPage(props: PageProps<"/runs/[jobId]">) {
  const { jobId } = await props.params;

  let job;
  try {
    job = await jobsApi.getJob(jobId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">{job.job_id}</h1>
        <p className="mt-1 text-sm text-text-muted">Live run for experiment {job.experiment_id}</p>
      </div>
      <LiveRunView jobId={jobId} initialJob={job} />
    </div>
  );
}
