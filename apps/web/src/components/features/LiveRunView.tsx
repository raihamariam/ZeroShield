"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Badge, StatusPill } from "@/components/ui";
import { jobsApi } from "@/lib/api";
import type { JobStatusResponse, RunEventPayload, RunEventType } from "@/lib/api/types";
import { formatDateTime, formatRelativeToNow } from "@/lib/utils/format";
import { cn } from "@/lib/utils/cn";

const HAPPY_PATH: RunEventType[] = [
  "queued",
  "preparing",
  "safety_check",
  "running_baseline",
  "running_mitigation",
  "analysing",
  "generating_evidence",
];

const STAGE_LABELS: Record<RunEventType, string> = {
  queued: "Queued",
  preparing: "Preparing",
  safety_check: "Safety check",
  running_baseline: "Running baseline",
  running_mitigation: "Running mitigation",
  analysing: "Analysing",
  generating_evidence: "Generating evidence",
  completed: "Complete",
  denied: "Denied",
  failed: "Failed",
};

type ConnectionState = "connecting" | "open" | "closed";

/** Live run progress, driven entirely by the real RunEvent trail streamed from
 * GET /jobs/{job_id}/events (SSE) - never a fabricated progress percentage. If
 * DATABASE_URL isn't configured on the backend, that stream degrades honestly to
 * just the terminal job_status with no intermediate events, and this view renders
 * that faithfully (unreached stages stay grey, nothing is guessed). */
export function LiveRunView({ jobId, initialJob }: { jobId: string; initialJob: JobStatusResponse }) {
  const [job, setJob] = useState<JobStatusResponse>(initialJob);
  const [events, setEvents] = useState<RunEventPayload[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [streamTimedOut, setStreamTimedOut] = useState(false);
  const seenKeys = useRef(new Set<string>());

  useEffect(() => {
    const source = new EventSource(jobsApi.jobEventsUrl(jobId));

    source.onopen = () => setConnection("open");

    source.addEventListener("run_event", (raw) => {
      const payload = JSON.parse((raw as MessageEvent).data) as RunEventPayload;
      const key = `${payload.event_type}:${payload.occurred_at}`;
      if (seenKeys.current.has(key)) return;
      seenKeys.current.add(key);
      setEvents((prev) => [...prev, payload]);
    });

    source.addEventListener("job_terminal", (raw) => {
      const payload = JSON.parse((raw as MessageEvent).data) as {
        job_status: JobStatusResponse["status"];
        error: string | null;
      };
      setConnection("closed");
      source.close();
      // The SSE payload only carries status+error; refetch once for the full record
      // (result summary, timestamps) now that it's final.
      jobsApi
        .getJob(jobId)
        .then(setJob)
        .catch(() => setJob((prev) => ({ ...prev, status: payload.job_status, error: payload.error })));
    });

    source.addEventListener("stream_timeout", () => {
      setConnection("closed");
      setStreamTimedOut(true);
      source.close();
    });

    source.onerror = () => {
      setConnection((current) => (current === "closed" ? current : "connecting"));
    };

    return () => source.close();
  }, [jobId]);

  const reached = new Set(events.map((e) => e.event_type));
  const lastEvent = events[events.length - 1];
  const isTerminal = job.status === "completed" || job.status === "failed" || job.status === "denied";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill status={job.status} />
        {!isTerminal ? <ConnectionBadge state={connection} /> : null}
        <span className="text-sm text-text-muted">
          Submitted {formatRelativeToNow(job.submitted_at)} · Updated {formatRelativeToNow(job.updated_at)}
        </span>
      </div>

      <ol className="flex flex-col gap-0">
        {HAPPY_PATH.map((stage, i) => {
          const done = reached.has(stage);
          const isCurrent = !isTerminal && lastEvent?.event_type === stage;
          return (
            <li key={stage} className="flex gap-3">
              <div className="flex flex-col items-center">
                <StageMarker done={done} current={isCurrent} />
                {i < HAPPY_PATH.length - 1 ? (
                  <div className={cn("w-px flex-1 min-h-6", done ? "bg-accent" : "bg-border")} />
                ) : null}
              </div>
              <div className="pb-4">
                <p className={cn("text-sm font-medium", done ? "text-foreground" : "text-text-muted")}>
                  {STAGE_LABELS[stage]}
                </p>
                {events
                  .filter((e) => e.event_type === stage)
                  .map((e, idx) => (
                    <p key={idx} className="text-xs text-text-muted" title={formatDateTime(e.occurred_at)}>
                      {formatRelativeToNow(e.occurred_at)}
                      {e.detail ? ` · ${summariseDetail(e.detail)}` : ""}
                    </p>
                  ))}
              </div>
            </li>
          );
        })}
        <li className="flex gap-3">
          <StageMarker
            done={isTerminal}
            current={false}
            tone={job.status === "failed" || job.status === "denied" ? "danger" : "success"}
          />
          <div>
            <p className={cn("text-sm font-medium", isTerminal ? "text-foreground" : "text-text-muted")}>
              {job.status === "denied" ? "Denied" : job.status === "failed" ? "Failed" : "Complete"}
            </p>
            {isTerminal && job.error ? <p className="mt-0.5 text-xs text-danger">{job.error}</p> : null}
          </div>
        </li>
      </ol>

      {streamTimedOut && !isTerminal ? (
        <p className="text-sm text-warning">
          Live updates stopped after the maximum stream duration.{" "}
          <button type="button" onClick={() => window.location.reload()} className="underline">
            Refresh
          </button>{" "}
          to keep watching, or check back on this page later - the run continues in the background.
        </p>
      ) : null}

      {job.status === "completed" && job.result ? (
        <div className="rounded-xl border border-border bg-surface p-4 text-sm">
          <p className="font-medium text-foreground">Result summary</p>
          <p className="mt-1 text-text-muted">
            {job.result.total_cases} cases · block rate improvement{" "}
            <span className="font-medium text-foreground">{(job.result.block_rate_improvement * 100).toFixed(1)}%</span>
          </p>
          <div className="mt-3 flex gap-4">
            <Link href={`/experiments/${job.experiment_id}`} className="font-medium text-accent hover:underline">
              View full results & verdict →
            </Link>
            <Link href={`/evidence-vault/${job.experiment_id}`} className="font-medium text-accent hover:underline">
              View evidence →
            </Link>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function summariseDetail(detail: Record<string, unknown>): string {
  const entries = Object.entries(detail);
  if (entries.length === 0) return "";
  return entries.map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(", ");
}

function StageMarker({ done, current, tone = "accent" }: { done: boolean; current: boolean; tone?: "accent" | "danger" | "success" }) {
  const toneClasses = {
    accent: "border-accent bg-accent",
    danger: "border-danger bg-danger",
    success: "border-success bg-success",
  } as const;
  return (
    <span
      className={cn(
        "h-3 w-3 shrink-0 rounded-full border-2",
        done ? toneClasses[tone] : "border-border bg-surface",
        current ? "animate-pulse" : ""
      )}
      aria-hidden="true"
    />
  );
}

function ConnectionBadge({ state }: { state: ConnectionState }) {
  if (state === "open") return <Badge variant="success">Live</Badge>;
  if (state === "connecting") return <Badge variant="warning">Connecting…</Badge>;
  return <Badge variant="neutral">Disconnected</Badge>;
}
