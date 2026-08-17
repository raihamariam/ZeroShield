import type { Metadata } from "next";
import Link from "next/link";
import { Badge, Card, CardBody, CardHeader } from "@/components/ui";

export const metadata: Metadata = { title: "Legacy Dashboard" };

export default function LegacyDashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-semibold text-foreground">Legacy Dashboard</h1>
          <Badge variant="warning">Legacy · Read-only</Badge>
        </div>
        <p className="mt-1 text-sm text-text-muted">
          The original Streamlit demonstration dashboard (Milestone 18), kept for read-only reference during the
          transition to this web application.
        </p>
      </div>

      <Card>
        <CardHeader title="What changed" />
        <CardBody className="flex flex-col gap-2 text-sm text-foreground">
          <p>
            This web application is now the primary ZeroShield interface. The Streamlit dashboard&apos;s run-execution
            path has been disabled so it can no longer trigger a run outside of - and therefore bypass - the
            Experiment Studio approval workflow this app enforces. It remains available for browsing experiments,
            results, evidence, and the Overleaf export, none of which write governance state.
          </p>
          <p>
            To submit a run, use{" "}
            <Link href="/experiments" className="text-accent hover:underline">
              Experiments
            </Link>{" "}
            or{" "}
            <Link href="/experiment-studio" className="text-accent hover:underline">
              Experiment Studio
            </Link>{" "}
            here instead.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Open the legacy dashboard" />
        <CardBody className="flex flex-col gap-2 text-sm">
          <p className="text-text-muted">
            Runs as a separate service (see <code className="font-mono text-xs">docker-compose.yml</code>) on port
            8502.
          </p>
          <a
            href="http://localhost:8502"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex w-fit items-center rounded-lg border border-border px-3.5 py-2 font-medium text-foreground hover:bg-surface-muted"
          >
            Open legacy dashboard ↗
          </a>
        </CardBody>
      </Card>
    </div>
  );
}
