import type { ReactNode } from "react";
import Link from "next/link";
import { cn } from "@/lib/utils/cn";

export type StatTileTone = "neutral" | "success" | "warning" | "danger" | "info";

const TONE_CLASSES: Record<StatTileTone, string> = {
  neutral: "text-foreground",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
  info: "text-info",
};

/** A single Mission Control metric card: a real API-derived number, its label, and an
 * optional link into the page that explains it - never a hard-coded demo figure. */
export function StatTile({
  label,
  value,
  tone = "neutral",
  href,
  hint,
  className,
}: {
  label: string;
  value: ReactNode;
  tone?: StatTileTone;
  href?: string;
  hint?: string;
  className?: string;
}) {
  const content = (
    <div className={cn("rounded-xl border border-border bg-surface p-4", href && "hover:bg-surface-muted", className)}>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className={cn("mt-1 text-2xl font-semibold tabular-nums", TONE_CLASSES[tone])}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-text-muted">{hint}</p> : null}
    </div>
  );

  if (href) {
    return (
      <Link href={href} className="block focus-visible:rounded-xl">
        {content}
      </Link>
    );
  }
  return content;
}
