import { SkeletonTable } from "./Skeleton";

/** Shared loading.tsx body for list-style routes (filter form + table) - keeps every
 * route's loading.tsx a thin wrapper instead of duplicating this markup per route. */
export function ListPageSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className="h-16 animate-pulse rounded-xl border border-border bg-surface-muted" aria-hidden="true" />
      <div className="rounded-xl border border-border bg-surface">
        <SkeletonTable rows={8} columns={6} />
      </div>
    </div>
  );
}
