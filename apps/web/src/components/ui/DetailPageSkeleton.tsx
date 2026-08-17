import { SkeletonCard, SkeletonText } from "./Skeleton";

/** Shared loading.tsx body for detail routes that render several stacked cards. */
export function DetailPageSkeleton({ cards = 3 }: { cards?: number }) {
  return (
    <div className="flex flex-col gap-6">
      <div className="h-8 w-64 animate-pulse rounded-md bg-surface-muted" aria-hidden="true" />
      {Array.from({ length: cards }).map((_, i) => (
        <div key={i} className="rounded-xl border border-border bg-surface p-4">
          <SkeletonText lines={3} />
        </div>
      ))}
      <SkeletonCard />
    </div>
  );
}
