import Link from "next/link";
import { cn } from "@/lib/utils/cn";

/** Plain GET-link pagination (no client JS required): builds hrefs against the current
 * search params with only "offset" changed, so back/forward and shareable URLs work. */
export function Pagination({
  total,
  limit,
  offset,
  basePath,
  searchParams,
}: {
  total: number;
  limit: number;
  offset: number;
  basePath: string;
  searchParams: Record<string, string | undefined>;
}) {
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.floor(offset / limit) + 1;

  function hrefForOffset(nextOffset: number): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && key !== "offset") params.set(key, value);
    }
    params.set("offset", String(nextOffset));
    return `${basePath}?${params.toString()}`;
  }

  const canPrev = offset > 0;
  const canNext = offset + limit < total;

  if (total === 0) return null;

  return (
    <nav
      aria-label="Pagination"
      className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-3 py-3 text-sm"
    >
      <p className="text-text-muted">
        Showing <span className="font-medium text-foreground">{offset + 1}</span>–
        <span className="font-medium text-foreground">{Math.min(offset + limit, total)}</span> of{" "}
        <span className="font-medium text-foreground">{total}</span>
        {" · "}Page {currentPage} of {totalPages}
      </p>
      <div className="flex gap-2">
        <PaginationLink href={hrefForOffset(Math.max(0, offset - limit))} disabled={!canPrev}>
          Previous
        </PaginationLink>
        <PaginationLink href={hrefForOffset(offset + limit)} disabled={!canNext}>
          Next
        </PaginationLink>
      </div>
    </nav>
  );
}

function PaginationLink({
  href,
  disabled,
  children,
}: {
  href: string;
  disabled: boolean;
  children: string;
}) {
  const classes = cn(
    "rounded-lg border border-border px-3 py-1.5 font-medium",
    disabled ? "pointer-events-none opacity-40" : "hover:bg-surface-muted"
  );
  if (disabled) {
    return (
      <span className={classes} aria-disabled="true">
        {children}
      </span>
    );
  }
  return (
    <Link href={href} className={classes}>
      {children}
    </Link>
  );
}
