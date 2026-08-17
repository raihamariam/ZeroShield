import { ApiError } from "@/lib/api/client";
import { cn } from "@/lib/utils/cn";

function describeError(error: unknown): { title: string; detail: string } {
  if (error instanceof ApiError) {
    if (error.isUnreachable) {
      return {
        title: "ZeroShield API is unreachable",
        detail: "The backend did not respond. Check that the API and its dependencies are running.",
      };
    }
    if (error.status === 404) {
      return { title: "Not found", detail: error.body?.detail ?? "The requested item does not exist." };
    }
    return {
      title: `Request failed (HTTP ${error.status})`,
      detail: error.body?.detail ?? error.message,
    };
  }
  if (error instanceof Error) {
    return { title: "Something went wrong", detail: error.message };
  }
  return { title: "Something went wrong", detail: "An unexpected error occurred." };
}

export function ErrorState({ error, className }: { error: unknown; className?: string }) {
  const { title, detail } = describeError(error);
  return (
    <div
      role="alert"
      className={cn(
        "rounded-xl border border-danger-bg bg-danger-bg p-4 text-sm text-danger",
        className
      )}
    >
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-danger/90">{detail}</p>
    </div>
  );
}
