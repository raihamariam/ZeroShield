import type { Metadata } from "next";
import { EmptyState } from "@/components/ui";
import { Button } from "@/components/ui/Button";

export const metadata: Metadata = { title: "Not found" };

export default function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you're looking for doesn't exist, or hasn't been built yet."
      action={
        <Button href="/" variant="secondary">
          Back to Mission Control
        </Button>
      }
    />
  );
}
