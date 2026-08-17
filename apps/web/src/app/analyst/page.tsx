import type { Metadata } from "next";
import Link from "next/link";
import { AssessmentReviewButton } from "@/components/features/AssessmentReviewButton";
import { Badge, EmptyState, ErrorState } from "@/components/ui";
import { Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { analystApi } from "@/lib/api";
import { formatDateTime, formatPercent, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "ZeroShield Analyst" };

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function AnalystPage(props: PageProps<"/analyst">) {
  const raw = await props.searchParams;
  const reviewedParam = firstValue(raw.reviewed) ?? "false";

  let assessments;
  let error: unknown = null;
  try {
    assessments = (
      await analystApi.listAssessments({ reviewed: reviewedParam === "" ? undefined : reviewedParam === "true" })
    ).assessments;
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">ZeroShield Analyst</h1>
        <p className="mt-1 text-sm text-text-muted">
          Every AI-generated assessment across the platform, in one review queue. Advisory only - nothing here can
          approve an experiment, execute a run, or alter evidence; it exists to be explicitly reviewed or dismissed by
          a human.
        </p>
      </div>

      <form method="GET" action="/analyst" className="flex max-w-xs items-end gap-2">
        <div className="flex-1">
          <label htmlFor="reviewed" className="mb-1.5 block text-sm font-medium text-foreground">
            Review status
          </label>
          <Select id="reviewed" name="reviewed" defaultValue={reviewedParam}>
            <option value="false">Awaiting review</option>
            <option value="true">Reviewed</option>
            <option value="">All</option>
          </Select>
        </div>
        <button type="submit" className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90">
          Filter
        </button>
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !assessments || assessments.length === 0 ? (
        <EmptyState
          title="Nothing here"
          description="AI assessments appear here once generated from a CVE's ZeroShield Analyst panel or a control's regression explanation."
        />
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Subject</TH>
                <TH>Confidence</TH>
                <TH>Generated</TH>
                <TH>Status</TH>
                <TH></TH>
              </TR>
            </THead>
            <TBody>
              {assessments.map((a) => (
                <TR key={a.assessment_id}>
                  <TD>
                    <Badge variant="accent">{titleCase(a.assessment_type)}</Badge>
                  </TD>
                  <TD>
                    {a.subject_type === "vulnerability" ? (
                      <Link href={`/vulnerabilities/${a.subject_id}`} className="font-medium text-accent hover:underline">
                        {a.subject_id}
                      </Link>
                    ) : a.subject_type === "control" ? (
                      <Link href={`/controls/${a.subject_id}`} className="font-medium text-accent hover:underline">
                        {a.subject_id}
                      </Link>
                    ) : (
                      a.subject_id
                    )}
                  </TD>
                  <TD>{formatPercent(a.confidence, 0)}</TD>
                  <TD title={formatDateTime(a.created_at)}>{formatDateTime(a.created_at)}</TD>
                  <TD>
                    {a.reviewed ? (
                      <Badge variant="success">Reviewed by {a.reviewed_by}</Badge>
                    ) : (
                      <Badge variant="warning">Awaiting review</Badge>
                    )}
                  </TD>
                  <TD>{!a.reviewed ? <AssessmentReviewButton assessmentId={a.assessment_id} /> : null}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
}
