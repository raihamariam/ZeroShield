import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { AssetEditPanel } from "@/components/features/AssetEditPanel";
import { Badge, Card, CardBody, CardHeader, ErrorState, StatusPill } from "@/components/ui";
import { ApiError } from "@/lib/api/client";
import { assetsApi } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/assets/[assetId]">): Promise<Metadata> {
  const { assetId } = await props.params;
  return { title: assetId };
}

export default async function AssetDetailPage(props: PageProps<"/assets/[assetId]">) {
  const { assetId } = await props.params;

  let asset;
  try {
    asset = await assetsApi.getAsset(assetId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-foreground">{asset.name}</h1>
          <StatusPill status={asset.criticality} />
          {asset.active ? <Badge variant="success">Active</Badge> : <Badge variant="neutral">Inactive</Badge>}
        </div>
        <p className="mt-1 text-sm text-text-muted">
          {asset.asset_id} · {asset.vendor} / {asset.product}
          {asset.version ? ` (${asset.version})` : ""}
        </p>
      </div>

      <Card>
        <CardHeader title="Details" />
        <CardBody className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
          <Stat label="Environment" value={titleCase(asset.environment)} />
          <Stat label="Exposure" value={titleCase(asset.exposure)} />
          <Stat label="Created" value={formatDateTime(asset.created_at)} />
          <Stat label="Updated" value={formatDateTime(asset.updated_at)} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Edit" description="Step 7's deliberately small inventory - only these fields are mutable." />
        <CardBody>
          <AssetEditPanel asset={asset} />
        </CardBody>
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className="mt-0.5 text-foreground">{value}</p>
    </div>
  );
}
