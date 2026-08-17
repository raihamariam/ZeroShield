import type { Metadata } from "next";
import Link from "next/link";
import { CreateAssetForm } from "@/components/features/CreateAssetForm";
import { Badge, EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { assetsApi } from "@/lib/api";
import { titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Assets" };

export default async function AssetsPage() {
  let assets;
  let error: unknown = null;
  try {
    assets = (await assetsApi.listAssets()).assets;
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Assets</h1>
          <p className="mt-1 text-sm text-text-muted">
            A deliberately small inventory - not a CMDB. Used only to deterministically match vendor/product against a
            CVE, never AI or fuzzy matching.
          </p>
        </div>
      </div>

      <CreateAssetForm />

      {error ? (
        <ErrorState error={error} />
      ) : !assets || assets.length === 0 ? (
        <EmptyState title="No assets registered" description="Register the first asset above." />
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <TR>
                <TH>Asset</TH>
                <TH>Vendor / product</TH>
                <TH>Environment</TH>
                <TH>Exposure</TH>
                <TH>Criticality</TH>
                <TH>Status</TH>
              </TR>
            </THead>
            <TBody>
              {assets.map((asset) => (
                <TR key={asset.asset_id}>
                  <TD>
                    <Link href={`/assets/${asset.asset_id}`} className="font-medium text-accent hover:underline">
                      {asset.name}
                    </Link>
                    <p className="text-xs text-text-muted">{asset.asset_id}</p>
                  </TD>
                  <TD>
                    {asset.vendor} / {asset.product}
                    {asset.version ? ` (${asset.version})` : ""}
                  </TD>
                  <TD>{titleCase(asset.environment)}</TD>
                  <TD>{titleCase(asset.exposure)}</TD>
                  <TD>
                    <StatusPill status={asset.criticality} />
                  </TD>
                  <TD>{asset.active ? <Badge variant="success">Active</Badge> : <Badge variant="neutral">Inactive</Badge>}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
}
